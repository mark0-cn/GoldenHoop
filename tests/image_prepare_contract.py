"""Actual Rust source -> isolated converter -> immutable disk host pipeline.

The host-controller image is trusted infrastructure. Its daemon/host-PID view
never enters a source or converter workload. Local runc is explicit development
evidence; runsc on a disposable Linux runner is a separate required gate.
"""
import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import tempfile
import uuid

from image_builder_contract import docker
from image_source_contract import Contract as SourceContract


class Contract(SourceContract):
    def __init__(self, args):
        self.recovery = None
        if args.recover_report:
            raw = args.recover_report.read_bytes()
            failed = json.loads(raw)
            assert failed['suite'] == 'actual-Rust-image-preparation-pipeline' and failed['result'] == 'failed'
            self.recovery = failed
            self.args, self.owner = args, failed['owner']
            assert re.fullmatch('[a-f0-9]{32}', self.owner)
            self.context = Path(failed['temporary_context'])
            assert self.context.parent.resolve() == Path(tempfile.gettempdir()).resolve()
            assert self.context.name.startswith('goldenhoop-source-export-') and not self.context.is_symlink()
            self.files = set(self.context.iterdir())
            assert self.context.resolve() == self.context.absolute()
            assert all(re.fullmatch(r'[a-f0-9]{32}\.tar|cleanup-state\.db|[a-f0-9]{32}-cleanup-state\.db|prepared-state\.db|disk-manifest\.json|rootfs\.ext4|disk-chunk-[0-9]{8}', p.name) for p in self.files)
            self.labels = ['--label', 'dev.goldenhoop.task=m4-image-source-contract', '--label', 'dev.goldenhoop.owner='+self.owner]
            self.counter, self.jobs, self.image = 100, failed['owned_jobs'], None
            self.volume = failed['retained_state_volume']
            assert self.volume == 'ghsrc-state-'+self.owner
            self.root = Path(__file__).resolve().parents[1]
            self.sources = [self.root/'Cargo.toml',self.root/'Cargo.lock',self.root/'images/host/Dockerfile',self.root/'tests/image_source_contract.py',self.root/'tests/image_builder_contract.py']
            self.sources += sorted(p for p in (self.root/'crates').rglob('*') if p.is_file() and '__pycache__' not in p.parts)
            self.report = dict(result='failed',cleanup='unknown',cases=[],observations={},owner=self.owner,
                               temporary_context=str(self.context),failed_report_sha256=hashlib.sha256(raw).hexdigest())
        else:
            super().__init__(args)
        self.builder = None
        self.check_volumes = []
        self.disk_size = getattr(args, 'disk_bytes', 64 * 1024**2)
        self.source_base_id = None
        self.report.update(suite='actual-Rust-image-preparation-pipeline', runtime=args.runtime,
                           scope='private disk pipeline; KVM placement, crash reconciliation and snapshot/template capabilities are separate gates')
        if self.recovery:
            self.report.update(runtime='maintenance_only',scope='fenced early-abort or stable-disk maintenance; no converter execution or gVisor acceptance')
        if args.source_commit:
            self.report['source_commit']=args.source_commit
        self.sources += [Path(__file__).resolve(), self.root/'images/agent/Dockerfile']
        self.hashes = self.fingerprints()

    def container(self, *, viewer=False, entrypoint=None):
        args = super().container(viewer=viewer, entrypoint=entrypoint)
        if not viewer:
            args += ['--cgroupns', 'host', '--mount',
                     'type=bind,src=/sys/fs/cgroup,dst=/sys/fs/cgroup,readonly']
        return args

    def call(self, arguments, expected=0, artifact_root='/state/blobs'):
        cid = docker(*(self.container() + [self.image, '--database', '/state/source.db',
                                           '--artifact-root', artifact_root, *arguments])).decode().strip()
        try:
            result = subprocess.run(['docker', 'start', '--attach', cid], capture_output=True, timeout=300)
            observed = json.loads(docker('inspect', cid))[0]['State']
            value = json.loads(result.stdout) if result.stdout.strip() else None
            self.report['observations']['last_call'] = dict(command=arguments[0], state=observed,
                                                            result=value, stderr=result.stderr.decode(errors='replace')[-3000:])
            assert observed['Status'] == 'exited' and not observed['OOMKilled'], observed
            assert observed['ExitCode'] == expected, self.report['observations']['last_call']
            return value
        finally:
            self.remove_container(cid)

    def intent(self, source, *, runtime=True, opt_in=True):
        job, generation = str(uuid.uuid4()), str(uuid.uuid4())
        self.jobs.append((job, generation, source))
        args = ['prepare', '--id', job, '--generation', generation, '--source-image', source,
                '--builder-image', self.builder, '--disk-bytes', str(self.disk_size)]
        if runtime and self.args.runtime == 'runc':
            args += ['--runtime', 'runc-development']
            if opt_in:
                args += ['--allow-runc-development']
        return args

    def journal(self, name):
        database = self.copy('source.db', name)
        with closing(sqlite3.connect(f'file:{database.as_posix()}?mode=ro&immutable=1', uri=True)) as connection:
            rows = connection.execute('SELECT id,generation,installation_id,request_json,payload_json FROM image_jobs').fetchall()
        return [dict(id=row[0], generation=row[1], installation_id=row[2], request=json.loads(row[3]),
                     payload=json.loads(row[4])) for row in rows]

    def isolation_observation(self):
        # Trusted diagnostic image only, with the same guest-facing isolation
        # settings and no input, output, host mount, daemon access or secret.
        # This records a kernel view; it cannot accept the image pipeline.
        command = ("printf 'ROOT_PID=%s\\n' \"$$\"; "
                   "cat /proc/self/status; printf '\\nINTERFACES\\n'; cat /proc/net/dev; "
                   "printf '\\nROOT_MOUNT\\n'; grep ' / ' /proc/mounts; "
                   "if /usr/bin/touch /goldenhoop-readonly-diagnostic; then "
                   "printf 'ROOT_WRITE=allowed\\n'; exit 3; else printf 'ROOT_WRITE=refused\\n'; fi")
        self.counter += 1
        args = ['create','--name',f'ghprep-probe-{self.owner}-{self.counter}',*self.labels,
                '--runtime',self.args.runtime,'--hostname',self.owner,'--user','0:0',
                '--network','none','--read-only','--cap-drop','ALL',
                '--security-opt','no-new-privileges:true','--memory','1g','--memory-swap','1g',
                '--pids-limit','128','--cpus','1']
        for capability in ['CHOWN','DAC_OVERRIDE','FOWNER','FSETID']:
            args += ['--cap-add',capability]
        cid=docker(*args,'--entrypoint','/bin/sh',self.builder,'-c',command).decode().strip()
        try:
            process=subprocess.run(['docker','start','--attach',cid],capture_output=True,timeout=45)
            actual=json.loads(docker('inspect',cid))[0]
            assert actual['Image']==self.builder and actual['HostConfig']['Runtime']==self.args.runtime
            assert actual['State']['Status']=='exited' and not actual['State']['OOMKilled']
            assert len(process.stdout)<=32768 and len(process.stderr)<=8192
            self.report['observations']['isolated_kernel_diagnostic']={
                'scope':'diagnostic only; actual parent/gVisor pipeline acceptance remains required',
                'runtime':self.args.runtime,'image':self.builder,'state':actual['State'],
                'stdout':process.stdout.decode(errors='replace'),'stderr':process.stderr.decode(errors='replace')}
            assert actual['State']['ExitCode']==0,self.report['observations']['isolated_kernel_diagnostic']
        finally:
            self.remove_container(cid)

    def inspect_disk(self, path, reference, inventory):
        volume = 'ghprep-disk-check-' + self.owner
        docker('volume', 'create', *self.labels, volume)
        self.check_volumes.append(volume)

        def create(program, arguments, readonly):
            self.counter += 1
            return docker('create', '--name', f'ghprep-check-{self.owner}-{self.counter}', *self.labels,
                          '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                          '--security-opt', 'no-new-privileges:true', '--cpus', '1', '--memory', '256m',
                          '--memory-swap', '256m', '--pids-limit', '32', '--entrypoint', program,
                          '--mount', f'type=volume,src={volume},dst=/output,volume-nocopy' + (',readonly' if readonly else ''),
                          self.builder, *arguments).decode().strip()

        seed = create('/never-executed', [], False)
        try:
            docker('cp', str(path), seed + ':/output/rootfs.ext4')
            actual = json.loads(docker('inspect', seed))[0]['State']
            assert actual['Status'] == 'created' and actual['Pid'] == 0 and not actual['Running']
        finally:
            self.remove_container(seed)

        def run(program, arguments):
            cid = create(program, arguments, True)
            try:
                result = docker('start', '--attach', cid)
                state = json.loads(docker('inspect', cid))[0]['State']
                assert state['Status'] == 'exited' and state['ExitCode'] == 0 and not state['OOMKilled'], state
                return result
            finally:
                self.remove_container(cid)

        run('/usr/sbin/e2fsck', ['-f', '-n', '/output/rootfs.ext4'])
        debug = lambda command: run('/usr/sbin/debugfs', ['-R', command, '/output/rootfs.ext4'])
        assert debug('cat /sentinel') == b'goldenhoop-source-ok\n'
        for key, target in [('agent', '/usr/local/bin/goldenhoop-agent'), ('init', '/sbin/goldenhoop-init')]:
            data = debug('cat ' + target)
            assert hashlib.sha256(data).hexdigest() == inventory[key]['sha256'] and len(data) == inventory[key]['size_bytes'], (target,len(data),inventory[key])
        workspace = debug('stat /workspace').decode()
        assert re.search(r'Mode:\s+02770\b', workspace) and re.search(r'User:\s+1000\s+Group:\s+1000\b', workspace), workspace
        assert debug('cat /etc/machine-id') == b''
        self.report['observations']['independent_workspace_stat'] = workspace
        self.report['observations']['independently_read_disk'] = reference

    def consume_prepared_disk(self, path, preparation):
        # A separate actual KVM gate consumes the independently verified disk.
        # The ordinary converter contract makes no guest-execution claim.
        pass

    def exercise(self):
        image = json.loads(docker('image', 'inspect', self.args.image))[0]
        assert image['Config']['Labels']['dev.goldenhoop.task'] == 'm4-image-source-export-fixture'
        assert image['Config']['Labels']['dev.goldenhoop.owner'] == self.args.image_owner
        self.image = image['Id']
        builder = json.loads(docker('image', 'inspect', self.args.builder_image))[0]
        assert builder['Config']['Labels']['dev.goldenhoop.owner'] == self.args.builder_owner
        assert builder['Config']['Labels']['dev.goldenhoop.task'] == 'm4-image-builder-fixture'
        self.builder = builder['Id']
        self.report.update(host_image_id=self.image, builder_image_id=self.builder)
        if self.recovery:
            check_volume='ghprep-disk-check-'+self.owner
            if docker('volume','ls','--quiet','--filter','name=^'+check_volume+'$').strip():
                actual=json.loads(docker('volume','inspect',check_volume))[0]
                assert actual['Labels']['dev.goldenhoop.owner']==self.owner
                self.check_volumes.append(check_volume)
            rows = self.recovery['observations']['cleanup_jobs']
            for row in rows:
                if row['id'] in {job for job,_,_ in self.jobs} and row['payload']['phase'] != 'failed_collected':
                    if row['payload']['phase'] in ['ready','collecting']:
                        result=self.call(['collect-image','--id',row['id']])
                        assert result['phase']=='collected' and result['provider_cleanup']=='complete'
                        self.report['cases'].append('stable_disk_after_fixture_inspection_failure_is_collected_without_relaunch')
                        continue
                    assert row['payload']['phase'] in ['source_ready','volumes_ready','seeder_observed']
                    assert row['payload']['request'] is None and row['payload']['builder_id'] is None
                    result = self.call(['abort-before-input','--id',row['id']])
                    assert result['phase'] == 'failed_collected' and result['provider_cleanup'] == 'complete'
                    assert result['error'] == row['payload']['error']
                    assert self.call(['abort-before-input','--id',row['id']])['phase'] == 'failed_collected'
                    self.report['cases'].append('fenced_acknowledged_pre_input_failure_is_collected_by_actual_Rust_parent_without_reset_or_replay')
            self.report['observations']['final_jobs'] = self.journal('recovered-state.db')
            assert all(row['payload']['phase'] in ['failed_collected','collected'] for row in self.report['observations']['final_jobs'])
            self.report['result'] = 'passed'
            return
        if getattr(self.args, 'source_base_image', None):
            base = json.loads(docker('image', 'inspect', self.args.source_base_image))[0]
            labels = base['Config']['Labels']
            assert labels['dev.goldenhoop.owner'] == self.args.source_base_owner
            assert labels['dev.goldenhoop.task'] == 'm4-image-guest-source-fixture'
            assert base['Architecture'] == 'amd64' and base['Os'] == 'linux'
            assert re.fullmatch('sha256:[a-f0-9]{64}', base['Id'])
            assert re.fullmatch('[a-z0-9][a-z0-9._/:-]{0,199}', self.args.source_base_image)
            self.source_base_id = base['Id']
            # BuildKit treats a bare image ID in FROM as a registry name.
            # Resolve the exact owned local tag, then check both its immutable
            # ID and the generated image's inherited content layers.
            self.source_base = self.args.source_base_image
            self.report['source_base_image_id'] = self.source_base_id
            self.report['observations']['source_base_layers'] = base['RootFS']['Layers']
        self.volume = 'ghsrc-state-' + self.owner
        docker('volume', 'create', *self.labels, self.volume)
        self.isolation_observation()
        source, _ = self.source_image()
        if self.source_base_id:
            layers = json.loads(docker('image', 'inspect', source))[0]['RootFS']['Layers']
            base_layers = self.report['observations']['source_base_layers']
            assert json.loads(docker('image', 'inspect', self.args.source_base_image))[0]['Id'] == self.source_base_id
            assert layers[:len(base_layers)] == base_layers
        if self.args.runtime == 'runc':
            denied = self.call(self.intent(source, opt_in=False), expected=2)
            assert denied['phase'] == 'failed_collected' and denied['provider_cleanup'] == 'complete'
            assert denied['error']['code'] == 'unsupported_capability' and not denied['image_ready']
            self.report['cases'].append('runc_requires_both_explicit_runtime_and_development_opt_in')
            if 'runsc' not in json.loads(docker('info', '--format', '{{json .Runtimes}}')):
                denied = self.call(self.intent(source, runtime=False), expected=2)
                assert denied['phase'] == 'failed_collected' and denied['error']['code'] == 'unsupported_capability'
                self.report['cases'].append('missing_default_runsc_refused_without_weaker_fallback_or_provider_writes')
        arguments = self.intent(source)
        value = self.call(arguments)
        assert value['image_ready'] and value['provider_cleanup'] == 'complete' and value['error'] is None, value
        reference = value['disk']
        assert reference['size_bytes'] == self.disk_size and value['manifest']['disk']['sha256'] == reference['sha256']
        limits = value['host_observation']['limits']
        assert 0 < limits['memory_max'] <= 1024**3 and limits['swap_max'] == 0 and 16 <= limits['pids_max'] <= 128
        assert 0 < limits['cpu_quota'] <= limits['cpu_period']
        self.report['observations']['preparation'] = value
        self.report['cases'].append('actual_host_limits_private_stdin_handoff_and_verified_disk_publish_after_provider_collection')
        rows = self.journal('prepared-state.db')
        parent = next(row for row in rows if row['id'] == value['id'])
        child = next(row for row in rows if row['id'] == parent['payload']['source']['id'])
        assert child['payload']['phase'] == 'collected' and child['payload']['source_observation']['state']['Pid'] == 0
        assert child['payload']['source_observation']['state']['Status'] == 'created'
        for part in ['builder', 'seeder', 'input', 'output']:
            name = f'ghi-{uuid.UUID(reference["installation_id"]).hex}-{uuid.UUID(value["generation"]).hex}-{part}'
            assert not docker('ps', '-aq', '--filter', 'name=^/' + name + '$').strip()
            assert not docker('volume', 'ls', '--quiet', '--filter', 'name=^' + name + '$').strip()
        self.report['cases'].append('source_never_executed_and_source_archive_containers_and_both_volumes_are_collected')
        prefix = f'blobs/goldenhoop/{reference["installation_id"]}/large/{reference["id"]}/{reference["generation"]}'
        stored = json.loads(self.copy(prefix + '/manifest', 'disk-manifest.json').read_bytes())
        assert stored['reference'] == reference
        output = self.path('rootfs.ext4')
        whole = hashlib.sha256()
        with output.open('xb') as destination:
            for index, item in enumerate(stored['chunks']):
                data = self.copy(prefix + f'/chunk-{index:08}', f'disk-chunk-{index:08}').read_bytes()
                assert len(data) == item['size_bytes'] and hashlib.sha256(data).hexdigest() == item['sha256']
                whole.update(data)
                destination.write(data)
        assert output.stat().st_size == reference['size_bytes'] and whole.hexdigest() == reference['sha256']
        self.inspect_disk(output, reference, parent['payload']['inventory'])
        self.report['cases'].append('independent_all_chunks_whole_disk_fsck_pinned_assets_and_guest_identity_readback')
        docker('image', 'rm', source)
        assert self.call(arguments)['disk'] == reference
        self.report['cases'].append('fresh_process_reopens_verified_disk_after_source_image_collection_without_relaunch')
        self.consume_prepared_disk(output, value)
        for key, replacement in [('--generation', str(uuid.uuid4())), ('--disk-bytes', str(128*1024**2)), ('--builder-image', 'sha256:'+'b'*64)]:
            foreign = arguments.copy()
            foreign[foreign.index(key)+1] = replacement
            self.call(foreign, expected=1)
        self.call(['collect-image', '--id', value['id']], expected=1, artifact_root='/state/foreign')
        assert self.call(arguments)['disk'] == reference
        self.report['cases'].append('changed_generation_size_builder_and_storage_binding_cannot_reuse_or_collect_an_intent')
        collected = self.call(['collect-image', '--id', value['id']])
        assert collected['phase'] == 'collected' and not collected['image_ready'] and collected['provider_cleanup'] == 'complete'
        assert self.call(['collect-image', '--id', value['id']])['phase'] == 'collected'
        assert not self.call(arguments, expected=2)['image_ready']
        self.report['cases'].append('exact_disk_collection_is_idempotent_and_collected_intent_cannot_relaunch')
        bad, _ = self.source_image(volume=True)
        denied = self.call(self.intent(bad), expected=2)
        assert denied['phase'] == 'failed_collected' and denied['error']['code'] == 'unsupported_capability'
        assert denied['provider_cleanup'] == 'complete' and denied['disk'] is None
        self.report['cases'].append('anonymous_source_volumes_refused_before_conversion_and_parent_child_failure_is_collected')
        self.report['observations']['final_jobs'] = self.journal('final-state.db')
        self.report['result'] = 'passed'

    def cleanup(self):
        # Stop only fixture-owned host controllers before reading a frozen DB.
        for cid in docker('ps', '-aq', '--filter', 'label=dev.goldenhoop.owner=' + self.owner).decode().splitlines():
            self.remove_container(cid)
        unsettled = []
        if self.volume and self.jobs:
            rows = self.journal(uuid.uuid4().hex+'-cleanup-state.db')
            parents = {job: (generation, source) for job, generation, source in self.jobs}
            allowed = set(parents)
            # All fixture-owned controllers/inspectors above are gone. Stable
            # disks have no remaining consumers and can use normal Rust
            # collection even if a later independent assertion failed.
            for row in rows:
                if row['id'] in parents and row['payload']['phase'] in ['ready','collecting']:
                    result=self.call(['collect-image','--id',row['id']])
                    assert result['phase']=='collected' and result['provider_cleanup']=='complete'
            rows = self.journal(uuid.uuid4().hex+'-cleanup-state.db')
            for row in rows:
                if row['id'] in parents:
                    assert row['generation'] == parents[row['id']][0] and row['request']['request']['source_image'] == parents[row['id']][1]
                    allowed.add(row['payload']['source']['id'])
                    if row['payload']['phase'] not in ['collected', 'failed_collected']:
                        unsettled.append(row['id'] + ':' + row['payload']['phase'])
            assert set(parents).issubset({row['id'] for row in rows}) and {row['id'] for row in rows}.issubset(allowed)
            self.report['observations']['cleanup_jobs'] = rows
            if unsettled:
                # These are retained reconciliation evidence, not unowned
                # garbage. Never report uncertain provider/storage writes as
                # collected, or erase the only durable ownership journal.
                self.report['retained_state_volume'] = self.volume
                raise AssertionError('unsettled durable image jobs: ' + ','.join(unsettled))
        for volume in self.check_volumes:
            actual = json.loads(docker('volume', 'inspect', volume))[0]
            assert actual['Labels']['dev.goldenhoop.owner'] == self.owner
            docker('volume', 'rm', volume)
            assert not docker('volume', 'ls', '--quiet', '--filter', 'name=^'+volume+'$').strip()
        if self.volume:
            actual = json.loads(docker('volume', 'inspect', self.volume))[0]
            assert actual['Labels']['dev.goldenhoop.owner'] == self.owner
            docker('volume', 'rm', self.volume)
            assert not docker('volume', 'ls', '--quiet', '--filter', 'name=^'+self.volume+'$').strip()
        for image in docker('image', 'ls', '--quiet', '--filter', 'label=dev.goldenhoop.owner='+self.owner).decode().splitlines():
            actual = json.loads(docker('image', 'inspect', image))[0]
            assert actual['Config']['Labels']['dev.goldenhoop.owner'] == self.owner
            docker('image', 'rm', image)
        if self.args.remove_image:
            owned = [(self.args.image,self.args.image_owner,self.image), (self.args.builder_image,self.args.builder_owner,self.builder)]
            if self.source_base_id:
                owned.append((self.args.source_base_image,self.args.source_base_owner,self.source_base_id))
            for tag, owner, image in owned:
                if image:
                    actual = json.loads(docker('image', 'inspect', tag))[0]
                    assert actual['Id'] == image and actual['Config']['Labels']['dev.goldenhoop.owner'] == owner
                    docker('image', 'rm', tag)
                    assert not docker('image', 'ls', '--quiet', '--filter', 'reference='+tag).strip()
        assert self.context.resolve() == self.context.absolute() and self.context.name.startswith('goldenhoop-source-export-')
        for entry in self.context.iterdir():
            metadata = entry.lstat()
            assert entry in self.files and stat.S_ISREG(metadata.st_mode) and not entry.is_symlink()
            assert not getattr(metadata, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0)
            entry.chmod(stat.S_IREAD | stat.S_IWRITE)
            entry.unlink()
        self.context.rmdir()
        assert not self.context.exists()
        assert not docker('ps', '-aq', '--filter', 'label=dev.goldenhoop.owner='+self.owner).strip()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', required=True)
    parser.add_argument('--image-owner', required=True)
    parser.add_argument('--builder-image', required=True)
    parser.add_argument('--builder-owner', required=True)
    parser.add_argument('--source-base-image')
    parser.add_argument('--source-base-owner')
    parser.add_argument('--disk-bytes', type=int, default=64*1024**2)
    parser.add_argument('--runtime', choices=['runsc','runc'], default='runsc')
    parser.add_argument('--allow-runc-development', action='store_true')
    parser.add_argument('--remove-image', action='store_true')
    parser.add_argument('--recover-report', type=Path)
    parser.add_argument('--source-commit')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if bool(args.source_base_image) != bool(args.source_base_owner):
        parser.error('a workload fixture base requires its exact task owner')
    if not 64*1024**2 <= args.disk_bytes <= 16*1024**3 or args.disk_bytes % 4096:
        parser.error('disk size must be 64 MiB to 16 GiB and block aligned')
    if args.recover_report and args.source_base_image:
        parser.error('maintenance must not adopt a new source-base fixture')
    if args.source_commit and not re.fullmatch('[a-f0-9]{40}',args.source_commit):
        parser.error('source commit must be a complete lowercase SHA1')
    if args.runtime == 'runc' and not args.allow_runc_development:
        parser.error('runc requires explicit --allow-runc-development; it does not establish production isolation')
    if args.output.exists():
        parser.error('preserve the original output and choose a fresh report')
    raise SystemExit(Contract(args).run())
