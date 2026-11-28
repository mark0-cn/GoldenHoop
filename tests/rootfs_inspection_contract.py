"""Actual immutable ext4 inspection in the source-built isolated Rust tool.

This component gate grants no rootfs snapshot, cold-boot or template capability.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import time
import uuid

from image_builder_contract import Contract, digest, docker
import rootfs_host_fixture as host


class RootfsContract(Contract):
    def __init__(self, args):
        super().__init__(args)
        if args.owner:
            self.owner = uuid.UUID(args.owner).hex
            self.label = ['--label', 'dev.goldenhoop.task=m4-image-builder-contract',
                          '--label', 'dev.goldenhoop.owner='+self.owner]
        self.report['owner'] = self.owner
        self.report['selected_cases'] = args.case
        self.sources += [Path(__file__).resolve(), Path(host.__file__).resolve()]
        root = Path(__file__).resolve().parents[1]
        self.source_hashes = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in self.sources}
        self.report.update(suite='actual-isolated-Rust-rootfs-inspection', source_commit=args.source_commit,
                           scope='read-only ext4 component; production host rootfs orchestration, capture, cold boot and templates remain unverified')
        self.report['host_observations'] = {}

    def writable(self, volume, program, arguments, extra=()):
        cid = self.container(arguments, entrypoint=program, mounts=[(volume, '/output', False), *extra])
        try:
            result = docker('start', '--attach', cid)
            state = json.loads(docker('inspect', cid))[0]['State']
            assert state['Status'] == 'exited' and state['ExitCode'] == 0 and not state['OOMKilled'], state
            return result
        finally:
            self.remove_container(cid)

    def remove_container(self, cid):
        super().remove_container(cid)
        observation = self.report.get('host_observations', {}).get(cid)
        if observation:
            deadline = time.monotonic()+15
            while not host.absent(observation):
                assert time.monotonic() < deadline, observation
                time.sleep(0.1)
            observation['original_process_and_owned_cgroup_absent'] = True

    def authorized(self, request, source, target, action, fingerprint, cancel=False):
        # Only the test parent has Docker/host access. Pin every effective
        # placement field before the permit; guest virtual cgroups are unused.
        self.counter += 1
        command = ['create', '--interactive', '--name', f'ghib-{self.owner}-{self.counter}', *self.label,
                   '--runtime', 'runsc', '--hostname', uuid.UUID(request['generation']).hex,
                   '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                   '--security-opt', 'no-new-privileges:true', '--cpus', '1', '--memory', '1g', '--memory-swap', '1g', '--pids-limit', '64']
        for capability in ['CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'FSETID']:
            command += ['--cap-add', capability]
        for volume, path, readonly in [(source, '/input', True), (target, '/output', False)]:
            command += ['--mount', f'type=volume,src={volume},dst={path},volume-nocopy'+(',readonly' if readonly else '')]
        cid = docker(*command, self.image, 'await-'+action).decode().strip()
        process = None
        try:
            actual = json.loads(docker('inspect', cid))[0]
            config = actual['HostConfig']
            assert actual['Image'] == self.image and config['Runtime'] == 'runsc' and config['NetworkMode'] == 'none'
            assert config['ReadonlyRootfs'] and not config['Privileged'] and config['CapDrop'] == ['ALL']
            assert set(config['CapAdd']) == {'CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'FSETID'}
            assert config['SecurityOpt'] == ['no-new-privileges:true'] and config['PidsLimit'] == 64
            assert config['Memory'] == config['MemorySwap'] == 1024**3 and config['NanoCpus'] == 10**9
            assert actual['Config']['OpenStdin'] and not actual['Config']['Tty'] and not actual['Config']['StdinOnce']
            expected = {(source, '/input', False), (target, '/output', True)}
            assert {(m['Name'], m['Destination'], m['RW']) for m in actual['Mounts']} == expected
            process = subprocess.Popen(['docker', 'start', '--attach', '--interactive', cid], stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            deadline = time.monotonic()+20
            while True:
                state = json.loads(docker('inspect', cid))[0]['State']
                if state['Running']:
                    break
                assert state['Status'] == 'created' and time.monotonic() < deadline, state
                time.sleep(0.05)
            observation = host.observe(cid, state['Pid'])
            self.report['host_observations'][cid] = observation
            permit = dict(format=1, installation_id=str(uuid.uuid4()), job_id=str(uuid.uuid4()),
                          generation=request['generation'], nonce=str(uuid.uuid4()), builder_image=self.image,
                          request_sha256=fingerprint, runtime='runsc', limits=observation['limits'])
            assert host.ticks(state['Pid']) == observation['start_ticks']
            process.stdin.write(json.dumps(permit).encode()+b'\n'); process.stdin.flush()
            if cancel:
                self.cancel_stage(cid, target)
            docker('wait', cid, timeout=240)
            # Keep stdin open through confirmed exit. EOF is not completion.
            process.wait(timeout=10)
            answer = self.answer(cid, docker('logs', cid))
            return cid, answer
        except BaseException:
            self.remove_container(cid)
            raise
        finally:
            if process:
                if process.poll() is None:
                    process.terminate(); process.wait(timeout=10)
                for pipe in [process.stdin, process.stdout, process.stderr]:
                    pipe.close()

    def cancel_stage(self, cid, target):
        deadline = time.monotonic()+45
        while True:
            stage = self.inspected(target, '/usr/bin/find', ['/output', '-mindepth', '1', '-maxdepth', '1', '-name', '*.checking'])
            if stage.strip():
                docker('kill', '--signal', 'TERM', cid)
                return
            state = json.loads(docker('inspect', cid))[0]['State']
            assert state['Running'] and time.monotonic() < deadline, state

    def answer(self, cid, output):
        state = json.loads(docker('inspect', cid))[0]['State']
        assert state['Status'] == 'exited' and not state['OOMKilled'], state
        answer = json.loads(output)
        assert state['ExitCode'] == (0 if answer['passed'] else 2), (state, answer)
        assert answer['tools_collected'] and answer['staging_absent'], answer
        return answer

    def prepare(self, archive, request, volume, cancel=False):
        assert not cancel
        if self.args.runtime == 'runc':
            return super().prepare(archive, request, volume)
        source = self.seeded(archive, request)
        fingerprint = hashlib.sha256(json.dumps(request, separators=(',', ':')).encode()).hexdigest()
        return self.authorized(request, source, volume, 'prepare', fingerprint)

    def inspect(self, source, request, cancel=False):
        # A never-started seeder writes only the bounded request. The disk is
        # already an independently copied fixture; each inspection mounts it RO.
        cid = self.container([], entrypoint='/bin/true', mounts=[(source, '/input', False)])
        packet = self.context/(uuid.uuid4().hex+'-input.tar')
        with tarfile.open(packet, 'w') as output:
            data = json.dumps(request).encode()
            header = tarfile.TarInfo('inspect-rootfs.json'); header.mode = 0o400
            header.size = len(data); header.uid = header.gid = 0
            output.addfile(header, io.BytesIO(data))
        try:
            with packet.open('rb') as stream:
                docker('cp', '-', cid+':/input', stdin=stream)
            assert json.loads(docker('inspect', cid))[0]['State']['Status'] == 'created'
        finally:
            self.remove_container(cid)
        target = self.volume()
        if self.args.runtime == 'runsc':
            raw = b'goldenhoop.rootfs-inspection.request.v1\0'+json.dumps(request, separators=(',', ':')).encode()
            cid, answer = self.authorized(request, source, target, 'inspect-rootfs', hashlib.sha256(raw).hexdigest(), cancel)
        else:
            cid = self.container(['inspect-rootfs'], mounts=[(source, '/input', True), (target, '/output', False)], builder=True)
            try:
                docker('start', cid)
                if cancel:
                    self.cancel_stage(cid, target)
                docker('wait', cid, timeout=240)
                answer = self.answer(cid, docker('logs', cid))
            except BaseException:
                self.remove_container(cid)
                raise
        self.remove_container(cid)
        self.empty(target)
        return answer

    def disk_content(self, volume):
        sha = self.inspected(volume, '/usr/bin/sha256sum', ['/output/rootfs.ext4']).decode().split()[0]
        size = int(self.inspected(volume, '/usr/bin/stat', ['-c', '%s', '/output/rootfs.ext4']))
        return dict(sha256=sha, size_bytes=size)

    def exercise(self):
        actual = json.loads(docker('image', 'inspect', self.args.image))[0]
        assert actual['Config']['Labels']['dev.goldenhoop.task'] == 'm4-image-builder-fixture'
        assert actual['Config']['Labels']['dev.goldenhoop.owner'] == self.args.image_owner
        self.image = actual['Id']; self.report['image_id'] = self.image
        inventory = json.loads(self.inspected(None, '/bin/cat', ['/opt/goldenhoop/rootfs-inventory.json']))
        archive = self.archive('positive')
        prepared = dict(generation=str(uuid.uuid4()), archive=digest(archive), agent=inventory['agent'], init=inventory['init'], disk_bytes=64*1024**2)
        original = self.volume()
        cid, converted = self.prepare(archive, prepared, original)
        self.remove_container(cid); assert converted['passed'], converted
        self.report['observations']['prepared_manifest'] = converted['manifest']
        self.report['observations']['inspector_inventory'] = inventory
        self.report['cases'].append('source_built_converter_produces_actual_clean_ext4_fixture')

        def copy_disk():
            volume = self.volume()
            self.writable(volume, '/bin/cp', ['--sparse=always', '/input/'+prepared['generation']+'/rootfs.ext4', '/output/rootfs.ext4'], [(original, '/input', True)])
            self.writable(volume, '/bin/chmod', ['0600', '/output/rootfs.ext4'])
            return volume
        def debug(volume, command):
            return self.writable(volume, '/usr/sbin/debugfs', ['-w', '-R', command, '/output/rootfs.ext4'])
        good = copy_disk()
        request = dict(generation=str(uuid.uuid4()), disk=self.disk_content(good), agent=inventory['agent'], init=inventory['init'], guest=dict(control_port=52, pids=256))
        found = self.inspect(good, request)
        assert found['passed'], found
        inspection = found['inspection']
        assert inspection['disk'] == request['disk'] and inspection['inventory'] == inventory
        assert inspection['agent']['content'] == inventory['agent'] and inspection['init']['content'] == inventory['init']
        assert inspection['init']['path'] == '/usr/sbin/goldenhoop-init' and inspection['guest'] == request['guest']
        assert self.disk_content(good) == request['disk']
        self.report['observations']['inspection'] = inspection
        self.report['cases'].append('clean_ext4_usr_merge_fixed_assets_guest_config_and_unchanged_input')

        changes = {
            'agent_mode': ['set_inode_field /usr/local/bin/goldenhoop-agent mode 0100777'],
            'init_owner': ['set_inode_field /usr/sbin/goldenhoop-init uid 1000'],
            'agent_hardlink': ['link /usr/local/bin/goldenhoop-agent /workspace/boot-alias', 'set_inode_field /usr/local/bin/goldenhoop-agent links_count 2'],
            'protected_parent': ['set_inode_field /usr/local/bin mode 040777'],
            'workspace_owner': ['set_inode_field /workspace uid 0'],
            'agent_symlink': ['rm /usr/local/bin/goldenhoop-agent', 'symlink /usr/local/bin/goldenhoop-agent /workspace/agent-alias'],
            'agent_content': ['zap_block -f /usr/local/bin/goldenhoop-agent -p 0 0'],
            'guest_unknown': ['rm /etc/goldenhoop/guest.json', 'write /opt/goldenhoop/rootfs-inventory.json /etc/goldenhoop/guest.json', 'set_inode_field /etc/goldenhoop/guest.json mode 0100644'],
            'dirty': ['set_super_value state 0'],
            'pending_recovery': ['feature needs_recovery'],
            'inconsistent_links': ['set_inode_field /usr/bin/sentinel links_count 2'],
        }
        selected = set(args for args in (self.args.case or ['digest', 'guest_mismatch', *changes, 'truncated', 'corrupt_superblock', 'TERM']))
        assert selected.issubset({'digest', 'guest_mismatch', *changes, 'truncated', 'corrupt_superblock', 'TERM'}), selected
        for kind in ['digest', 'guest_mismatch', *changes, 'truncated', 'corrupt_superblock']:
            if kind not in selected:
                continue
            volume = copy_disk()
            for command in changes.get(kind, []):
                debug(volume, command)
            if kind == 'truncated':
                self.writable(volume, '/usr/bin/truncate', ['-s', str(64*1024**2-4096), '/output/rootfs.ext4'])
            elif kind == 'corrupt_superblock':
                self.writable(volume, '/bin/dd', ['if=/dev/zero', 'of=/output/rootfs.ext4', 'bs=1024', 'count=1', 'seek=1', 'conv=notrunc'])
            before = self.disk_content(volume)
            if kind in changes or kind in {'truncated', 'corrupt_superblock'}:
                assert before != request['disk'], (kind, 'fixture mutation was not observed')
            changed = dict(request, generation=str(uuid.uuid4()), disk=dict(before), guest=dict(request['guest']))
            if kind == 'digest': changed['disk']['sha256'] = '0'*64
            if kind == 'guest_mismatch': changed['guest']['pids'] = 128
            if kind == 'truncated': changed['disk']['size_bytes'] = request['disk']['size_bytes']
            refused = self.inspect(volume, changed)
            assert not refused['passed'] and refused['inspection'] is None, (kind, refused)
            if kind == 'guest_unknown':
                assert 'unknown field' in refused['error'], refused
            if kind == 'inconsistent_links':
                assert 'image tool failed' in refused['error'], refused
            assert self.disk_content(volume) == before, kind
            self.report['observations'][kind+'_refusal'] = refused['error']
            self.report['cases'].append(kind+'_refused_input_unchanged_output_absent')
            print(json.dumps({'case': kind, 'refused': True}), flush=True)
        if 'TERM' not in selected:
            self.report['result'] = 'passed'
            return
        large = dict(prepared, generation=str(uuid.uuid4()), disk_bytes=4*1024**3)
        original_large = self.volume()
        cid, converted = self.prepare(archive, large, original_large)
        self.remove_container(cid); assert converted['passed'], converted
        source = self.volume()
        self.writable(source, '/bin/cp', ['--sparse=always', '/input/'+large['generation']+'/rootfs.ext4', '/output/rootfs.ext4'], [(original_large, '/input', True)])
        before = self.disk_content(source)
        changed = dict(request, generation=str(uuid.uuid4()), disk=before)
        stopped = self.inspect(source, changed, cancel=True)
        assert not stopped['passed'] and 'interrupted' in stopped['error'] and stopped['inspection'] is None, stopped
        assert self.disk_content(source) == before
        self.report['observations']['TERM_refusal'] = stopped['error']
        self.report['cases'].append('TERM_during_actual_inspection_collects_tools_and_stage_and_preserves_input')
        self.report['result'] = 'passed'


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', required=True)
    parser.add_argument('--image-owner', required=True)
    parser.add_argument('--runtime', choices=['runsc', 'runc'], default='runsc')
    parser.add_argument('--allow-runc-development', action='store_true')
    parser.add_argument('--source-commit')
    parser.add_argument('--owner', help='explicit unique UUID for workflow cleanup')
    parser.add_argument('--case', action='append', help='run only named negative controls; the full gate omits this option')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--remove-image', action='store_true')
    args = parser.parse_args()
    if args.output.exists(): parser.error('preserve the original report and choose a fresh path')
    if args.runtime == 'runc' and not args.allow_runc_development: parser.error('runc requires explicit --allow-runc-development')
    raise SystemExit(RootfsContract(args).run())
