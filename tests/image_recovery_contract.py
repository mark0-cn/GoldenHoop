"""Actual SIGKILL / delayed Docker acknowledgement / immutable upload recovery.

Only the trusted fixture has a daemon socket and host PID/cgroup observations.
All source/converter isolation is configured by the production Rust service.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import tempfile
import time
import uuid

from image_builder_contract import docker
from image_source_contract import Contract as SourceContract


class Contract(SourceContract):
    def __init__(self, args):
        self.recovery = None
        if args.recover_report:
            raw = args.recover_report.read_bytes()
            self.recovery = json.loads(raw)
            assert self.recovery['suite'] == 'actual-image-producer-crash-reconciliation'
            assert self.recovery['cleanup'] == 'unknown'
            self.args, self.owner = args, self.recovery['owner']
            assert re.fullmatch('[a-f0-9]{32}', self.owner)
            self.context = Path(self.recovery['temporary_context'])
            assert self.context.parent.resolve() == Path(tempfile.gettempdir()).resolve()
            assert self.context.name.startswith('goldenhoop-source-export-') and not self.context.is_symlink()
            assert self.context.resolve() == self.context.absolute()
            self.files = set(self.context.iterdir())
            assert all(re.fullmatch('[a-f0-9]{32}\\.tar', p.name) for p in self.files)
            self.labels = ['--label', 'dev.goldenhoop.task=m4-image-source-contract', '--label', 'dev.goldenhoop.owner='+self.owner]
            self.counter, self.jobs = 100, self.recovery['owned_jobs']
            self.image = None
            self.volume = 'ghsrc-state-'+self.owner
            self.root = Path(__file__).resolve().parents[1]
            self.sources = [self.root/'Cargo.toml', self.root/'Cargo.lock', self.root/'images/host/Dockerfile', self.root/'tests/image_source_contract.py', self.root/'tests/image_builder_contract.py']
            self.sources += sorted(p for p in (self.root/'crates').rglob('*') if p.is_file() and '__pycache__' not in p.parts)
            self.report = dict(result='failed', cleanup='unknown', cases=[], observations={}, owner=self.owner,
                               temporary_context=str(self.context), failed_report_sha256=hashlib.sha256(raw).hexdigest())
        else:
            super().__init__(args)
        self.parents = set()
        self.proxy = None
        self.proxy_base = None
        self.proxy_volume = None
        self.clone_volume = None
        self.builder = None
        self.controllers = set()
        self.sources += [Path(__file__).resolve(), self.root/'tests/image_fault_proxy.py', self.root/'images/agent/Dockerfile']
        self.hashes = self.fingerprints()
        self.report.update(suite='actual-image-producer-crash-reconciliation',
                           scope='local image writer fences and explicit same-generation recovery; earlier converter start/permit recovery, remote storage and KVM remain separate')
        if args.source_commit:
            self.report['source_commit'] = args.source_commit
        if self.recovery:
            self.report['scope'] = 'maintenance of the exact retained fixture after an independent journal-reader failure; no new crash-injection acceptance'

    def container(self, *, viewer=False, entrypoint=None):
        args = super().container(viewer=viewer, entrypoint=entrypoint)
        if not viewer:
            direct = 'type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock'
            if self.proxy:
                args[args.index(direct)] = f'type=volume,src={self.proxy_volume},dst=/var/run,volume-nocopy'
            args += ['--cgroupns', 'host', '--mount', 'type=bind,src=/sys/fs/cgroup,dst=/sys/fs/cgroup,readonly']
        return args

    def proxy_code(self, code):
        return json.loads(docker('exec', self.proxy, '/usr/bin/python3', '-c', code, timeout=30))

    def control(self, action='state', value=None):
        code = ("import http.client,json,socket; "
                "c=http.client.HTTPConnection('localhost',timeout=10); "
                "c.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); c.sock.connect('/proxy/docker.sock'); "
                f"c.request('POST','/_fault/{action}',body={json.dumps(json.dumps(value) if value is not None else '')},headers={{'Content-Type':'application/json'}}); "
                "r=c.getresponse(); assert r.status==200; print(r.read().decode()); c.close()")
        return self.proxy_code(code)

    def wait(self, operation, message, seconds=30):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            value = operation()
            if value:
                return value
            time.sleep(0.2)
        raise AssertionError(message)

    def hit(self, seconds=120):
        def observe():
            value = self.control()
            if value['fault']['hit']:
                return value
            for cid in self.controllers:
                actual = json.loads(docker('inspect', cid))[0]['State']
                if actual['Status'] == 'exited':
                    output = docker('logs', cid).decode(errors='replace')[-4096:]
                    raise AssertionError(f'producer exited before the requested fault boundary: {actual}; {output}')
            return None
        return self.wait(observe, 'fault did not reach its real API boundary', seconds)

    def journal(self):
        # Only frozen journals are inspected. SQLite's immutable flag skips
        # WAL discovery, so use it only when no nonempty WAL remains. A crashed
        # writer's existing WAL/SHM is read through the ordinary read-only path.
        assert not self.controllers
        code = ("import sqlite3,json,pathlib; w=pathlib.Path('/observe/source.db-wal'); "
                               "uri='file:/observe/source.db?mode=ro'+('' if w.exists() and w.stat().st_size else '&immutable=1'); "
                               "c=sqlite3.connect(uri,uri=True); "
                               "rows=c.execute('SELECT id,generation,installation_id,request_json,payload_json,revision FROM image_jobs').fetchall(); c.close(); "
                               "print(json.dumps([dict(id=r[0],generation=r[1],installation_id=r[2],request=json.loads(r[3]),payload=json.loads(r[4]),revision=r[5]) for r in rows]))")
        if self.proxy:
            return self.proxy_code(code)
        # Maintenance after the old proxy itself was collected: a fresh trusted
        # read-only observer needs neither a daemon socket nor host namespaces.
        cid = docker(*self.container(viewer=True, entrypoint='/usr/bin/python3'), self.proxy_base,
                     '-B', '-c', code.replace('/observe/', '/state/')).decode().strip()
        try:
            data = docker('start', '--attach', cid)
            actual = json.loads(docker('inspect', cid))[0]['State']
            assert actual['ExitCode'] == 0 and actual['Status'] == 'exited' and not actual['OOMKilled']
            return json.loads(data)
        finally:
            self.remove_container(cid)

    def row(self, job):
        return next(row for row in self.journal() if row['id'] == job)

    def partial_chunk(self, job):
        assert str(uuid.UUID(job)) == job
        return self.proxy_code(f"import pathlib,hashlib,json; paths=[p for p in pathlib.Path('/observe/blobs').rglob('chunk-00000000') if p.parent.parent.name=={json.dumps(job)}]; "
                               "assert len(paths)<=1; p=paths[0] if paths else None; "
                               "print(json.dumps(dict(sha256=hashlib.sha256(p.read_bytes()).hexdigest(),size=p.stat().st_size,device=p.stat().st_dev,inode=p.stat().st_ino) if p else None))")

    def stored_content(self, reference):
        # Independent, read-only storage observation. Also retain an existing
        # chunk's inode so a resume cannot silently replace its published data.
        code = ("import pathlib,hashlib,json,uuid; "
                f"r=json.loads({json.dumps(json.dumps(reference))}); "
                "[uuid.UUID(r[k]) for k in ['installation_id','id','generation']]; "
                "p=pathlib.Path('/observe/blobs/goldenhoop')/r['installation_id']/'large'/r['id']/r['generation']; "
                "m=json.loads((p/'manifest').read_bytes()); assert m['reference']==r; h=hashlib.sha256(); size=0; first=None\n"
                "for i,c in enumerate(m['chunks']):\n"
                " f=p/f'chunk-{i:08}'; data=f.read_bytes(); digest=hashlib.sha256(data).hexdigest(); assert len(data)==c['size_bytes'] and digest==c['sha256']; h.update(data); size+=len(data)\n"
                " if i==0: first=dict(sha256=digest,size=len(data),device=f.stat().st_dev,inode=f.stat().st_ino)\n"
                "assert size==r['size_bytes'] and h.hexdigest()==r['sha256']; print(json.dumps(dict(size_bytes=size,sha256=h.hexdigest(),chunks=len(m['chunks']),first_chunk=first)))")
        return self.proxy_code(code)

    def start(self, arguments):
        cid = docker(*(self.container() + [self.image, '--database', '/state/source.db', '--artifact-root', '/state/blobs', *arguments])).decode().strip()
        self.controllers.add(cid)
        docker('start', cid)
        return cid

    def kill(self, cid):
        before = json.loads(docker('inspect', cid))[0]
        assert before['Config']['Labels']['dev.goldenhoop.owner'] == self.owner
        assert before['State']['Running'] and before['State']['Pid'] > 1
        docker('kill', '--signal', 'KILL', cid)
        assert docker('wait', cid).strip() == b'137'
        after = json.loads(docker('inspect', cid))[0]['State']
        assert after['Status'] == 'exited' and after['ExitCode'] == 137 and not after['OOMKilled']
        self.report['observations'].setdefault('actual_killed_producers', []).append(dict(container_id=cid, host_pid=before['State']['Pid'], exit=after))
        self.remove_container(cid)
        self.controllers.remove(cid)

    def stop_supervisors(self, keep_proxy=False):
        for cid in docker('ps', '-aq', '--no-trunc', '--filter', 'label=dev.goldenhoop.owner='+self.owner).decode().splitlines():
            actual = json.loads(docker('inspect', cid))[0]
            role = actual['Config']['Labels'].get('dev.goldenhoop.role')
            # Source images inherit the fixture label. Their provider carriers
            # must be collected by Rust, never hidden by supervisor teardown.
            if role in ['image-source-export', 'image-prepare'] or keep_proxy and cid == self.proxy:
                continue
            self.remove_container(cid)

    def new_export(self, source):
        job, generation = str(uuid.uuid4()), str(uuid.uuid4())
        self.jobs.append((job, generation, source))
        return job, ['export', '--id', job, '--generation', generation, '--source-image', source]

    def recovered_export(self, job, before, partial=None):
        value = self.call(['reconcile-export', '--id', job])
        assert value['archive_ready'] and value['provider_cleanup'] == 'complete' and value['error'] is None, value
        after = self.row(job)
        assert after['generation'] == before['generation']
        if before['payload']['archive']:
            assert value['archive'] == before['payload']['archive']
        recovery = value['recovery_observation']
        assert recovery['outcome'] == 'ready'
        assert recovery['original_error'] == before['payload']['error']
        stored = self.stored_content(value['archive'])
        if partial:
            assert stored['first_chunk'] == partial
        self.report['observations'].setdefault('recoveries', []).append(dict(before=before, after=after, report=value, independent_storage=stored))
        self.call(['collect-export', '--id', job])
        return value

    def exercise(self):
        host = json.loads(docker('image', 'inspect', self.args.image))[0]
        assert host['Config']['Labels']['dev.goldenhoop.owner'] == self.args.image_owner
        assert host['Config']['Labels']['dev.goldenhoop.task'] == 'm4-image-source-export-fixture'
        self.image = host['Id']
        self.report['host_image_id'] = self.image
        if self.recovery:
            assert self.image == self.recovery['host_image_id']
            self.proxy_volume = 'ghsrc-proxy-'+self.owner
            self.clone_volume = 'ghsrc-clone-'+self.owner
            self.proxy_base = json.loads(docker('image', 'inspect', self.args.proxy_image))[0]['Id']
            assert self.proxy_base == self.recovery.get('trusted_proxy_image_id', self.proxy_base)
            candidates = docker('ps', '-aq', '--no-trunc', '--filter', 'name=^ghsrc-fault-'+self.owner+'$').decode().splitlines()
            if candidates:
                assert len(candidates) == 1
                proxy = json.loads(docker('inspect', candidates[0]))[0]
                assert proxy['Config']['Labels']['dev.goldenhoop.owner'] == self.owner
                assert proxy['Config']['Labels']['dev.goldenhoop.task'] == 'm4-image-source-contract'
                self.proxy = proxy['Id']
            self.stop_supervisors(keep_proxy=True)
            self.report['cases'].append('same_retained_fixture_is_settled_by_actual_Rust_maintenance_after_reader_failure_without_rewriting_original_report')
            self.report['result'] = 'passed'
            return
        proxy_base = json.loads(docker('image', 'inspect', self.args.proxy_image))[0]
        self.proxy_base = proxy_base['Id']
        assert proxy_base['Os'] == 'linux' and proxy_base['Architecture'] == 'amd64'
        self.report.update(host_image_id=self.image, trusted_proxy_image_id=proxy_base['Id'])
        version = json.loads(docker('version', '--format', '{{json .Server}}'))
        self.report['observations']['docker_host'] = {key: version[key] for key in ['Version','ApiVersion','Os','Arch','KernelVersion']}
        self.volume = 'ghsrc-state-' + self.owner
        self.proxy_volume = 'ghsrc-proxy-' + self.owner
        self.clone_volume = 'ghsrc-clone-' + self.owner
        for volume in [self.volume, self.proxy_volume, self.clone_volume]:
            docker('volume', 'create', *self.labels, volume)
        proxy_code = (self.root/'tests/image_fault_proxy.py').read_text(encoding='utf-8')
        self.proxy = docker('create', '--name', 'ghsrc-fault-'+self.owner, *self.labels,
                            '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                            '--security-opt', 'no-new-privileges:true', '--memory', '512m', '--memory-swap', '512m', '--pids-limit', '64',
                            '--mount', f'type=volume,src={self.proxy_volume},dst=/proxy,volume-nocopy',
                            '--mount', f'type=volume,src={self.volume},dst=/observe,readonly,volume-nocopy',
                            '--mount', f'type=volume,src={self.clone_volume},dst=/clone,volume-nocopy',
                            '--mount', 'type=bind,src=/var/run/docker.sock,dst=/backend.sock',
                            '--entrypoint', '/usr/bin/python3', proxy_base['Id'], '-B', '-u', '-c', proxy_code).decode().strip()
        docker('start', self.proxy)
        self.wait(lambda: b'trusted Docker fault proxy ready' in docker('logs', self.proxy), 'proxy did not start')
        source, _ = self.source_image()

        self.control('arm', dict(mode='create_after'))
        job, args = self.new_export(source)
        producer = self.start(args)
        held = self.hit()
        assert held['fault']['backend_completed'] and held['fault']['status'] == 201
        self.call(['reconcile-export', '--id', job], expected=1)
        self.call(args, expected=1)
        self.report['cases'].append('actual_live_producer_excludes_competing_dispatch_and_reconciliation')
        self.kill(producer)
        before = self.row(job)
        assert before['payload']['phase'] == 'create_dispatched' and before['payload']['container_id'] is None
        # A copied database/lock is not authority to adopt a different inode.
        self.proxy_code("import pathlib,shutil,json; source=pathlib.Path('/observe'); target=pathlib.Path('/clone'); "
                        "[(shutil.copytree(p,target/p.name) if p.is_dir() else shutil.copy2(p,target/p.name)) for p in source.iterdir()]; print('true')")
        original = self.volume
        create_count = sum(r['method'] == 'POST' and '/containers/create' in r['path'] for r in self.control()['requests'])
        try:
            self.volume = self.clone_volume
            self.call(['reconcile-export', '--id', job], expected=1)
        finally:
            self.volume = original
        assert sum(r['method'] == 'POST' and '/containers/create' in r['path'] for r in self.control()['requests']) == create_count
        self.report['cases'].append('copied_database_and_lock_inodes_refused_without_provider_replay')
        self.control('release')
        value = self.recovered_export(job, before)
        assert value['source_observation']['container_id'] == held['fault']['container_id']
        self.report['cases'].append('positive_never_started_create_is_adopted_after_actual_producer_sigkill_without_recreate')

        self.control('arm', dict(mode='create_before'))
        job, args = self.new_export(source)
        producer = self.start(args)
        held = self.hit()
        assert not held['fault']['backend_completed']
        self.kill(producer)
        before = self.row(job)
        unknown = self.call(['reconcile-export', '--id', job], expected=2)
        assert not unknown['archive_ready'] and unknown['provider_cleanup'] == 'unknown' and unknown['error'] is not None
        assert self.row(job)['payload']['container_id'] is None
        create_count = sum(r['method'] == 'POST' and '/containers/create' in r['path'] for r in self.control()['requests'])
        self.control('release')
        self.wait(lambda: self.control()['fault']['backend_completed'], 'delayed original create did not settle')
        value = self.recovered_export(job, before)
        assert value['recovery_observation']['last_error'] == unknown['error']
        assert sum(r['method'] == 'POST' and '/containers/create' in r['path'] for r in self.control()['requests']) == create_count
        self.report['cases'].append('absent_unacknowledged_create_stays_unknown_then_adopts_late_original_effect_with_failure_history_and_no_replayed_create')

        self.control('arm', dict(mode='export_mid', skip=1))
        job, args = self.new_export(source)
        producer = self.start(args)
        self.hit()
        partial = self.wait(lambda: self.partial_chunk(job), 'partial upload did not publish its first immutable chunk')
        self.kill(producer)
        before = self.row(job)
        assert before['payload']['phase'] == 'upload_dispatched' and before['payload']['archive'] is not None
        self.control('release')
        self.recovered_export(job, before, partial)
        self.report['cases'].append('actual_partial_source_upload_resumes_the_same_reference_after_sigkill_and_revalidates_bytes_before_collection')

        self.control('arm', dict(mode='remove_after'))
        job, args = self.new_export(source)
        producer = self.start(args)
        self.hit()
        self.kill(producer)
        before = self.row(job)
        assert before['payload']['phase'] == 'removing'
        self.control('release')
        self.recovered_export(job, before)
        self.report['cases'].append('acknowledgement_lost_after_actual_carrier_removal_recovers_only_after_storage_and_id_name_absence_readback')

        job, args = self.new_export(source)
        self.call(args)
        self.control('arm', dict(mode='inspect404_after'))
        collector = self.start(['collect-export', '--id', job])
        self.hit()
        self.kill(collector)
        before = self.row(job)
        assert before['payload']['phase'] == 'collecting'
        self.control('release')
        value = self.call(['reconcile-export', '--id', job])
        assert value['provider_cleanup'] == 'complete' and not value['archive_ready'] and value['error'] is None
        assert self.row(job)['payload']['phase'] == 'collected'
        self.report['cases'].append('actual_interrupted_collector_deletes_only_the_original_fenced_immutable_generation')

        if self.args.builder_image:
            self.disk_recovery(source)
        self.report['observations']['proxy_requests'] = self.control()
        self.report['observations']['final_jobs'] = self.journal()
        assert all(row['payload']['phase'] in ['collected', 'failed_collected'] for row in self.journal())
        self.report['result'] = 'passed'

    def disk_recovery(self, source):
        builder = json.loads(docker('image', 'inspect', self.args.builder_image))[0]
        assert builder['Config']['Labels']['dev.goldenhoop.owner'] == self.args.builder_owner
        assert builder['Config']['Labels']['dev.goldenhoop.task'] == 'm4-image-builder-fixture'
        self.builder = builder['Id']
        self.report['builder_image_id'] = self.builder
        job, generation = str(uuid.uuid4()), str(uuid.uuid4())
        self.jobs.append((job, generation, source))
        self.parents.add(job)
        args = ['prepare', '--id', job, '--generation', generation, '--source-image', source,
                '--builder-image', self.builder, '--disk-bytes', str(64*1024**2)]
        if self.args.runtime == 'runc':
            args += ['--runtime', 'runc-development', '--allow-runc-development']
        self.control('arm', dict(mode='disk_mid'))
        producer = self.start(args)
        self.hit(seconds=720)
        partial = self.wait(lambda: self.partial_chunk(job), 'partial disk upload did not publish its first immutable chunk')
        self.kill(producer)
        before = self.row(job)
        assert before['payload']['phase'] == 'disk_upload_dispatched' and before['payload']['disk'] is not None
        starts = sum(r['method'] == 'POST' and r['path'].split('?')[0].endswith('/start') for r in self.control()['requests'])
        self.control('release')
        value = self.call(['reconcile-image', '--id', job])
        assert value['image_ready'] and value['provider_cleanup'] == 'complete' and value['error'] is None, value
        assert value['disk'] == before['payload']['disk'] and value['manifest'] == before['payload']['manifest']
        assert value['recovery_observation']['outcome'] == 'ready'
        assert sum(r['method'] == 'POST' and r['path'].split('?')[0].endswith('/start') for r in self.control()['requests']) == starts
        stored = self.stored_content(value['disk'])
        assert stored['first_chunk'] == partial
        self.report['observations']['disk_recovery'] = dict(before=before, report=value, after=self.row(job), independent_storage=stored)
        self.call(['collect-image', '--id', job])
        self.report['cases'].append('actual_partial_disk_upload_recovers_same_reference_and_manifest_after_sigkill_without_converter_restart_or_permit_replay')

    def cleanup(self):
        try:
            self.cleanup_resources()
        except Exception:
            if self.volume:
                self.report['retained_state_volume'] = self.volume
            # Even a reader/proxy failure must not leave trusted supervisors
            # running. Keep the ownership journal/outputs for reconciliation.
            self.stop_supervisors()
            raise

    def cleanup_resources(self):
        # Release real API operations, then stop only this fixture's producers.
        # Incomplete durable jobs retain their state volume and useful outputs.
        if self.proxy:
            state = self.control()
            if state['fault'] and not state['fault']['released']:
                self.control('release')
        for cid in list(self.controllers):
            self.remove_container(cid)
            self.controllers.remove(cid)
        unsettled = []
        rows = []
        if self.volume and self.jobs:
            try:
                rows = self.journal()
            except Exception:
                self.report['retained_state_volume'] = self.volume
                self.stop_supervisors()
                raise
            for row in rows:
                if row['id'] not in {job for job, _, _ in self.jobs}:
                    continue
                parent = row['id'] in self.parents
                action = 'image' if parent else 'export'
                if row['payload']['phase'] not in ['collected', 'failed_collected', 'ready', 'collecting']:
                    try:
                        self.call(['reconcile-'+action, '--id', row['id']])
                    except Exception as error:
                        unsettled.append(str(error))
                if self.row(row['id'])['payload']['phase'] in ['ready', 'collecting']:
                    self.call(['collect-'+action, '--id', row['id']])
            rows = self.journal()
            expected = {job for job, _, _ in self.jobs}
            for row in rows:
                if row['id'] in self.parents:
                    expected.add(row['payload']['source']['id'])
            assert {row['id'] for row in rows} == expected
            self.report['observations']['cleanup_jobs'] = rows
            unsettled += [row['id']+':'+row['payload']['phase'] for row in rows if row['payload']['phase'] not in ['collected', 'failed_collected']]
        if self.proxy:
            self.report['observations']['proxy_at_collection'] = self.control()
        self.stop_supervisors()
        for job in {row['id'] for row in rows} | {job for job, _, _ in self.jobs}:
            for key in ['dev.goldenhoop.image-job', 'dev.goldenhoop.job']:
                if docker('ps', '-aq', '--filter', f'label={key}={job}').strip():
                    unsettled.append('provider carrier still present for '+job)
            if docker('volume', 'ls', '--quiet', '--filter', 'label=dev.goldenhoop.job='+job).strip():
                unsettled.append('provider volume still present for '+job)
        if unsettled:
            self.report['retained_state_volume'] = self.volume
            raise AssertionError('; '.join(unsettled))
        for volume in [self.clone_volume, self.proxy_volume, self.volume]:
            if volume:
                value = json.loads(docker('volume', 'inspect', volume))[0]
                assert value['Labels']['dev.goldenhoop.owner'] == self.owner
                docker('volume', 'rm', volume)
                assert not docker('volume', 'ls', '--quiet', '--filter', 'name=^'+volume+'$').strip()
        for image in docker('image', 'ls', '--quiet', '--filter', 'label=dev.goldenhoop.owner='+self.owner).decode().splitlines():
            value = json.loads(docker('image', 'inspect', image))[0]
            assert value['Config']['Labels']['dev.goldenhoop.owner'] == self.owner
            docker('image', 'rm', image)
        if self.args.remove_image:
            for tag, owner, image in [(self.args.image,self.args.image_owner,self.image), (self.args.builder_image,self.args.builder_owner,self.builder)]:
                if image:
                    value = json.loads(docker('image', 'inspect', tag))[0]
                    assert value['Id'] == image and value['Config']['Labels']['dev.goldenhoop.owner'] == owner
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
    parser.add_argument('--proxy-image', required=True)
    parser.add_argument('--builder-image')
    parser.add_argument('--builder-owner')
    parser.add_argument('--runtime', choices=['runsc', 'runc'], default='runsc')
    parser.add_argument('--allow-runc-development', action='store_true')
    parser.add_argument('--source-commit')
    parser.add_argument('--remove-image', action='store_true')
    parser.add_argument('--recover-report', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('preserve the original output and choose a fresh report')
    if bool(args.builder_image) != bool(args.builder_owner):
        parser.error('a converter image requires its exact task owner')
    if args.runtime == 'runc' and not args.allow_runc_development:
        parser.error('runc requires explicit development opt-in and does not establish production isolation')
    if args.source_commit and not re.fullmatch('[a-f0-9]{40}', args.source_commit):
        parser.error('source commit must be a complete SHA1')
    raise SystemExit(Contract(args).run())
