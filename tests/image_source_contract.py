"""Actual trusted Rust host export; source containers are never executed."""
import argparse
from contextlib import closing
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import stat
import subprocess
import tarfile
import tempfile
import traceback
import uuid

from image_builder_contract import docker


class Contract:
    def __init__(self, args):
        self.args = args
        self.owner = uuid.uuid4().hex
        self.context = Path(tempfile.mkdtemp(prefix='goldenhoop-source-export-'))
        self.files = set()
        self.labels = ['--label', 'dev.goldenhoop.task=m4-image-source-contract',
                       '--label', 'dev.goldenhoop.owner=' + self.owner]
        self.counter = 0
        self.jobs = []
        self.image = None
        self.volume = None
        self.report = {'suite': 'actual-Rust-immutable-source-export', 'result': 'failed',
                       'cleanup': 'unknown', 'cases': [], 'observations': {},
                       'owner': self.owner, 'temporary_context': str(self.context),
                       'scope': 'trusted host source acquisition only; production converter handoff, gVisor and produced-image KVM gates remain required'}
        self.root = Path(__file__).resolve().parents[1]
        sources = [self.root/'Cargo.toml', self.root/'Cargo.lock', self.root/'images/host/Dockerfile', Path(__file__).resolve(), self.root/'tests/image_builder_contract.py']
        sources += sorted(p for p in (self.root/'crates').rglob('*') if p.is_file() and '__pycache__' not in p.parts)
        self.sources = sources
        self.hashes = self.fingerprints()

    def fingerprints(self):
        return {p.relative_to(self.root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in self.sources}

    def path(self, name):
        path = self.context/name
        assert not path.exists() and path.parent == self.context
        self.files.add(path)
        return path

    def source_image(self, volume=False):
        name = 'goldenhoop-source-fixture:' + self.owner + ('-volume' if volume else '-plain')
        path = self.path(uuid.uuid4().hex + '.tar')
        payload = b'goldenhoop-immutable-source\x00\xff' * 230000
        dockerfile = b'FROM scratch\nCOPY sentinel /sentinel\nCOPY payload /payload\nENTRYPOINT ["/source-must-never-execute"]\n'
        if volume:
            dockerfile += b'VOLUME ["/anonymous"]\n'
        with tarfile.open(path, 'w') as output:
            for filename, data in [('Dockerfile', dockerfile), ('sentinel', b'goldenhoop-source-ok\n'), ('payload', payload)]:
                entry = tarfile.TarInfo(filename)
                entry.size, entry.mode = len(data), 0o444
                output.addfile(entry, io.BytesIO(data))
        with path.open('rb') as source:
            docker('build', *self.labels, '--tag', name, '-', timeout=180, stdin=source)
        observed = json.loads(docker('image', 'inspect', name))[0]
        assert observed['Config']['Labels']['dev.goldenhoop.owner'] == self.owner
        return observed['Id'], payload

    def container(self, *, viewer=False, entrypoint=None):
        self.counter += 1
        args = ['create', '--name', f'ghsrc-{self.owner}-{self.counter}', *self.labels,
                '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                '--security-opt', 'no-new-privileges:true', '--cpus', '1',
                '--memory', '512m', '--memory-swap', '512m', '--pids-limit', '64',
                '--mount', f'type=volume,src={self.volume},dst=/state,volume-nocopy' + (',readonly' if viewer else '')]
        if viewer:
            args += ['--entrypoint', entrypoint or '/bin/true']
        else:
            # This is the trusted host controller, not the untrusted source.
            args += ['--mount', 'type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock']
        return args

    def remove_container(self, cid):
        value = json.loads(docker('inspect', cid))[0]
        assert value['Config']['Labels']['dev.goldenhoop.owner'] == self.owner
        assert value['Config']['Labels']['dev.goldenhoop.task'] == 'm4-image-source-contract'
        docker('rm', '--force', cid)
        assert cid not in docker('ps', '-aq', '--no-trunc').decode().splitlines()

    def call(self, arguments, expected=0, artifact_root='/state/blobs'):
        command = self.container() + [self.image, '--database', '/state/source.db', '--artifact-root', artifact_root, *arguments]
        cid = docker(*command).decode().strip()
        try:
            result = subprocess.run(['docker', 'start', '--attach', cid], capture_output=True, timeout=240)
            observed = json.loads(docker('inspect', cid))[0]
            state = observed['State']
            assert state['Status'] == 'exited' and not state['OOMKilled'], state
            assert state['ExitCode'] == expected, (state, result.stdout[-4000:], result.stderr[-1000:])
            value = json.loads(result.stdout) if result.stdout.strip() else None
            return value
        finally:
            self.remove_container(cid)

    def copy(self, source, name):
        cid = docker(*self.container(viewer=True), self.image).decode().strip()
        try:
            path = self.path(name)
            docker('cp', f'{cid}:/state/{source}', str(path))
            assert json.loads(docker('inspect', cid))[0]['State']['Status'] == 'created'
            return path
        finally:
            self.remove_container(cid)

    def exercise(self):
        image = json.loads(docker('image', 'inspect', self.args.image))[0]
        assert image['Config']['Labels']['dev.goldenhoop.task'] == 'm4-image-source-export-fixture'
        assert image['Config']['Labels']['dev.goldenhoop.owner'] == self.args.image_owner
        self.image = image['Id']
        self.report['host_image_id'] = self.image
        self.volume = 'ghsrc-state-' + self.owner
        docker('volume', 'create', *self.labels, self.volume)
        source, payload = self.source_image()
        job, generation = str(uuid.uuid4()), str(uuid.uuid4())
        self.jobs.append((job, generation, source))
        arguments = ['export', '--id', job, '--generation', generation, '--source-image', source]
        value = self.call(arguments)
        assert value['archive_ready'] and value['provider_cleanup'] == 'complete' and value['error'] is None, value
        observed = value['source_observation']
        assert observed['image_id'] == source and observed['state']['Status'] == 'created' and observed['state']['Pid'] == 0
        assert observed['state']['Running'] is False and observed['restart_count'] == 0 and observed['mounts'] == []
        assert observed['readonly_rootfs'] and observed['network_mode'] == 'none'
        assert not docker('ps', '-aq', '--filter', 'label=dev.goldenhoop.image-job=' + job).strip()
        self.report['observations']['export'] = value
        self.report['cases'].append('actual_pinned_source_export_stays_created_without_process_mounts_or_network_then_confirms_carrier_absence')
        reference = value['archive']
        prefix = f'blobs/goldenhoop/{reference["installation_id"]}/large/{reference["id"]}/{reference["generation"]}'
        manifest = json.loads(self.copy(prefix + '/manifest', 'manifest.json').read_bytes())
        assert manifest['reference'] == reference and len(manifest['chunks']) >= 2
        chunks = []
        for index, item in enumerate(manifest['chunks']):
            data = self.copy(prefix + f'/chunk-{index:08}', f'chunk-{index:08}').read_bytes()
            assert len(data) == item['size_bytes'] and hashlib.sha256(data).hexdigest() == item['sha256']
            chunks.append(data)
        archive = b''.join(chunks)
        assert len(archive) == reference['size_bytes'] < 16*1024**2 and hashlib.sha256(archive).hexdigest() == reference['sha256']
        with tarfile.open(fileobj=io.BytesIO(archive), mode='r:') as rootfs:
            assert rootfs.extractfile('sentinel').read() == b'goldenhoop-source-ok\n'
            assert rootfs.extractfile('payload').read() == payload
        self.report['cases'].append('independent_chunk_whole_hash_and_archive_payload_readback_without_host_unpack')
        docker('image', 'rm', source)
        assert self.call(arguments)['archive'] == reference
        self.report['cases'].append('fresh_host_process_reopens_same_intent_and_archive_after_source_image_collection_without_relaunch')
        foreign = arguments.copy()
        foreign[foreign.index('--generation') + 1] = str(uuid.uuid4())
        self.call(foreign, expected=1)
        assert self.call(arguments)['archive'] == reference
        self.report['cases'].append('foreign_generation_refused_before_provider_write')
        bad, _ = self.source_image(volume=True)
        bad_job, bad_generation = str(uuid.uuid4()), str(uuid.uuid4())
        self.jobs.append((bad_job, bad_generation, bad))
        refused = self.call(['export', '--id', bad_job, '--generation', bad_generation, '--source-image', bad], expected=2)
        assert not refused['archive_ready'] and refused['provider_cleanup'] == 'complete' and refused['archive'] is None
        assert refused['error']['code'] == 'unsupported_capability'
        assert not docker('ps', '-aq', '--filter', 'label=dev.goldenhoop.image-job=' + bad_job).strip()
        self.report['cases'].append('anonymous_volume_source_refused_without_carrier_or_storage_writes')
        collected = self.call(['collect-export', '--id', job])
        assert not collected['archive_ready'] and collected['provider_cleanup'] == 'complete' and collected['error'] is None
        assert self.call(['collect-export', '--id', job])['provider_cleanup'] == 'complete'
        self.call(arguments, expected=2)
        self.call(['collect-export', '--id', job], expected=1, artifact_root='/state/foreign-blobs')
        viewer = docker(*self.container(viewer=True, entrypoint='/usr/bin/find'), self.image, '/state/blobs', '-type', 'f', '-print').decode().strip()
        try:
            assert docker('start', '--attach', viewer) == b''
            state = json.loads(docker('inspect', viewer))[0]['State']
            assert state['Status'] == 'exited' and state['ExitCode'] == 0 and not state['OOMKilled'], state
        finally:
            self.remove_container(viewer)
        self.report['cases'].append('confirmed_exact_archive_collection_is_idempotent_and_collected_identity_cannot_relaunch')
        self.report['cases'].append('foreign_storage_binding_refused_and_independent_readonly_inspector_confirms_no_blob_objects')
        database = self.copy('source.db', 'state.db')
        with closing(sqlite3.connect(f'file:{database.as_posix()}?mode=ro&immutable=1', uri=True)) as connection:
            row = connection.execute('SELECT revision,payload_json FROM image_jobs WHERE id=?', (job,)).fetchone()
        assert row[0] > 0 and json.loads(row[1])['phase'] == 'collected'
        self.report['observations']['final_job_revision'] = row[0]
        self.report['result'] = 'passed'

    def cleanup(self):
        # All host-controller processes are stopped before their private state
        # volume is collected, fencing local filesystem writers on failures.
        for cid in docker('ps', '-aq', '--filter', 'label=dev.goldenhoop.owner=' + self.owner).decode().splitlines():
            self.remove_container(cid)
        unsettled = []
        if self.volume and self.jobs:
            try:
                snapshot = self.copy('source.db', 'cleanup-state.db')
                with closing(sqlite3.connect(f'file:{snapshot.as_posix()}?mode=ro&immutable=1', uri=True)) as connection:
                    rows = connection.execute('SELECT id,generation,payload_json FROM image_jobs').fetchall()
                self.report['observations']['cleanup_jobs'] = [{'id': row[0], 'generation': row[1], 'payload': json.loads(row[2])} for row in rows]
                actual_jobs = {(row[0], row[1]) for row in rows}
                expected_jobs = {(job, generation) for job, generation, _ in self.jobs}
                if actual_jobs != expected_jobs:
                    unsettled.append('private cleanup journal does not cover exactly the dispatched fixture intents')
                for job, _, raw in rows:
                    payload = json.loads(raw)
                    if payload['phase'] == 'create_dispatched' and payload['container_id'] is None and not docker('ps', '-aq', '--filter', 'label=dev.goldenhoop.image-job=' + job).strip():
                        unsettled.append('provider create settlement is unconfirmed for ' + job)
            except Exception as error:
                unsettled.append('private cleanup journal observation failed: ' + str(error))
        for job, generation, source in self.jobs:
            for cid in docker('ps', '-aq', '--filter', 'label=dev.goldenhoop.image-job=' + job).decode().splitlines():
                value = json.loads(docker('inspect', cid))[0]
                labels = value['Config']['Labels']
                assert labels['dev.goldenhoop.generation'] == generation and labels['dev.goldenhoop.role'] == 'image-source-export'
                assert value['Image'] == source and value['State']['Status'] == 'created' and value['State']['Pid'] == 0 and not value['Mounts']
                docker('rm', cid)
            assert not docker('ps', '-aq', '--filter', 'label=dev.goldenhoop.image-job=' + job).strip()
        assert not docker('ps', '-aq', '--filter', 'label=dev.goldenhoop.owner=' + self.owner).strip()
        if self.volume:
            value = json.loads(docker('volume', 'inspect', self.volume))[0]
            assert value['Labels']['dev.goldenhoop.owner'] == self.owner and value['Labels']['dev.goldenhoop.task'] == 'm4-image-source-contract'
            docker('volume', 'rm', self.volume)
            assert not docker('volume', 'ls', '--quiet', '--filter', 'name=' + self.volume).strip()
        for image in docker('image', 'ls', '--quiet', '--filter', 'label=dev.goldenhoop.owner=' + self.owner).decode().splitlines():
            value = json.loads(docker('image', 'inspect', image))[0]
            assert value['Config']['Labels']['dev.goldenhoop.owner'] == self.owner
            docker('image', 'rm', image)
        assert not docker('image', 'ls', '--quiet', '--filter', 'label=dev.goldenhoop.owner=' + self.owner).strip()
        if self.args.remove_image and self.image:
            value = json.loads(docker('image', 'inspect', self.args.image))[0]
            assert value['Config']['Labels']['dev.goldenhoop.owner'] == self.args.image_owner and value['Id'] == self.image
            docker('image', 'rm', self.args.image)
            assert not docker('image', 'ls', '--quiet', '--filter', 'reference=' + self.args.image).strip()
        assert self.context.resolve() == self.context.absolute() and self.context.parent.resolve() == Path(tempfile.gettempdir()).resolve()
        assert self.context.name.startswith('goldenhoop-source-export-') and not self.context.is_symlink()
        for entry in self.context.iterdir():
            metadata = entry.lstat()
            assert entry in self.files and stat.S_ISREG(metadata.st_mode) and not entry.is_symlink()
            assert not getattr(metadata, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0)
            entry.chmod(stat.S_IREAD | stat.S_IWRITE)
            entry.unlink()
        self.context.rmdir()
        assert not self.context.exists()
        if unsettled:
            raise AssertionError('; '.join(unsettled))

    def run(self):
        try:
            self.exercise()
        except Exception as error:
            self.report['error'] = f'{type(error).__name__}: {error}'
            self.report['failure_site'] = [{'file': Path(frame.filename).name, 'line': frame.lineno, 'function': frame.name} for frame in traceback.extract_tb(error.__traceback__)]
        finally:
            try:
                self.cleanup()
                self.report['cleanup'] = 'complete'
            except Exception as error:
                self.report['cleanup_error'] = f'{type(error).__name__}: {error}'
                self.report['cleanup_failure_site'] = [{'file': Path(frame.filename).name, 'line': frame.lineno, 'function': frame.name} for frame in traceback.extract_tb(error.__traceback__)]
                self.report['result'] = 'failed'
            self.report['source_files_sha256'] = self.hashes
            self.report['owned_jobs'] = self.jobs
            if self.fingerprints() != self.hashes:
                self.report['source_changed_during_run'] = True
                self.report['result'] = 'failed'
            self.args.output.parent.mkdir(parents=True, exist_ok=True)
            with self.args.output.open('x', encoding='utf-8', newline='\n') as output:
                output.write(json.dumps(self.report, indent=2) + '\n')
            print(json.dumps({key: self.report[key] for key in ['result', 'cleanup', 'cases']}))
        return 0 if self.report['result'] == 'passed' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', required=True)
    parser.add_argument('--image-owner', required=True)
    parser.add_argument('--remove-image', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('output exists; preserve the original and choose a fresh report')
    raise SystemExit(Contract(args).run())
