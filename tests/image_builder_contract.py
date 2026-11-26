"""Real isolated Rust conversion and offline ext4 inspection; no VM claim."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import tempfile
import time
import traceback
import uuid


def docker(*args, timeout=60, stdin=None):
    value = subprocess.run(['docker', *args], stdin=stdin, capture_output=True, timeout=timeout)
    if value.returncode:
        raise RuntimeError(f'Docker {args[0]} failed: {value.stderr.decode(errors="replace")[-3000:]}')
    return value.stdout


def digest(path):
    with path.open('rb') as source:
        return {'sha256': hashlib.file_digest(source, 'sha256').hexdigest(), 'size_bytes': path.stat().st_size}


class Contract:
    def __init__(self, args):
        self.args = args
        root = Path(__file__).resolve().parents[1]
        sources = [root/'Cargo.toml', root/'Cargo.lock', root/'images/agent/Dockerfile', Path(__file__).resolve()]
        sources += sorted((root/'crates').rglob('*.rs'))
        sources += sorted((root/'crates').rglob('Cargo.toml'))
        self.sources = sources
        self.source_hashes = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
        self.owner = uuid.uuid4().hex
        self.context = Path(tempfile.mkdtemp(prefix='goldenhoop-builder-contract-'))
        self.label = ['--label', 'dev.goldenhoop.task=m4-image-builder-contract',
                      '--label', f'dev.goldenhoop.owner={self.owner}']
        self.report = {'suite': 'actual-isolated-Rust-image-converter', 'result': 'failed',
                       'cleanup': 'unknown', 'cases': [], 'observations': {},
                       'runtime': args.runtime, 'scope': 'offline conversion component only; host production orchestration and KVM acceptance remain required'}
        self.counter = 0
        self.image = None

    def volume(self):
        self.counter += 1
        name = f'ghibv-{self.owner}-{self.counter}'
        docker('volume', 'create', *self.label, name)
        return name

    def container(self, arguments, *, entrypoint=None, mounts=(), builder=False):
        self.counter += 1
        command = ['create', '--name', f'ghib-{self.owner}-{self.counter}', *self.label,
                   '--runtime', self.args.runtime, '--network', 'none', '--read-only',
                   '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                   '--cpus', '1', '--memory', '1g' if builder else '128m',
                   '--memory-swap', '1g' if builder else '128m', '--pids-limit', '64' if builder else '32']
        if builder:
            for capability in ['CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'FSETID']:
                command += ['--cap-add', capability]
        for name, target, readonly in mounts:
            command += ['--mount', f'type=volume,src={name},dst={target},volume-nocopy' + (',readonly' if readonly else '')]
        if entrypoint:
            command += ['--entrypoint', entrypoint]
        return docker(*command, self.image, *arguments).decode().strip()

    def remove_container(self, cid):
        value = json.loads(docker('inspect', cid))[0]
        assert value['Config']['Labels']['dev.goldenhoop.owner'] == self.owner
        assert value['Config']['Labels']['dev.goldenhoop.task'] == 'm4-image-builder-contract'
        docker('rm', '--force', cid)
        assert cid not in docker('ps', '-aq', '--no-trunc').decode().splitlines()

    def inspected(self, volume, program, arguments):
        cid = self.container(arguments, entrypoint=program, mounts=[(volume, '/output', True)] if volume else [])
        try:
            output = docker('start', '--attach', cid)
            state = json.loads(docker('inspect', cid))[0]['State']
            assert state['Status'] == 'exited' and state['ExitCode'] == 0 and not state['OOMKilled'], state
            return output
        finally:
            self.remove_container(cid)

    def archive(self, kind):
        path = self.context / (uuid.uuid4().hex + '.tar')
        with tarfile.open(path, 'w', format=tarfile.PAX_FORMAT) as output:
            def add(name, data=b'', entry_type=tarfile.REGTYPE, target='', mode=0o644, uid=1000):
                entry = tarfile.TarInfo(name)
                entry.type, entry.linkname, entry.mode = entry_type, target, mode
                entry.uid = entry.gid = uid
                entry.size = len(data) if entry_type == tarfile.REGTYPE else 0
                output.addfile(entry, io.BytesIO(data))
            if kind == 'escape':
                add('escape', entry_type=tarfile.SYMTYPE, target='..')
                add('escape/outside', b'forbidden')
            elif kind == 'absolute':
                add('/outside', b'forbidden')
            elif kind == 'device':
                add('device', entry_type=tarfile.CHRTYPE)
            else:
                for name in ['usr', 'usr/local', 'usr/local/bin', 'usr/sbin', 'etc']:
                    add(name, entry_type=tarfile.DIRTYPE, mode=0o777)
                add('sbin', entry_type=tarfile.SYMTYPE, target='usr/sbin')
                add('usr/local/bin/goldenhoop-agent', b'old-untrusted', mode=0o666)
                add('workspace/agent-alias', entry_type=tarfile.LNKTYPE, target='usr/local/bin/goldenhoop-agent')
                add('etc/machine-id', b'stale-image-identity')
                add('etc/resolv.conf', entry_type=tarfile.SYMTYPE, target='/outside')
                add('etc/goldenhoop/guest.json', b'{}', mode=0o666)
                add('usr/bin/sentinel', b'goldenhoop-image-builder-ok\n')
        return path

    def seeded(self, archive, request):
        volume = self.volume()
        cid = self.container([], entrypoint='/bin/true', mounts=[(volume, '/input', False)])
        packet = self.context / (uuid.uuid4().hex + '-input.tar')
        with tarfile.open(packet, 'w') as output:
            header = output.gettarinfo(str(archive), arcname='source.tar')
            header.uid = header.gid = 0
            header.mode = 0o400
            with archive.open('rb') as source:
                output.addfile(header, source)
            data = json.dumps(request).encode()
            header = tarfile.TarInfo('prepare.json')
            header.uid = header.gid = 0
            header.mode, header.size = 0o400, len(data)
            output.addfile(header, io.BytesIO(data))
        try:
            with packet.open('rb') as source:
                docker('cp', '-', f'{cid}:/input', stdin=source)
            assert json.loads(docker('inspect', cid))[0]['State']['Status'] == 'created', 'input seeder was executed'
        finally:
            self.remove_container(cid)
        return volume

    def prepare(self, archive, request, volume, cancel=False):
        source = self.seeded(archive, request)
        cid = self.container(['prepare'], mounts=[(source, '/input', True), (volume, '/output', False)], builder=True)
        try:
            if cancel:
                docker('start', cid)
                deadline = time.monotonic() + 60
                while True:
                    stage = self.inspected(volume, '/usr/bin/find', ['/output', '-mindepth', '1', '-maxdepth', '1', '-name', '*.writing'])
                    if stage.strip():
                        break
                    state = json.loads(docker('inspect', cid))[0]['State']
                    assert state['Running'] and time.monotonic() < deadline, state
                docker('kill', '--signal', 'TERM', cid)
                docker('wait', cid, timeout=90)
                output = docker('logs', cid)
            else:
                attached = subprocess.run(['docker', 'start', '--attach', cid], capture_output=True, timeout=240)
                output = attached.stdout
            observed = json.loads(docker('inspect', cid))[0]
            state = observed['State']
            assert state['Status'] == 'exited' and not state['OOMKilled'], state
            answer = json.loads(output)
            assert state['ExitCode'] == (0 if answer['passed'] else 2), (state, answer)
            assert answer['tools_collected'] and answer['staging_absent'], answer
            return cid, answer
        except BaseException:
            self.remove_container(cid)
            raise

    def empty(self, volume):
        assert self.inspected(volume, '/usr/bin/find', ['/output', '-mindepth', '1', '-maxdepth', '1', '-print']) == b''

    def exercise(self):
        value = json.loads(docker('image', 'inspect', self.args.image))[0]
        assert value['Config']['Labels']['dev.goldenhoop.task'] == 'm4-image-builder-fixture'
        assert value['Config']['Labels']['dev.goldenhoop.owner'] == self.args.image_owner
        self.image = value['Id']
        self.report['image_id'] = self.image
        inventory = json.loads(self.inspected(None, '/bin/cat', ['/opt/goldenhoop/inventory.json']))
        self.report['observations']['inventory'] = inventory
        archive = self.archive('positive')
        request = dict(generation=str(uuid.uuid4()), archive=digest(archive), agent=inventory['agent'], init=inventory['init'], disk_bytes=64*1024**2)
        volume = self.volume()
        cid, result = self.prepare(archive, request, volume)
        try:
            assert result['passed'], result
            manifest = result['manifest']
            assert manifest['archive'] == request['archive'] and manifest['agent'] == inventory['agent'] and manifest['init'] == inventory['init']
            assert manifest['format'] == 1 and manifest['generation'] == request['generation']
            assert manifest['disk']['size_bytes'] == request['disk_bytes']
            assert manifest['mke2fs'] == inventory['mke2fs'] and manifest['e2fsck'] == inventory['e2fsck']
            exported = self.context / 'rootfs.ext4'
            docker('cp', f'{cid}:/output/{request["generation"]}/rootfs.ext4', str(exported))
            assert digest(exported) == manifest['disk']
        finally:
            self.remove_container(cid)
        disk = '/output/' + request['generation'] + '/rootfs.ext4'
        def debug(command):
            return self.inspected(volume, '/usr/sbin/debugfs', ['-R', command, disk])
        assert debug('cat /usr/bin/sentinel') == b'goldenhoop-image-builder-ok\n'
        assert debug('cat /workspace/agent-alias') == b'old-untrusted'
        assert debug('cat /etc/machine-id') == b''
        identity_stat = debug('stat /etc/machine-id').decode()
        assert 'Inode:' in identity_stat and re.search(r'\bSize:\s+0\b', identity_stat), identity_stat
        parent_stat = debug('stat /usr/local/bin').decode()
        assert re.search(r'User:\s+0\s+Group:\s+0\b', parent_stat), parent_stat
        assert re.search(r'Mode:\s+0755\b', parent_stat), parent_stat
        workspace_stat = debug('stat /workspace').decode()
        assert re.search(r'User:\s+1000\s+Group:\s+1000\b', workspace_stat), workspace_stat
        assert re.search(r'Mode:\s+02770\b', workspace_stat), workspace_stat
        self.report['observations']['pinned_parent_stat'] = parent_stat
        self.report['observations']['workspace_stat'] = workspace_stat
        assert json.loads(debug('cat /etc/goldenhoop/guest.json')) == {'control_port': 52, 'pids': 256}
        assert debug('cat /etc/resolv.conf') == b'nameserver 127.0.0.1\n'
        for name, path in [('agent', '/usr/local/bin/goldenhoop-agent'), ('init', '/usr/sbin/goldenhoop-init')]:
            data = debug('cat ' + path)
            assert hashlib.sha256(data).hexdigest() == inventory[name]['sha256'] and len(data) == inventory[name]['size_bytes']
        self.report['observations']['prepared_manifest'] = manifest
        self.report['cases'].append('actual_offline_ext4_and_pinned_assets_private_hardlink_identity_configuration')
        repeated, refused = self.prepare(archive, request, volume)
        self.remove_container(repeated)
        assert not refused['passed'] and 'already exists' in refused['error'], refused
        assert debug('cat /usr/bin/sentinel') == b'goldenhoop-image-builder-ok\n'
        self.report['cases'].append('published_generation_refuses_overwrite_and_preserves_original')
        for kind in ['digest', 'escape', 'absolute', 'device']:
            source = archive if kind == 'digest' else self.archive(kind)
            request = dict(request, generation=str(uuid.uuid4()), archive=digest(source))
            if kind == 'digest':
                request['archive']['sha256'] = '0'*64
            target = self.volume()
            cid, refused = self.prepare(source, request, target)
            self.remove_container(cid)
            assert not refused['passed'], refused
            self.empty(target)
            self.report['observations'][kind + '_refusal'] = refused['error']
            self.report['cases'].append(kind + '_refused_with_actual_empty_output_volume')
        request = dict(request, generation=str(uuid.uuid4()), archive=digest(archive), disk_bytes=4*1024**3)
        target = self.volume()
        cid, stopped = self.prepare(archive, request, target, cancel=True)
        self.remove_container(cid)
        assert not stopped['passed'] and 'interrupted' in stopped['error'], stopped
        self.empty(target)
        self.report['cases'].append('TERM_fences_conversion_and_confirms_tracked_tool_and_staging_collection')
        self.report['result'] = 'passed'

    def clean_context(self):
        assert self.context.resolve() == self.context.absolute() and self.context.resolve().parent == Path(tempfile.gettempdir()).resolve()
        assert self.context.name.startswith('goldenhoop-builder-contract-')
        assert not self.context.is_symlink()
        for entry in self.context.iterdir():
            metadata = entry.lstat()
            assert stat.S_ISREG(metadata.st_mode) and not entry.is_symlink(), entry
            assert not getattr(metadata, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0), entry
            assert re.fullmatch(r'(?:[0-9a-f]{32}(?:-input)?\.tar|rootfs\.ext4)', entry.name), entry
            # Docker cp preserves 0400 as the Windows read-only attribute.
            entry.chmod(stat.S_IREAD | stat.S_IWRITE)
            entry.unlink()
        self.context.rmdir()
        assert not self.context.exists()

    def run(self):
        try:
            self.exercise()
        except Exception as error:
            self.report['error'] = f'{type(error).__name__}: {error}'
            self.report['failure_site'] = [{'file': Path(frame.filename).name, 'line': frame.lineno, 'function': frame.name} for frame in traceback.extract_tb(error.__traceback__)]
        finally:
            errors = []
            try:
                for cid in docker('ps', '-aq', '--filter', f'label=dev.goldenhoop.owner={self.owner}').decode().splitlines():
                    self.remove_container(cid)
                assert not docker('ps', '-aq', '--filter', f'label=dev.goldenhoop.owner={self.owner}').strip()
                for name in docker('volume', 'ls', '--quiet', '--filter', f'label=dev.goldenhoop.owner={self.owner}').decode().splitlines():
                    value = json.loads(docker('volume', 'inspect', name))[0]
                    assert value['Labels']['dev.goldenhoop.task'] == 'm4-image-builder-contract' and value['Labels']['dev.goldenhoop.owner'] == self.owner
                    docker('volume', 'rm', name)
                assert not docker('volume', 'ls', '--quiet', '--filter', f'label=dev.goldenhoop.owner={self.owner}').strip()
                if self.args.remove_image and self.image:
                    value = json.loads(docker('image', 'inspect', self.args.image))[0]
                    assert value['Config']['Labels']['dev.goldenhoop.owner'] == self.args.image_owner
                    docker('image', 'rm', self.args.image)
                    assert not docker('image', 'ls', '--quiet', '--filter', f'reference={self.args.image}').strip()
                self.clean_context()
            except Exception as error:
                errors.append(str(error))
            self.report['cleanup'] = 'complete' if not errors else 'unknown'
            if errors:
                self.report['cleanup_errors'] = errors
                self.report['result'] = 'failed'
            root = Path(__file__).resolve().parents[1]
            current = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in self.sources}
            self.report['source_files_sha256'] = self.source_hashes
            if current != self.source_hashes:
                self.report['source_changed_during_run'] = True
                self.report['result'] = 'failed'
            self.args.output.parent.mkdir(parents=True, exist_ok=True)
            with self.args.output.open('x', encoding='utf-8', newline='\n') as output:
                output.write(json.dumps(self.report, indent=2)+'\n')
            print(json.dumps({key: self.report[key] for key in ['result', 'cleanup', 'cases']}))
        return 0 if self.report['result'] == 'passed' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', required=True)
    parser.add_argument('--image-owner', required=True)
    parser.add_argument('--runtime', choices=['runsc', 'runc'], default='runsc')
    parser.add_argument('--allow-runc-development', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--remove-image', action='store_true')
    args = parser.parse_args()
    if args.output.exists():
        parser.error('output already exists; preserve the original report and choose a fresh path')
    if args.runtime == 'runc' and not args.allow_runc_development:
        parser.error('runc requires explicit --allow-runc-development')
    raise SystemExit(Contract(args).run())
