"""Actual default-runsc conversion followed by a jailed KVM boot of its disk.

Python supplies test fixtures and independently verifies storage; production
source acquisition, conversion, isolation, native lifecycle and RPC are Rust.
No host extraction or second mkfs substitutes for the prepared disk.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import tarfile
import uuid

from firecracker_guest_contract import artifact, digest, download
from image_builder_contract import docker
from image_prepare_contract import Contract as PreparationContract


class Contract(PreparationContract):
    def __init__(self, args):
        super().__init__(args)
        self.disk_size = 256 * 1024**2
        self.guest_fixture = Path('/var/lib') / ('ghip-' + self.owner[:8])
        self.owns_guest_fixture = False
        self.guest_collected = True
        self.sources += [Path(__file__).resolve(), self.root / 'tests/firecracker_guest_contract.py',
                         self.root / 'images/microvm/upstream.json',
                         self.root / '.github/workflows/image-prepared-guest.yml']
        self.hashes = self.fingerprints()
        self.report.update(suite='actual-runsc-prepared-disk-jailed-KVM-guest',
                           scope='private verified image-to-KVM handoff; interrupted allocation recovery, snapshots, templates and complete M4 remain unaccepted',
                           prepared_guest_fixture=str(self.guest_fixture),
                           guest_started=False, runtime_capabilities_verified=False)

    def exercise(self):
        runtime = subprocess.run(['runsc', '--version'], capture_output=True, timeout=15, check=True)
        self.report['observations']['runtime_identity'] = dict(
            runsc_version=runtime.stdout.decode().strip(), runsc_sha256=digest(Path('/usr/local/bin/runsc')),
            docker=json.loads(docker('version', '--format', '{{json .}}')),
            kernel=platform.release(), uid=os.geteuid())
        observation = subprocess.run([str(self.args.binary.resolve(strict=True)), 'probe-kvm'],
                                     capture_output=True, timeout=30)
        self.report['observations']['kvm_prerequisite'] = json.loads(observation.stdout)
        assert observation.returncode == 0, self.report['observations']['kvm_prerequisite']
        super().exercise()

    def probe(self, binary, configuration, timeout):
        self.guest_collected = False
        process = subprocess.Popen([str(binary), 'probe-guest', '--config', str(configuration)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.terminate()
            stdout, stderr = process.communicate(timeout=45)
            self.report['observations']['guest_watchdog_terminated_operation'] = True
        assert len(stdout) <= 1024**2 and len(stderr) <= 1024**2
        result = json.loads(stdout)
        self.report['observations']['last_guest_probe'] = dict(
            result=result, exit_code=process.returncode, stderr=stderr.decode(errors='replace')[-3000:])
        generation = uuid.UUID(result['generation'])
        self.guest_collected = (result['cleanup'] == 'complete' and result['root_absent'] and
                                result['cgroup_absent'] and result['vmm_reaped'] and
                                not (Path('/var/lib') / ('ghv-' + generation.hex[:8])).exists() and
                                not (Path('/sys/fs/cgroup') / ('ghv-' + generation.hex[:8])).exists())
        assert self.guest_collected, 'actual prepared-disk VMM collection is unconfirmed'
        return result, process.returncode, stderr

    def consume_prepared_disk(self, path, preparation):
        assert self.args.runtime == 'runsc', 'this gate requires actual production conversion'
        root = self.guest_fixture
        root.mkdir(mode=0o700)
        self.owns_guest_fixture = True
        upstream = json.loads((self.root / 'images/microvm/upstream.json').read_text())
        release = root / 'release.tgz'
        download(upstream['firecracker'], release)
        with tarfile.open(release, 'r:gz') as archive:
            for name in ['firecracker', 'jailer']:
                entries = [entry for entry in archive.getmembers()
                           if entry.name.split('/')[-1] == name + '-v1.18.0-x86_64']
                assert len(entries) == 1 and entries[0].isfile() and 0 < entries[0].size <= 64 * 1024**2
                with archive.extractfile(entries[0]) as source, (root / name).open('xb') as output:
                    shutil.copyfileobj(source, output, length=65536)
                    output.flush()
                    os.fsync(output.fileno())
                (root / name).chmod(0o500)
        download(upstream['kernel'], root / 'kernel')
        (root / 'kernel').chmod(0o400)
        for source, destination, mode in [(path, root / 'rootfs.ext4', 0o400),
                                          (self.args.binary.resolve(strict=True), root / 'goldenhoop-firecracker', 0o500)]:
            with source.open('rb') as input_file, destination.open('xb') as output:
                shutil.copyfileobj(input_file, output, length=65536)
                output.flush()
                os.fsync(output.fileno())
            destination.chmod(mode)
        boot = {name: artifact(root / name) for name in ['firecracker', 'jailer', 'kernel']}
        boot['rootfs'] = artifact(root / 'rootfs.ext4')
        reference = preparation['disk']
        assert boot['rootfs']['sha256'] == reference['sha256'] and boot['rootfs']['size'] == reference['size_bytes']
        self.report['observations']['prepared_guest_artifacts'] = boot
        self.report['observations']['guest_binary_sha256'] = digest(root / 'goldenhoop-firecracker')
        for name, value in [('boot.json', boot), ('corrupt.json', dict(boot, rootfs=dict(boot['rootfs'], sha256='0'*64)))]:
            with (root / name).open('x', encoding='utf-8') as output:
                output.write(json.dumps(value))
                output.flush()
                os.fsync(output.fileno())
            (root / name).chmod(0o400)
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        binary = root / 'goldenhoop-firecracker'
        refused, code, stderr = self.probe(binary, root / 'corrupt.json', 60)
        self.report['observations']['corrupt_prepared_disk_control'] = refused
        assert code == 2 and not stderr and not refused['passed'] and not refused['guest_started']
        assert refused['process'] is None and refused['error'] == 'artifact digest mismatch'
        self.report['cases'].append('corrupt_prepared_disk_digest_refused_before_VMM_launch_with_confirmed_collection')
        result, code, stderr = self.probe(binary, root / 'boot.json', 240)
        self.report['observations']['prepared_guest'] = result
        self.report['guest_started'] = result['guest_started']
        assert code == 0 and not stderr and result['passed'] and result['guest_started'], result.get('error')
        assert result['runtime_profile_published'] is False and len(result['checks']) >= 5
        self.report['cases'] += ['prepared_guest:' + check for check in result['checks']]
        # Native Rust copies an independent disk. Guest writes must not mutate
        # either the verified storage reconstruction or this pinned boot input.
        assert digest(path) == digest(root / 'rootfs.ext4') == reference['sha256']
        self.report['cases'].append('actual_guest_writes_leave_the_immutable_prepared_disk_unchanged')

    def cleanup(self):
        errors = []
        if self.owns_guest_fixture:
            try:
                assert self.guest_collected, 'retained prepared guest fixtures because VMM collection is unconfirmed'
                root = self.guest_fixture
                assert root.parent == Path('/var/lib') and re.fullmatch(r'ghip-[a-f0-9]{8}', root.name)
                metadata = root.lstat()
                assert stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0 and metadata.st_mode & 0o077 == 0
                names = {'release.tgz', 'firecracker', 'jailer', 'kernel', 'rootfs.ext4',
                         'goldenhoop-firecracker', 'boot.json', 'corrupt.json'}
                for child in root.iterdir():
                    metadata = child.lstat()
                    assert child.name in names and stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
                    assert metadata.st_nlink == 1
                    child.unlink()
                root.rmdir()
                assert not root.exists()
            except Exception as error:
                errors.append(str(error))
        self.report['prepared_guest_fixture_absent'] = not self.guest_fixture.exists()
        try:
            super().cleanup()
        except Exception as error:
            errors.append(str(error))
        if errors:
            raise AssertionError('; '.join(errors))


def main():
    parser = argparse.ArgumentParser()
    for option in ['image', 'image-owner', 'builder-image', 'builder-owner', 'source-base-image', 'source-base-owner', 'source-commit']:
        parser.add_argument('--' + option, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--remove-image', action='store_true')
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() != 'x86_64' or os.geteuid() != 0:
        parser.error('actual prepared-disk KVM verification requires a trusted Linux x86_64 root host')
    if not re.fullmatch('[a-f0-9]{40}', args.source_commit) or args.output.exists():
        parser.error('require a full immutable source SHA and a fresh output')
    args.runtime, args.allow_runc_development, args.recover_report = 'runsc', False, None
    return Contract(args).run()


if __name__ == '__main__':
    raise SystemExit(main())
