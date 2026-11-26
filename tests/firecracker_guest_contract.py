"""Actual jailed KVM guest gate. Python prepares test fixtures, never a runtime.

The lifecycle, authentication, RPC and VMM collection under test are Rust. No
emulator/container execution can substitute for guest execution in this gate.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import time
import urllib.request
import uuid


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(65536), b''):
            result.update(block)
    return result.hexdigest()


def run(command, timeout=60, **kwargs):
    result = subprocess.run(command, timeout=timeout, capture_output=True, **kwargs)
    if result.returncode:
        raise AssertionError(f'{command[0]} failed ({result.returncode}): {result.stderr.decode(errors="replace")[-3000:]}')
    return result.stdout


def download(spec, destination):
    started = time.monotonic()
    with urllib.request.urlopen(spec['url'], timeout=30) as response, destination.open('xb') as output:
        total = 0
        while block := response.read(65536):
            total += len(block)
            assert total <= 128 * 1024 * 1024, 'upstream fixture exceeds limit'
            assert time.monotonic() - started < 180, 'upstream download deadline'
            output.write(block)
    assert digest(destination) == spec['sha256'], 'upstream fixture digest mismatch'
    if 'size' in spec:
        assert destination.stat().st_size == spec['size'], 'upstream fixture length mismatch'


def artifact(path):
    return {'path': str(path), 'sha256': digest(path), 'size': path.stat().st_size}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--owner', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--driver-contract', action='store_true')
    parser.add_argument('--public-contract', action='store_true')
    parser.add_argument('--control', type=Path)
    parser.add_argument('--cli', type=Path)
    args = parser.parse_args()
    if args.public_contract and (not args.driver_contract or not args.control or not args.cli):
        parser.error('public contract requires --driver-contract, --control and --cli')
    assert re.fullmatch(r'[0-9a-f]{40}', args.source_commit)
    assert re.fullmatch(r'[0-9]+-[0-9]+', args.owner)
    root = Path(__file__).resolve().parent.parent
    sources = [root / 'Cargo.toml', root / 'Cargo.lock', Path(__file__).resolve(),
               root / '.github/workflows/firecracker-guest.yml', root / 'images/agent/Dockerfile']
    if args.driver_contract:
        sources += [root / 'tests/firecracker_driver_contract.py', root / 'tests/firecracker_manager_fixture.py', root / '.github/workflows/firecracker-driver.yml']
    for crate in ['firecracker', 'guest-init', 'agent', 'protocol', 'runtime']:
        sources += sorted((root / f'crates/{crate}').rglob('*.rs'))
        sources.append(root / f'crates/{crate}/Cargo.toml')
    if args.public_contract:
        sources += [root / 'tests/firecracker_public_contract.py', root / '.github/workflows/firecracker-public.yml']
        sources += sorted((root / 'crates').rglob('*.rs')) + sorted((root / 'crates').rglob('Cargo.toml'))
        sources += sorted((root / 'sdk/python').rglob('*.py')) + [root / 'sdk/python/pyproject.toml']
    sources += sorted((root / 'images/microvm').glob('*.json'))
    report = {
        'suite': 'actual jailed Firecracker guest bootstrap',
        'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'source_commit': args.source_commit,
        'source_files_sha256': {p.relative_to(root).as_posix(): digest(p) for p in sources},
        'host': {'system': platform.system(), 'architecture': platform.machine(),
                 'kernel': platform.release(), 'uid': os.geteuid()},
        'result': 'failed', 'cleanup': 'unknown', 'cases': [],
        'guest_started': False, 'runtime_capabilities_verified': False,
        'scope': 'private real guest bootstrap only; public lifecycle, expiry, recovery, snapshots and templates remain unaccepted',
    }
    fixture = Path('/var/lib') / f'ghf-{uuid.uuid4().hex[:8]}'
    container = None
    image_id = None
    owns_fixture = False
    guest_collected = True
    try:
        assert platform.system() == 'Linux' and platform.machine() == 'x86_64' and os.geteuid() == 0
        fixture.mkdir(mode=0o700)
        owns_fixture = True
        upstream = json.loads((root / 'images/microvm/upstream.json').read_text())
        release = fixture / 'firecracker.tgz'
        download(upstream['firecracker'], release)
        with tarfile.open(release, 'r:gz') as archive:
            for binary in ['firecracker', 'jailer']:
                entries = [entry for entry in archive.getmembers()
                           if entry.name.split('/')[-1] == f'{binary}-v1.18.0-x86_64']
                assert len(entries) == 1 and entries[0].isfile() and 0 < entries[0].size <= 64 * 1024 * 1024
                with archive.extractfile(entries[0]) as source, (fixture / binary).open('xb') as output:
                    shutil.copyfileobj(source, output, length=65536)
                (fixture / binary).chmod(0o500)
        kernel = fixture / 'kernel'
        download(upstream['kernel'], kernel)
        kernel.chmod(0o400)
        image = json.loads(run(['docker', 'image', 'inspect', args.image]))[0]
        assert image['Config']['Labels'].get('dev.goldenhoop.run') == args.owner
        assert image['Config']['Labels'].get('dev.goldenhoop.task') == 'm4-guest'
        assert image['Config']['Labels'].get('dev.goldenhoop.microvm') == 'rootfs'
        image_id = image['Id']
        report['image'] = {'id': image_id, 'owner': args.owner, 'guest_container_started': False}
        container = run(['docker', 'create', '--network', 'none', '--label', 'dev.goldenhoop.task=m4-guest-export',
                         '--label', f'dev.goldenhoop.run={args.owner}', image_id]).decode().strip()
        exported = fixture / 'rootfs.tar'
        with exported.open('xb') as output:
            subprocess.run(['docker', 'export', container], stdout=output, stderr=subprocess.PIPE,
                           check=True, timeout=60)
        contents = fixture / 'rootfs'
        contents.mkdir()
        run(['tar', '-xf', str(exported), '-C', str(contents)])
        report['guest_binaries'] = {name: artifact(contents / path) for name, path in [
            ('agent', 'usr/local/bin/goldenhoop-agent'), ('init', 'sbin/goldenhoop-init')]}
        disk = fixture / 'rootfs.ext4'
        # Offline ext4 construction: no filesystem is mounted on the host.
        run(['mkfs.ext4', '-q', '-F', '-b', '4096', '-d', str(contents), str(disk), '262144'], timeout=120)
        disk.chmod(0o400)
        binary = fixture / 'goldenhoop-firecracker'
        shutil.copyfile(args.binary.resolve(strict=True), binary)
        binary.chmod(0o500)
        report['binary_sha256'] = digest(binary)
        boot = {name: artifact(fixture / path) for name, path in [
            ('firecracker', 'firecracker'), ('jailer', 'jailer'), ('kernel', 'kernel'), ('rootfs', 'rootfs.ext4')]}
        report['artifacts'] = boot
        config = fixture / 'boot.json'
        config.write_text(json.dumps(boot), encoding='utf-8')
        config.chmod(0o400)
        corrupt = json.loads(json.dumps(boot))
        corrupt['kernel']['sha256'] = '0' * 64
        refused_config = fixture / 'refused.json'
        refused_config.write_text(json.dumps(corrupt), encoding='utf-8')
        refused_config.chmod(0o400)
        guest_collected = False
        refused_process = subprocess.run([str(binary), 'probe-guest', '--config', str(refused_config)],
                                         capture_output=True, timeout=60)
        refused = json.loads(refused_process.stdout)
        report['corrupt_artifact_control'] = refused
        guest_collected = (refused['cleanup'] == 'complete' and refused['root_absent'] and
                           refused['cgroup_absent'] and refused['vmm_reaped'])
        assert guest_collected, 'corrupt artifact failure-path collection unconfirmed'
        assert refused_process.returncode == 2 and not refused['passed'] and not refused['guest_started']
        assert refused['process'] is None and refused['error'] == 'artifact digest mismatch'
        refused_suffix = f'ghv-{uuid.UUID(refused["generation"]).hex[:8]}'
        assert not (Path('/var/lib') / refused_suffix).exists()
        assert not (Path('/sys/fs/cgroup') / refused_suffix).exists()
        guest_collected = False
        started = time.monotonic()
        process = subprocess.Popen([str(binary), 'probe-guest', '--config', str(config)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, stderr = process.communicate(timeout=240)
        except subprocess.TimeoutExpired:
            # Rust handles TERM by fencing and collecting its owned generation.
            process.terminate()
            stdout, stderr = process.communicate(timeout=45)
            report['watchdog_terminated_operation'] = True
        report['duration_milliseconds'] = round((time.monotonic() - started) * 1000)
        report['exit_code'] = process.returncode
        report['stderr'] = stderr.decode(errors='replace')[-3000:]
        report['probe'] = json.loads(stdout)
        probe = report['probe']
        report['guest_started'] = probe['guest_started']
        guest_collected = (probe['cleanup'] == 'complete' and probe['root_absent'] and
                           probe['cgroup_absent'] and probe['vmm_reaped'])
        assert guest_collected, 'actual Rust VMM/jail/cgroup collection unconfirmed'
        generation = uuid.UUID(probe['generation'])
        suffix = f'ghv-{generation.hex[:8]}'
        assert not (Path('/var/lib') / suffix).exists(), 'owned VM root still exists'
        assert not (Path('/sys/fs/cgroup') / suffix).exists(), 'owned VM cgroup still exists'
        assert probe['runtime_profile_published'] is False
        assert not stderr and process.returncode == 0 and probe['passed'], probe.get('error')
        assert probe['guest_started'] and len(probe['checks']) >= 5
        report['cases'] = ['corrupt_kernel_digest_refused_before_launch_with_confirmed_collection'] + probe['checks']
        report['result'] = 'passed'
        if args.driver_contract:
            from firecracker_driver_contract import suite
            report['scope'] = 'actual native RuntimeDriver/AgentTransport lifecycle; public Worker/SDK integration and full M4 remain unaccepted'
            guest_collected = False
            driver = suite(binary, boot, fixture)
            report['driver'] = driver
            guest_collected = driver['cleanup'] == 'complete'
            report['cases'] += ['driver:' + case for case in driver['cases']]
            assert driver['result'] == 'passed' and guest_collected, driver.get('error', 'native driver collection unconfirmed')
        if args.public_contract:
            from firecracker_public_contract import suite as public_suite
            tools = []
            for source, name in [(args.control, 'goldenhoopd'), (args.cli, 'goldenhoop')]:
                target = fixture / name
                shutil.copyfile(source.resolve(strict=True), target); target.chmod(0o500)
                tools.append(target)
            report['public_binaries_sha256'] = {tool.name: digest(tool) for tool in tools}
            guest_collected = False
            public = public_suite(*tools, binary, boot, fixture)
            report['public'] = public
            guest_collected = public['cleanup'] == 'complete'
            report['cases'] += ['public:' + case for case in public['cases']]
            report['scope'] = 'actual basic native public API/SDK/CLI lifecycle; snapshots/templates and full M4 remain unaccepted'
            assert public['result'] == 'passed' and guest_collected, public.get('error', 'native public collection unconfirmed')
            report['runtime_capabilities_verified'] = True
    except Exception as error:
        report['result'] = 'failed'
        report['error'] = str(error)
    finally:
        cleanup_errors = []
        if container:
            try:
                inspected = json.loads(run(['docker', 'inspect', container]))[0]
                assert inspected['Config']['Labels'].get('dev.goldenhoop.run') == args.owner
                assert inspected['Config']['Labels'].get('dev.goldenhoop.task') == 'm4-guest-export'
                assert inspected['State']['Status'] == 'created', 'export fixture was unexpectedly executed'
                run(['docker', 'rm', container])
                assert not run(['docker', 'ps', '-aq', '--filter', f'id={container}']).strip()
            except Exception as error:
                cleanup_errors.append(str(error))
        if owns_fixture and guest_collected:
            try:
                assert fixture.parent == Path('/var/lib') and re.fullmatch(r'ghf-[0-9a-f]{8}', fixture.name)
                assert fixture.lstat().st_uid == 0 and fixture.lstat().st_mode & 0o077 == 0
                shutil.rmtree(fixture)
                assert not fixture.exists()
            except Exception as error:
                cleanup_errors.append(str(error))
        elif owns_fixture:
            cleanup_errors.append('retained owned fixtures because VMM collection is unconfirmed')
        report['fixture_absent'] = not fixture.exists()
        try:
            report['export_container_absent'] = not container or not run(['docker', 'ps', '-aq', '--filter', f'id={container}']).strip()
        except Exception as error:
            report['export_container_absent'] = None
            cleanup_errors.append(str(error))
        report['cleanup'] = 'complete' if not cleanup_errors and guest_collected else 'unknown'
        if cleanup_errors:
            report['cleanup_errors'] = cleanup_errors
            report['result'] = 'failed'
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps({key: report[key] for key in ['result', 'cleanup', 'guest_started', 'runtime_capabilities_verified']}))
    return 0 if report['result'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
