"""Actual KVM prerequisite gate; never substitutes for jailed guest acceptance."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{40}', args.source_commit):
        parser.error('source commit must be the immutable job commit')
    root = Path(__file__).resolve().parent.parent
    sources = [root / 'Cargo.toml', root / 'Cargo.lock', Path(__file__).resolve(),
               root / '.github/workflows/firecracker-prerequisites.yml']
    sources += sorted((root / 'crates/firecracker').rglob('*.rs'))
    sources += [root / 'crates/firecracker/Cargo.toml']
    sources += sorted((root / 'crates/protocol/src').rglob('*.rs'))
    report = {
        'suite': 'actual KVM device and empty-VM descriptor prerequisites',
        'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'source_commit': args.source_commit,
        'source_files_sha256': {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
        'host': {'system': platform.system(), 'architecture': platform.machine(),
                 'kernel': platform.release(), 'uid': os.geteuid() if hasattr(os, 'geteuid') else None},
        'result': 'failed', 'cleanup': 'complete', 'process_reaped': False, 'cases': [],
        'guest_started': False, 'runtime_capabilities_verified': False,
        'scope': 'KVM device/ioctl prerequisite only; jailed boot, guest commands/files, expiry, recovery and snapshots remain unverified',
    }
    try:
        assert report['host']['system'] == 'Linux' and report['host']['architecture'] == 'x86_64', 'requires Linux x86_64'
        assert report['host']['uid'] == 0, 'requires the same root access as the planned jailer worker'
        binary = args.binary.resolve(strict=True)
        assert binary.is_file(), 'missing built Rust probe'
        report['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
        started = time.monotonic()
        try:
            process = subprocess.run([str(binary), 'probe-kvm'], capture_output=True, timeout=10)
        except subprocess.TimeoutExpired:
            # subprocess.run kills and reaps its child before raising. This
            # trusted probe has no forks, guest RAM or persistent resources.
            report['process_reaped'] = True
            raise AssertionError('bounded Rust KVM probe timed out') from None
        report['process_reaped'] = True
        report['duration_milliseconds'] = round((time.monotonic() - started) * 1000)
        report['exit_code'] = process.returncode
        report['stdout_sha256'] = hashlib.sha256(process.stdout).hexdigest()
        report['stderr_sha256'] = hashlib.sha256(process.stderr).hexdigest()
        report['probe'] = json.loads(process.stdout)
        assert not process.stderr, 'unexpected Rust probe diagnostic'
        assert process.returncode == 0 and report['probe']['state'] == 'ready', 'actual host refuses KVM prerequisites'
        assert report['probe']['api_version'] == 12, 'unsupported actual KVM API'
        assert report['probe']['error_errno'] is None, 'unexpected KVM query or creation errno'
        assert report['probe']['runtime_capabilities_verified'] is False, 'a prerequisite must not publish runtime support'
        report['cases'] = ['actual_KVM_API_12_on_the_fixed_character_device',
                           'actual_empty_VM_descriptor_created_and_collected_without_runtime_capability_publication']
        report['result'] = 'passed'
    except Exception as error:
        report['error'] = str(error)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps({k: report[k] for k in ('result', 'cleanup', 'guest_started', 'runtime_capabilities_verified')}))
    return 0 if report['result'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
