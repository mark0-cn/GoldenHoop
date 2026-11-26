"""Actual 128MiB cgroup I/O regression; no KVM/runtime capability claim."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import uuid

BASE = 'debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc'


def docker(*args, timeout=60):
    result = subprocess.run(['docker', *args], capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'Docker {args[0]} failed: {result.stderr.decode(errors="replace")[-2000:]}')
    return result.stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-commit')
    args = parser.parse_args()
    if args.source_commit:
        assert re.fullmatch('[0-9a-f]{40}', args.source_commit)
    root = Path(__file__).resolve().parents[1]
    owner = uuid.uuid4().hex
    name, volume, image = 'gh-copy-' + owner, 'ghcv-' + owner, 'goldenhoop-copy:' + owner
    labels = {'dev.goldenhoop.task': 'm4-memory-copy', 'dev.goldenhoop.owner': owner}
    label_args = [part for key, value in labels.items() for part in ['--label', f'{key}={value}']]
    report = {'suite': 'actual-bounded-copy-fixture', 'source_commit': args.source_commit,
              'result': 'failed', 'cleanup': 'unknown', 'cases': [], 'owner': owner}
    context = Path(tempfile.mkdtemp(prefix='goldenhoop-copy-'))
    failure = None
    try:
        binary = context / 'copy-memory'
        shutil.copyfile(args.binary, binary)
        expected = hashlib.sha256(binary.read_bytes()).hexdigest()
        (context / 'Dockerfile').write_text(f'FROM {BASE}\nCOPY --chmod=0555 copy-memory /copy-memory\nENTRYPOINT ["/copy-memory"]\n', encoding='utf-8')
        docker('build', *label_args, '--tag', image, str(context), timeout=180)
        inspected = json.loads(docker('image', 'inspect', image))[0]
        assert all(inspected['Config']['Labels'].get(k) == v for k, v in labels.items())
        image_id = inspected['Id']
        docker('volume', 'create', *label_args, volume)
        cid = docker('create', '--name', name, *label_args, '--network', 'none', '--read-only',
                     '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                     '--memory', str(128 * 1024**2), '--memory-swap', str(128 * 1024**2),
                     '--cpus', '1', '--pids-limit', '32', '--mount', f'type=volume,src={volume},dst=/work,volume-nocopy', image_id).decode().strip()
        output = docker('start', '--attach', cid, timeout=240)
        state = json.loads(docker('inspect', cid))[0]
        report['process_state'] = state['State']
        assert state['State']['Status'] == 'exited' and state['State']['ExitCode'] == 0 and not state['State']['OOMKilled'], state['State']
        observed = json.loads(output)
        assert observed['result'] == 'passed' and observed['cleanup'] == 'complete'
        assert observed['observations']['binary_sha256'] == expected
        assert observed['observations']['memory_max_bytes'] == 128 * 1024**2
        assert observed['observations']['memory_peak_bytes'] <= 128 * 1024**2
        assert observed['observations']['size_bytes'] == 1024**3 + 17
        report['observations'] = observed['observations']
        report['image_id'] = image_id
        report['cases'] = ['actual128MiB_cgroup_limit', 'verified1GiB_sparse_copy', 'independent_destination_mutation', 'confirmed_empty_owned_volume']
        report['result'] = 'passed'
    except Exception as error:
        failure = error
        report['error'] = str(error)
    finally:
        errors = []
        try:
            found = docker('ps', '-aq', '--filter', f'label=dev.goldenhoop.owner={owner}').decode().splitlines()
            assert len(found) <= 1, found
            if found:
                found = found[0]
                value = json.loads(docker('inspect', found))[0]
                assert all(value['Config']['Labels'].get(k) == v for k, v in labels.items())
                assert value['Name'] == '/' + name
                if 'process_state' not in report:
                    report['process_state'] = value['State']
                    report['container_stderr_tail'] = subprocess.run(['docker', 'logs', '--tail', '20', found], capture_output=True).stderr.decode(errors='replace')[-4000:]
                docker('rm', '--force', found)
            assert not docker('ps', '-aq', '--filter', f'label=dev.goldenhoop.owner={owner}').strip()
            if volume in docker('volume', 'ls', '--quiet').decode().splitlines():
                value = json.loads(docker('volume', 'inspect', volume))[0]
                assert all(value['Labels'].get(k) == v for k, v in labels.items())
                docker('volume', 'rm', volume)
            assert volume not in docker('volume', 'ls', '--quiet').decode().splitlines()
            if docker('image', 'ls', '--quiet', '--filter', f'reference={image}').strip():
                value = json.loads(docker('image', 'inspect', image))[0]
                assert all(value['Config']['Labels'].get(k) == v for k, v in labels.items())
                docker('image', 'rm', image)
            assert not docker('image', 'ls', '--quiet', '--filter', f'reference={image}').strip()
        except Exception as error:
            errors.append(str(error))
        try:
            # This exact directory was created by mkdtemp in this invocation.
            assert context.resolve() == context.absolute()
            assert context.resolve().parent == Path(tempfile.gettempdir()).resolve()
            assert context.name.startswith('goldenhoop-copy-')
            shutil.rmtree(context)
            assert not context.exists()
        except Exception as error:
            errors.append(str(error))
        report['cleanup'] = 'complete' if not errors else 'unknown'
        if errors:
            report['result'] = 'failed'
            report['cleanup_errors'] = errors
        sources = [root / 'Cargo.toml', root / 'Cargo.lock', Path(__file__).resolve()]
        sources += sorted((root / 'crates/firecracker').rglob('*.rs')) + [root / 'crates/firecracker/Cargo.toml']
        report['source_files_sha256'] = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
        print(json.dumps({key: report[key] for key in ['result', 'cleanup', 'cases']}))
    if failure or errors:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
