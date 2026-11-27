"""Retain bounded real runsc diagnostics from a disposable test runner."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--primary-report', type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and re.fullmatch('[a-f0-9]{40}', args.source_commit)
    assert args.root.parent == Path('/var/lib') and re.fullmatch(r'gh-runsc-[0-9]+-[0-9]+', args.root.name)
    assert not args.output.exists()
    repository = Path(__file__).resolve().parents[1]
    sources = [Path(__file__).resolve(), repository / '.github/workflows/image-prepare.yml']
    report = dict(suite='actual-runsc-file-syscall-diagnostics', source_commit=args.source_commit,
                  source_files_sha256={p.relative_to(repository).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
                  scope='diagnostic only; no conversion or KVM capability acceptance',
                  result='diagnostic', cleanup='unknown', cases=[], logs=[])
    try:
        metadata = args.root.lstat()
        assert stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0 and metadata.st_mode & 0o077 == 0
        claim = args.root / 'source-commit'
        metadata = claim.lstat()
        assert stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0 and metadata.st_nlink == 1
        assert claim.read_text().strip() == args.source_commit
        files = sorted(args.root.iterdir())
        assert len(files) <= 256
        tail_budget, total = 2 * 1024**2, 0
        for path in files:
            if path == claim:
                continue
            assert re.fullmatch(r'trace\.[A-Za-z0-9_.-]{1,240}\.log', path.name)
            metadata = path.lstat()
            assert stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0 and metadata.st_nlink == 1
            assert metadata.st_size <= 32 * 1024**2
            total += metadata.st_size
            assert total <= 128 * 1024**2
            limit = min(65536 if path.name.endswith('.boot.log') else 1024, tail_budget)
            tail_budget -= limit
            whole, count, tail = hashlib.sha256(), 0, bytearray()
            with path.open('rb') as source:
                for block in iter(lambda: source.read(65536), b''):
                    count += len(block)
                    assert count <= metadata.st_size
                    whole.update(block)
                    if limit:
                        tail.extend(block)
                        if len(tail) > limit:
                            del tail[:-limit]
            assert count == metadata.st_size
            report['logs'].append(dict(name=path.name, size_bytes=count, sha256=whole.hexdigest(),
                                       tail=tail.decode(errors='replace'), tail_truncated=count > limit))
        # Never unlink a log that may still have an unfenced sandbox writer.
        primary = json.loads(args.primary_report.read_text())
        assert primary['source_commit'] == args.source_commit and primary['cleanup'] == 'complete'
        for path in files:
            path.unlink()
        args.root.rmdir()
        assert not args.root.exists()
        report['cleanup'] = 'complete'
    except Exception as error:
        report['error'] = f'{type(error).__name__}: {error}'
    report['trace_root_absent'] = not args.root.exists()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8', newline='\n') as output:
        output.write(json.dumps(report, indent=2) + '\n')
        output.flush()
        os.fsync(output.fileno())
    print(json.dumps({key: report[key] for key in ['suite', 'result', 'cleanup', 'trace_root_absent']}))
    return 0 if report['cleanup'] == 'complete' else 1


if __name__ == '__main__':
    raise SystemExit(main())
