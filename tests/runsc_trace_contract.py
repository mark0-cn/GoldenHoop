"""Retain bounded real runsc diagnostics from a disposable test runner."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import traceback


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
        report['trace_root_metadata'] = dict(uid=metadata.st_uid, mode=oct(stat.S_IMODE(metadata.st_mode)))
        assert stat.S_ISDIR(metadata.st_mode), 'trace root is not a real directory'
        claim = args.root / 'source-commit'
        metadata = claim.lstat()
        report['claim_metadata'] = dict(uid=metadata.st_uid, mode=oct(stat.S_IMODE(metadata.st_mode)),
                                        size_bytes=metadata.st_size, nlink=metadata.st_nlink)
        assert stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0 and metadata.st_nlink == 1, 'source claim owner/type/link count differs'
        assert 40 <= metadata.st_size <= 41, 'source claim size differs'
        assert claim.read_text().strip() == args.source_commit, 'source claim content differs'
        files = sorted(args.root.iterdir())
        assert len(files) <= 256, 'trace file count exceeds limit'
        report['file_inventory'] = []
        for path in files:
            metadata = path.lstat()
            report['file_inventory'].append(dict(name=path.name, uid=metadata.st_uid, mode=oct(stat.S_IMODE(metadata.st_mode)),
                                                 size_bytes=metadata.st_size, nlink=metadata.st_nlink))
        tail_budget, total = 2 * 1024**2, 0
        for path in files:
            if path == claim:
                continue
            assert re.fullmatch(r'trace\.[A-Za-z0-9_.%-]{1,240}\.log', path.name), 'unrecognized trace filename: ' + path.name
            metadata = path.lstat()
            assert stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1, 'trace is not a single-link regular file: ' + path.name
            assert metadata.st_size <= 32 * 1024**2, 'trace file size exceeds limit'
            total += metadata.st_size
            assert total <= 128 * 1024**2
            limit = min(65536 if path.name.endswith('.boot.log') else 1024, tail_budget)
            tail_budget -= limit
            whole, count, tail = hashlib.sha256(), 0, bytearray()
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as source:
                opened = os.fstat(source.fileno())
                assert stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1, 'opened trace type/link count differs'
                assert (opened.st_dev, opened.st_ino, opened.st_size) == (metadata.st_dev, metadata.st_ino, metadata.st_size), 'trace changed before read'
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
        assert primary['source_commit'] == args.source_commit and primary['cleanup'] == 'complete', 'primary compute collection is unconfirmed'
        # Diagnostics can be read without granting deletion authority. Preserve
        # all observations even when the stricter collection boundary refuses.
        metadata = args.root.lstat()
        assert metadata.st_uid == 0 and metadata.st_mode & 0o077 == 0, 'trace directory owner/private mode differs'
        assert all(item['uid'] == 0 for item in report['file_inventory']), 'trace file ownership differs; retain logs'
        for path in files:
            if path != claim:
                path.unlink()
        claim.unlink()
        args.root.rmdir()
        assert not args.root.exists()
        report['cleanup'] = 'complete'
    except Exception as error:
        report['error'] = f'{type(error).__name__}: {error}'
        report['failure_site'] = [{'file': Path(frame.filename).name, 'line': frame.lineno, 'function': frame.name}
                                  for frame in traceback.extract_tb(error.__traceback__)]
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
