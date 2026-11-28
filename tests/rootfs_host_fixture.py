"""Trusted Linux test parent only; never mounted into the inspected workload.

The production rootfs parent is not implemented by this fixture. For the runsc
component gate it reads physical host cgroups before handing over private stdin.
"""
from pathlib import Path
import os
import re


def ticks(pid):
    value = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    assert len(value) >= 20 and value[0] not in {'Z', 'X', 'x'}
    return int(value[19])


def observe(cid, pid):
    start = ticks(pid)
    placement = Path(f'/proc/{pid}/cgroup').read_text().splitlines()
    assert len(placement) == 1 and placement[0].startswith('0::/')
    relative = placement[0][3:]
    parts = relative[1:].split('/')
    assert 0 < len(parts) <= 32 and all(re.fullmatch(r'[A-Za-z0-9_.-]+', p) and p not in {'.', '..'} for p in parts)
    owned = [i for i, p in enumerate(parts) if p in {cid, 'docker-'+cid, 'docker-'+cid+'.scope'}]
    assert len(owned) == 1
    finite = {'memory.max': [], 'memory.swap.max': [], 'pids.max': [], 'cpu.max': []}
    observations = []
    directory = Path('/sys/fs/cgroup')
    for part in parts:
        directory /= part
        metadata = directory.lstat()
        assert directory.is_dir() and not directory.is_symlink() and metadata.st_uid == 0 and not metadata.st_mode & 0o022
        record = {'path': str(directory)}
        for name in finite:
            path = directory/name
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            except FileNotFoundError:
                continue
            try:
                metadata = os.fstat(fd)
                assert metadata.st_uid == 0 and not metadata.st_mode & 0o022
                value = os.read(fd, 4097).decode('ascii').strip()
                assert len(value) <= 4096
            finally:
                os.close(fd)
            record[name] = value
            fields = value.split()
            if name == 'cpu.max':
                assert len(fields) == 2 and int(fields[1]) > 0
                if fields[0] != 'max':
                    finite[name].append((int(fields[0]), int(fields[1])))
            elif value != 'max':
                finite[name].append(int(value))
        observations.append(record)
    assert all(finite.values()), observations
    from fractions import Fraction
    quota, period = min(finite['cpu.max'], key=lambda value: Fraction(*value))
    limits = dict(memory_max=min(finite['memory.max']), swap_max=min(finite['memory.swap.max']),
                  pids_max=min(finite['pids.max']), cpu_quota=quota, cpu_period=period)
    assert 0 < limits['memory_max'] <= 1024**3 and limits['swap_max'] == 0
    assert 16 <= limits['pids_max'] <= 64 and 0 < quota <= period
    assert ticks(pid) == start
    return dict(pid=pid, start_ticks=start, process_cgroup=relative,
                owned_cgroup='/sys/fs/cgroup/'+('/'.join(parts[:owned[0]+1])), limits=limits, observations=observations)


def absent(observation):
    try:
        original_gone = ticks(observation['pid']) != observation['start_ticks']
    except FileNotFoundError:
        original_gone = True
    except AssertionError:
        return False
    return original_gone and not Path(observation['owned_cgroup']).exists()
