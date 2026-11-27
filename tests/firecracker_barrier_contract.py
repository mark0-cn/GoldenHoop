"""Observe the actual PID1 barrier on an already owned jailed KVM generation.

The fixture reads its own disk with read-only debugfs; it never mounts it.
Snapshot creation, host restore coordination and public snapshot capabilities are absent.
"""
import base64
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import threading
import time
import uuid


@contextmanager
def guest_channel(record, runtime):
    endpoint = runtime/'j/firecracker'/record['owner']['generation']/'root/vsock.sock'
    metadata = endpoint.lstat()
    assert stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == record['process']['uid']
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(40);stream.connect(str(endpoint))
        pid, uid, gid = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        assert pid == record['process']['pid'] and uid == gid == record['process']['uid']
        fields = (Path('/proc')/str(pid)/'stat').read_text().rsplit(')', 1)[1].split()
        assert int(fields[19]) == record['process']['start_ticks']
        with stream.makefile('rb') as source:
            stream.sendall(b'CONNECT 52\n')
            assert re.fullmatch(rb'OK [0-9]+\n', source.readline(64))
            yield stream, source


def guest_frame(record, request, generation=None, bind=True):
    if bind and 'guest_control' not in request:
        request = {'guest_rpc': {'generation': generation or record['owner']['generation'], 'request': request}}
    return json.dumps(request, separators=(',', ':')).encode()+b'\n'


def guest_reply(source):
    data = source.readline(24*1024**2+1)
    if not data:
        raise ConnectionError('guest closed this private request without an acknowledgement')
    assert data.endswith(b'\n') and len(data) <= 24*1024**2
    return json.loads(data)


def guest_exchange(record, runtime, request, generation=None, bind=True):
    with guest_channel(record, runtime) as (stream, source):
        stream.sendall(guest_frame(record, request, generation, bind))
        return guest_reply(source)


def exercise(handle, record, runtime, call, rpc, command, report):
    generation = record['owner']['generation']
    jail = runtime/'j/firecracker'/generation/'root'
    disk = jail/'rootfs.ext4'
    observations = report['observations']['guest_barrier'] = {'generation': generation}

    def exchange(request):
        return guest_exchange(record, runtime, request)

    def control(kind, barrier, identity=generation):
        return exchange({'guest_control': kind, 'generation': identity, 'barrier': barrier})

    def closed(request):
        try: exchange(request)
        except ConnectionError: return
        raise AssertionError('invalid barrier authority received an acknowledgement')

    def disk_read(name, missing=False):
        assert re.fullmatch(r'[a-z0-9-]+', name)
        metadata = disk.lstat()
        assert stat.S_ISREG(metadata.st_mode) and metadata.st_uid == record['process']['uid']
        result = subprocess.run(['debugfs', '-R', 'cat /workspace/'+name, str(disk)],
                                capture_output=True, timeout=30, check=True)
        error = result.stderr.decode(errors='replace')
        if missing:
            assert not result.stdout and 'File not found' in error, error
        else:
            assert 'File not found' not in error, error
        assert len(result.stdout) <= 4*1024**2
        return result.stdout

    group = json.loads(command(handle,
        "import json;from pathlib import Path;print(json.dumps({"
        "'membership':Path('/proc/self/cgroup').read_text().strip(),"
        "'control':Path('/sys/fs/cgroup/goldenhoop/control/cgroup.procs').read_text().split(),"
        "'parent':Path('/sys/fs/cgroup/goldenhoop/cgroup.procs').read_text().strip(),"
        "'limit':Path('/sys/fs/cgroup/goldenhoop/pids.max').read_text().strip()}))"))
    assert group['membership'] == '0::/goldenhoop/workloads'
    assert group['control'] == ['1'] and not group['parent']
    assert group['limit'] == str(record['resources']['pids'])
    observations['actual_guest_groups'] = group
    report['cases'].append('guest_control_and_workloads_are_distinct_children_under_the_actual_aggregate_task_ceiling')

    barrier = str(uuid.uuid4())
    for identity, token in [(str(uuid.uuid4()), barrier), (generation, str(uuid.UUID(int=0)))]:
        closed({'guest_control': 'quiesce', 'generation': identity, 'barrier': token})
    assert rpc(handle, {'method': 'ping'})['status'] == 'success'
    report['cases'].append('wrong_generation_and_nil_barrier_close_without_acknowledgement_and_preserve_original_guest_health')

    ticks, race = 'barrier-ticks-'+uuid.uuid4().hex, 'barrier-race-'+uuid.uuid4().hex
    execution = str(uuid.uuid4())
    script = ("import os,time;from pathlib import Path;"
              f"p=Path({ticks!r});q=Path({(ticks+'-pending')!r})\n"
              "for i in range(10000):\n"
              " with q.open('w') as f: f.write(str(i));f.flush();os.fsync(f.fileno())\n"
              " os.replace(q,p);time.sleep(.01)\n")
    started = rpc(handle, {'method': 'start', 'id': execution, 'command': {
        'argv': ['python3', '-c', script], 'timeout_seconds': 120, 'max_output_bytes': 128}}, 'execution')
    assert started['id'] == execution
    until = time.monotonic()+15
    while True:
        answer = rpc(handle, {'method': 'read_file', 'path': ticks, 'max_bytes': 128})
        if answer['status'] == 'success':
            assert base64.b64decode(answer['data']['value']['data_base64'], validate=True).isdigit()
            break
        assert answer['data']['code'] == 'not_found' and time.monotonic() < until, answer
        time.sleep(.02)
    assert rpc(handle, {'method': 'inspect', 'id': execution}, 'execution')['state'] == 'running'
    payload = b'a'*(4*1024**2)
    rendezvous = threading.Barrier(3)
    def capture():
        rendezvous.wait(timeout=5);return control('quiesce', barrier)
    def write():
        rendezvous.wait(timeout=5)
        return exchange({'method': 'write_file', 'path': race, 'data_base64': base64.b64encode(payload).decode()})
    with ThreadPoolExecutor(max_workers=2) as pool:
        capture_result, write_result = pool.submit(capture), pool.submit(write)
        rendezvous.wait(timeout=5)
        receipt, writer = capture_result.result(timeout=50), write_result.result(timeout=50)
    assert receipt == {'protocol': 3, 'generation': generation, 'barrier': barrier,
                       'phase': 'quiesced', 'workload_frozen': True, 'rootfs_synced': True}, receipt
    if writer['status'] == 'success':
        assert writer['data']['kind'] == 'ok' and disk_read(race) == payload
        observations['concurrent_writer'] = 'completed before barrier; entire physical disk file verified'
    else:
        assert writer['data']['code'] == 'invalid_state', writer
        disk_read(race, missing=True)
        observations['concurrent_writer'] = 'refused by closed admission; physical disk path absent'
    observations['receipt'] = receipt
    observations['concurrent_payload_sha256'] = hashlib.sha256(payload).hexdigest()
    report['cases'].append('actual_concurrent_host_write_finishes_before_ack_or_is_refused_with_matching_physical_disk_observation')

    tick = disk_read(ticks);assert tick.isdigit()
    for _ in range(3):
        time.sleep(.15);assert disk_read(ticks) == tick
        assert control('barrier_status', barrier) == receipt
        assert exchange({'guest_control': 'info'})['generation'] == generation
    assert control('quiesce', barrier) == receipt
    for request in [{'method': 'write_file', 'path': race+'-after', 'data_base64': 'YQ=='},
                    {'method': 'start', 'id': str(uuid.uuid4()), 'command': {'argv': ['true']}}]:
        refused = rpc(handle, request)
        assert refused['status'] == 'error' and refused['data']['code'] == 'invalid_state', refused
    disk_read(race+'-after', missing=True)
    observations['stable_physical_counter'] = tick.decode()
    report['cases'].append('actual_running_command_stops_mutating_synced_disk_while_PID1_remains_reachable_and_new_dispatch_is_refused')

    call({'operation': 'pause', 'handle': handle})
    assert call({'operation': 'inspect', 'handle': handle})['state'] == 'paused'
    call({'operation': 'resume', 'handle': handle})
    assert control('barrier_status', barrier) == receipt
    closed({'guest_control': 'thaw', 'generation': generation, 'barrier': str(uuid.uuid4())})
    assert control('barrier_status', barrier) == receipt
    resumed = control('thaw', barrier)
    assert resumed == dict(receipt, phase='resumed', workload_frozen=False, rootfs_synced=False)
    assert control('thaw', barrier) == resumed
    closed({'guest_control': 'quiesce', 'generation': generation, 'barrier': barrier})
    assert control('barrier_status', barrier) == resumed
    until = time.monotonic()+10
    while True:
        current = rpc(handle, {'method': 'read_file', 'path': ticks, 'max_bytes': 128}, 'file')
        value = base64.b64decode(current['data_base64'], validate=True)
        if value.isdigit() and int(value) > int(tick): break
        assert time.monotonic() < until
        time.sleep(.02)
    rpc(handle, {'method': 'cancel', 'id': execution}, 'execution')
    until = time.monotonic()+20
    while True:
        stopped = rpc(handle, {'method': 'inspect', 'id': execution}, 'execution')
        if stopped['state'] == 'cancelled' and stopped['cleanup'] == 'complete': break
        assert time.monotonic() < until, stopped
        time.sleep(.05)
    observations['same_execution_after_thaw'] = stopped
    report['cases'].append('same_barrier_survives_real_VMM_pause_resume_and_explicit_thaw_resumes_the_original_command_without_reusing_spent_authority')
