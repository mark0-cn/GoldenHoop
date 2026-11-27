"""Actual native RuntimeDriver/AgentTransport lifecycle; no public worker claim.

Only fixture construction and assertions live in Python. The Rust supervisor
owns VMM launch, resource enforcement, absolute expiry and physical collection.
"""
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import traceback
import uuid
from firecracker_manager_fixture import Manager


def suite(binary, boot, fixture, guest_barrier=False, guest_authority=False):
    installation = str(uuid.uuid4())
    root = fixture / 'd'  # Native AF_UNIX endpoints must fit Linux's path bound.
    cfg = {'installation_id': installation, 'data_root': str(root), 'artifacts': boot,
           'supervisor': {'path': str(binary), 'size': binary.stat().st_size,
                          'sha256': hashlib.file_digest(binary.open('rb'), 'sha256').hexdigest()},
           'image': 'sha256:' + boot['rootfs']['sha256'],
           'max_resources': {'cpu_millis': 2000, 'memory_bytes': 512 * 1024**2, 'pids': 256},
           'capacity': {'cpu_millis': 2000, 'memory_bytes': 2 * 1024**3, 'max_vms': 2},
           'max_ttl_seconds': 300}
    config = fixture / 'driver.json'
    config.write_text(json.dumps(cfg)); config.chmod(0o600)
    request_file = fixture / 'driver-request.json'
    canary = 'host-only-' + uuid.uuid4().hex
    env = dict(os.environ, GH_M4_HOST_CANARY=canary)
    report = {'result': 'failed', 'cleanup': 'unknown', 'cases': [], 'observations': {},
              'public_worker_registered': False, 'runtime_capabilities_verified': False}
    handles = {}
    foreign = None
    interrupted = None
    restore_record = None
    original_group = None
    manager = Manager(binary, config, cfg)

    def prepare_request(value):
        request_file.write_text(json.dumps(value)); request_file.chmod(0o600)
        return [str(binary), 'driver-call', '--config', str(config), '--request', str(request_file)]

    def call(value, expect=True, timeout=150, original_scope=None):
        def enter_scope():
            with (original_scope / 'cgroup.procs').open('w') as target:
                target.write('0')
        process = subprocess.run(prepare_request(value), capture_output=True, timeout=timeout, env=env,
                                 preexec_fn=enter_scope if original_scope else None)
        try:
            answer = json.loads(process.stdout)
        except Exception:
            raise AssertionError(f'native CLI did not return JSON: exit={process.returncode}, stderr={process.stderr.decode(errors="replace")[-2000:]}') from None
        assert answer['ok'] is expect, answer
        assert process.returncode == (0 if expect else 2), (process.returncode, answer)
        return answer['data'] if expect else answer['error']

    def record(id):
        return json.loads((root / 'records' / f'{id}.json').read_text())

    def generation_paths(value):
        generation = uuid.UUID(value['owner']['generation'])
        suffix = uuid.UUID(installation).hex + '-' + generation.hex
        return root / 'vm' / generation.hex[:12], Path('/sys/fs/cgroup') / f'ghv-{suffix}', Path('/sys/fs/cgroup') / f'ghs-{suffix}'

    def request(pids=32, ttl=240):
        now = datetime.datetime.now(datetime.timezone.utc)
        resources = {'cpu_millis': 500, 'memory_bytes': 256 * 1024**2, 'pids': pids}
        create = {'profile': 'local-firecracker', 'image': cfg['image'], 'resources': resources,
                  'ttl_seconds': ttl, 'required_capabilities': ['commands', 'files', 'pause', 'network_isolation']}
        sandbox = {'id': str(uuid.uuid4()), 'profile': create['profile'], 'image': cfg['image'],
                   'state': 'pending', 'desired_state': 'running', 'cleanup': 'pending',
                   'created_at': now.isoformat(), 'expires_at': (now + datetime.timedelta(seconds=ttl)).isoformat(),
                   'observed_at': None, 'resources': resources, 'metadata': {}, 'reason': None}
        return {'operation': 'create', 'sandbox': sandbox, 'request': create}

    def rpc(handle, value, expect_kind=None):
        answer = call({'operation': 'rpc', 'handle': handle, 'request': value})
        if expect_kind:
            assert answer['status'] == 'success' and answer['data']['kind'] == expect_kind, answer
            return answer['data'].get('value')
        return answer

    def command(handle, script):
        id = str(uuid.uuid4())
        spec = {'argv': ['python3', '-c', script], 'timeout_seconds': 15, 'max_output_bytes': 4096}
        assert rpc(handle, {'method': 'start', 'id': id, 'command': spec}, 'execution')['id'] == id
        until = time.monotonic() + 25
        while True:
            execution = rpc(handle, {'method': 'inspect', 'id': id}, 'execution')
            if execution['state'] in ['succeeded', 'failed', 'cancelled', 'timed_out']:
                break
            assert time.monotonic() < until, 'native guest command deadline'
            time.sleep(.05)
        events = rpc(handle, {'method': 'events', 'id': id, 'after': 0}, 'events')
        output = b''.join(base64.b64decode(event['data']['data'], validate=True)
                          for event in events if event['kind'] == 'stdout')
        assert execution['state'] == 'succeeded' and execution['exit_code'] == 0 and execution['cleanup'] == 'complete', (execution, events)
        return output.decode().strip()

    def remove(handle):
        call({'operation': 'remove', 'handle': handle})
        value = record(handle['sandbox_id'])
        assert value['phase'] == 'collected'
        assert all(not path.exists() for path in generation_paths(value))
        for identity in [value.get('process'), value.get('supervisor')]:
            if identity:
                proc = Path('/proc') / str(identity['pid'])
                assert not proc.exists(), f'owned process still present: {identity["pid"]}'
        handles.pop(handle['sandbox_id'], None)
        return value

    try:
        manager.start()
        observed = call({'operation': 'probe'}, timeout=220)
        assert observed['availability'] == 'available', observed
        assert set(observed['capabilities']) == {'commands', 'files', 'pause', 'network_isolation'}
        report['cases'].append('actual_trait_probe_requires_command_file_pause_resume_and_collection')

        a_request = request()
        a = call(a_request); handles[a['sandbox_id']] = a
        a_record = record(a['sandbox_id'])
        manager.assert_parent(a_record)
        assert call(a_request) == a
        assert call({'operation': 'inspect', 'handle': a})['state'] == 'running'
        assert a in call({'operation': 'discover'})
        report['cases'].append('durable_same_intent_reconnects_the_same_generation_without_relaunch')
        runtime, vm_group, sup_group = generation_paths(a_record)
        assert (vm_group / 'cpu.max').read_text().strip() == '50000 100000'
        assert (vm_group / 'memory.max').read_text().strip() == str(384 * 1024**2)
        assert (vm_group / 'pids.max').read_text().strip() == '64'
        assert (sup_group / 'pids.max').read_text().strip() == '8'
        supervisor_memory = {name: (sup_group / name).read_text() for name in
                             ['memory.max', 'memory.peak', 'memory.events.local', 'memory.stat', 'io.stat']}
        report['observations']['supervisor_preparation_memory'] = supervisor_memory
        assert int(supervisor_memory['memory.max'].strip()) == 128 * 1024**2
        assert int(supervisor_memory['memory.peak'].strip()) <= 128 * 1024**2
        events = dict(line.split() for line in supervisor_memory['memory.events.local'].splitlines())
        assert int(events['oom_kill']) == 0, supervisor_memory
        assert canary.encode() not in (Path('/proc') / str(a_record['supervisor']['pid']) / 'environ').read_bytes()
        nonce = uuid.uuid4().hex
        script = f"import os\ns=open('/proc/self/status').read()\nassert os.getuid()==os.getgid()==1000\nassert 'NoNewPrivs:\\t1' in s\nassert next(l.split(':',1)[1].strip() for l in s.splitlines() if l.startswith('CapEff:'))=='0000000000000000'\nassert open('/sys/fs/cgroup/goldenhoop/pids.max').read().strip()=='32'\nassert sorted(os.listdir('/sys/class/net'))==['lo']\nassert 'GH_M4_HOST_CANARY' not in os.environ\nprint({nonce!r},flush=True)"
        assert command(a, script) == nonce
        report['cases'].append('actual_per_sandbox_cpu_memory_pids_uid_and_clean_supervisor_environment')

        data = base64.b64encode(nonce.encode()).decode()
        rpc(a, {'method': 'write_file', 'path': 'durable.txt', 'data_base64': data}, 'ok')
        assert rpc(a, {'method': 'read_file', 'path': 'durable.txt', 'max_bytes': 128}, 'file')['data_base64'] == data
        call({'operation': 'pause', 'handle': a})
        assert call({'operation': 'inspect', 'handle': a})['state'] == 'paused'
        blocked = call({'operation': 'rpc', 'handle': a, 'request': {'method': 'ping'}}, expect=False)
        assert blocked['retryable'] is False
        call({'operation': 'resume', 'handle': a})
        assert rpc(a, {'method': 'read_file', 'path': 'durable.txt', 'max_bytes': 128}, 'file')['data_base64'] == data
        rpc(a, {'method': 'remove_file', 'path': 'durable.txt'}, 'ok')
        absent = rpc(a, {'method': 'read_file', 'path': 'durable.txt', 'max_bytes': 128})
        assert absent['status'] == 'error' and absent['data']['code'] == 'not_found'
        report['cases'].append('actual_pause_resume_and_file_absence_after_remove')

        if guest_barrier:
            from firecracker_barrier_contract import exercise
            exercise(a, a_record, runtime, call, rpc, command, report)

        forged = dict(a, backend_ref=f'fc1:{installation}:{uuid.uuid4()}')
        call({'operation': 'remove', 'handle': forged}, expect=False)
        assert call({'operation': 'inspect', 'handle': a})['state'] == 'running'
        foreign = subprocess.Popen(['sleep', '180'])
        path = root / 'records' / f'{a["sandbox_id"]}.json'
        saved = path.read_bytes(); restore_record = (path, saved)
        bad = json.loads(saved); bad['supervisor']['pid'] = foreign.pid
        path.write_text(json.dumps(bad))
        call({'operation': 'remove', 'handle': a}, expect=False)
        assert foreign.poll() is None, 'foreign PID was signaled'
        path.write_bytes(saved); restore_record = None
        assert call({'operation': 'inspect', 'handle': a})['state'] == 'running'
        report['cases'].append('foreign_generation_and_foreign_process_cannot_authorize_collection')

        b_request = request(pids=48)
        b = call(b_request); handles[b['sandbox_id']] = b
        assert command(b, "print(open('/sys/fs/cgroup/goldenhoop/pids.max').read().strip())") == '48'
        assert runtime != generation_paths(record(b['sandbox_id']))[0]
        assert (runtime / 'j/firecracker' / a_record['owner']['generation'] / 'root/rootfs.ext4').stat().st_ino != (generation_paths(record(b['sandbox_id']))[0] / 'j/firecracker' / record(b['sandbox_id'])['owner']['generation'] / 'root/rootfs.ext4').stat().st_ino
        rpc(a, {'method': 'write_file', 'path': 'private-a', 'data_base64': data}, 'ok')
        assert rpc(b, {'method': 'read_file', 'path': 'private-a', 'max_bytes': 128})['status'] == 'error'
        quota_request = request()
        denied = call(quota_request, expect=False)
        assert denied['code'] == 'quota_exceeded'
        assert not (root / 'records' / f'{quota_request["sandbox"]["id"]}.json').exists()
        assert call({'operation': 'inspect', 'handle': a})['state'] == 'running'
        report['cases'].append('independent_disks_and_dynamic_guest_limits_with_reserved_installation_capacity')
        remove(b)

        # Interrupt the caller while the independently owned Rust supervisor is
        # still copying the trusted disk, then reconnect to the same intent.
        c_request = request(pids=40)
        interrupted = subprocess.Popen(prepare_request(c_request), stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        until = time.monotonic() + 20
        while True:
            c_path = root / 'records' / f'{c_request["sandbox"]["id"]}.json'
            if c_path.exists():
                current = json.loads(c_path.read_text())
                if current.get('supervisor') and current['phase'] == 'preparing':
                    break
            assert interrupted.poll() is None and time.monotonic() < until, 'did not observe live durable preparation'
            time.sleep(.02)
        generation = current['owner']['generation']
        interrupted.kill(); interrupted.communicate(timeout=10); interrupted = None
        c = call(c_request); handles[c['sandbox_id']] = c
        assert record(c['sandbox_id'])['owner']['generation'] == generation
        assert command(c, "print('reconnected-after-caller-kill')") == 'reconnected-after-caller-kill'
        report['cases'].append('caller_SIGKILL_during_creation_recovers_same_live_supervisor_and_generation')
        remove(c)

        d_request = request(pids=64, ttl=75)
        original_group = Path('/sys/fs/cgroup') / ('gho-' + uuid.UUID(installation).hex)
        original_group.mkdir()
        d = call(d_request, original_scope=original_group); handles[d['sandbox_id']] = d
        d_record = record(d['sandbox_id'])
        assert d_record['original_cgroup'] == manager.owner['cgroup'], d_record['original_cgroup']
        assert 'populated 0' in (original_group / 'cgroup.events').read_text().splitlines(), 'original caller service group remains populated'
        original_group.rmdir()
        call({'operation': 'pause', 'handle': d})
        paused = call({'operation': 'inspect', 'handle': d})
        assert paused['state'] == 'paused', paused
        expiry = datetime.datetime.fromisoformat(d_record['owner']['expires_at'].replace('Z', '+00:00')).timestamp()
        samples = report['observations']['independent_expiry'] = []
        # Keep the original expiry+10s budget. Directory removal precedes the
        # persistent parent's actual wait; an unreaped zombie is not absence.
        deadline = time.monotonic() + max(0, expiry + 10 - time.time())
        manager.wait_collected(d_record, deadline, samples)
        call({'operation': 'rpc', 'handle': d, 'request': {'method': 'ping'}}, expect=False)
        remove(d)
        report['cases'].append('independent_absolute_expiry_collects_paused_VM_after_callers_and_caller_service_group_disappear')
        if guest_authority:
            from firecracker_authority_contract import exercise as authority_exercise
            authority_exercise(a, a_record, runtime, call, rpc, report)
        remove(a)
        call({'operation': 'remove', 'handle': a})
        assert record(a['sandbox_id'])['phase'] == 'collected'
        assert call({'operation': 'discover'}) == []
        report['cases'].append('idempotent_generation_collection_and_empty_owned_discovery')
        report['result'] = 'passed'
    except Exception as error:
        report['error'] = f'{type(error).__name__}: {error}'
        report['failure_site'] = [{'file': Path(frame.filename).name, 'line': frame.lineno,
                                   'function': frame.name} for frame in traceback.extract_tb(error.__traceback__)]
    finally:
        if restore_record:
            restore_record[0].write_bytes(restore_record[1])
        if interrupted and interrupted.poll() is None:
            interrupted.kill(); interrupted.communicate(timeout=10)
        if foreign:
            foreign.terminate(); foreign.wait(timeout=10)
        cleanup_errors = []
        if original_group and original_group.exists():
            try:
                assert 'populated 0' in (original_group / 'cgroup.events').read_text().splitlines()
                original_group.rmdir()
            except Exception as error:
                cleanup_errors.append(str(error))
        records = []
        if (root / 'records').exists():
            for path in sorted((root / 'records').glob('*.json')):
                try:
                    value = json.loads(path.read_text()); records.append(value)
                    value['live_resources_before_final_collection'] = manager.observe(value)
                    assert value['owner']['installation_id'] == installation
                    handle = {'sandbox_id': value['owner']['sandbox_id'], 'profile': 'local-firecracker',
                              'backend_ref': f'fc1:{installation}:{value["owner"]["generation"]}'}
                    if value['phase'] != 'collected' or any(p.exists() for p in generation_paths(value)):
                        remove(handle)
                    assert all(not p.exists() for p in generation_paths(value))
                except Exception as error:
                    cleanup_errors.append(str(error))
        try:
            stop_error = manager.close()
            if stop_error:
                report['manager_stop_error'] = stop_error
                report['result'] = 'failed'
        except Exception as error:
            cleanup_errors.append(str(error))
        report['observations']['manager'] = manager.diagnostics()
        report['observations']['records_before_final_collection'] = records
        report['observations']['config'] = cfg
        report['cleanup'] = 'complete' if not cleanup_errors else 'unknown'
        if cleanup_errors:
            report['cleanup_errors'] = cleanup_errors
            report['result'] = 'failed'
    return report
