"""Real API/Python SDK/Rust CLI against the opt-in native-only Rust worker."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import traceback
import uuid

import httpx
from goldenhoop import ApiError, Client, Command, CreateArtifact
from firecracker_manager_fixture import Manager


def recovery_program(nonce, workspace='/workspace'):
    return ("from pathlib import Path; import time; "
            f"root=Path({workspace!r}); "
            f"(root/{('ready-' + nonce)!r}).write_text('ready'); "
            f"release=root/{('release-' + nonce)!r}\n"
            "while not release.exists(): time.sleep(.05)\n"
            "with (root/'once').open('a') as output: output.write('once')\n"
            "print('once',end='')")


def suite(control, cli, native, boot, fixture, manager_recovery=False):
    report = {'result': 'failed', 'cleanup': 'unknown', 'cases': [], 'observations': {},
              'scope': 'basic native public lifecycle only; full M4 remains unaccepted'}
    database = fixture / 'public.db'
    token = uuid.uuid4().hex + uuid.uuid4().hex
    env = dict(os.environ, GOLDENHOOP_API_TOKEN=token,
               DOCKER_HOST='unix:///var/empty/goldenhoop-no-docker.sock')
    logs = {name: fixture / f'public-{name}.log' for name in ['api', 'worker']}
    processes = {}
    client = None
    config = fixture / 'public-native.json'
    root = fixture / 'p'
    endpoint = None
    installation = None
    sandboxes = []
    artifact_id = None
    manager = None

    def event_lines(name, event):
        values = []
        if logs[name].exists():
            for line in logs[name].read_text(errors='replace').splitlines():
                try:
                    value = json.loads(line)
                except ValueError:
                    continue
                if value.get('event') == event:
                    values.append(value)
        return values

    def start(name):
        started = time.monotonic()
        event = name + '_started'
        before = len(event_lines(name, event))
        args = [str(control), '--database', str(database), name]
        if name == 'api':
            args += ['--bind', '127.0.0.1:0', '--token', token]
        else:
            args += ['--runtime', 'firecracker', '--firecracker-config', str(config),
                     '--artifact-root', str(fixture / 'public-artifacts')]
        with logs[name].open('ab') as output:
            processes[name] = subprocess.Popen(args, stdin=subprocess.DEVNULL,
                                               stdout=output, stderr=subprocess.STDOUT, env=env)
        until = time.monotonic() + 180
        while len(event_lines(name, event)) <= before:
            assert processes[name].poll() is None, f'public {name} exited before readiness'
            assert time.monotonic() < until, f'public {name} readiness deadline'
            time.sleep(.1)
        report['observations'].setdefault('service_start_seconds', {}).setdefault(name, []).append(round(time.monotonic() - started, 3))
        return event_lines(name, event)[-1]

    def stop(name, kill=False):
        process = processes.get(name)
        if process and process.poll() is None:
            if kill:
                process.kill()
            else:
                process.send_signal(__import__('signal').SIGINT)
            process.wait(timeout=35)
        if process:
            assert not (Path('/proc') / str(process.pid)).exists()

    def record(sid):
        return json.loads((root / 'records' / f'{sid}.json').read_text())

    def paths(value):
        generation = uuid.UUID(value['owner']['generation'])
        suffix = uuid.UUID(installation).hex + '-' + generation.hex
        return [root / 'vm' / generation.hex[:12],
                Path('/sys/fs/cgroup') / ('ghv-' + suffix),
                Path('/sys/fs/cgroup') / ('ghs-' + suffix)]

    def create(ttl=240):
        return {'profile': 'local-firecracker', 'image': 'sha256:' + boot['rootfs']['sha256'],
                'ttl_seconds': ttl, 'resources': {'cpu_millis': 500,
                'memory_bytes': 256 * 1024**2, 'pids': 40},
                'required_capabilities': ['commands', 'files', 'pause', 'network_isolation', 'artifacts']}

    def complete(value):
        return client.wait_operation(value['id'], timeout=150)

    def terminate(sid):
        complete(client.terminate(sid, str(uuid.uuid4())))
        value = client.sandbox(sid)
        assert value['state'] == 'terminated' and value['cleanup'] == 'complete', value
        native_record = record(sid)
        assert native_record['phase'] == 'collected' and all(not p.exists() for p in paths(native_record))

    try:
        ready = start('api')
        installation = ready['installation_id']
        endpoint = 'http://' + ready['address']
        with native.open('rb') as source:
            native_sha = hashlib.file_digest(source, 'sha256').hexdigest()
        cfg = {'installation_id': installation, 'data_root': str(root), 'artifacts': boot,
               'supervisor': {'path': str(native), 'size': native.stat().st_size, 'sha256': native_sha},
               'image': 'sha256:' + boot['rootfs']['sha256'],
               'max_resources': {'cpu_millis': 2000, 'memory_bytes': 512 * 1024**2, 'pids': 256},
               'capacity': {'cpu_millis': 2000, 'memory_bytes': 2 * 1024**3, 'max_vms': 2},
               'max_ttl_seconds': 300}
        config.write_text(json.dumps(cfg)); config.chmod(0o600)
        manager = Manager(native, config, cfg)
        manager.start()
        start('worker')
        client = Client(endpoint, token)
        profiles = client.profiles()
        assert len(profiles) == 1 and profiles[0]['id'] == 'local-firecracker', profiles
        assert profiles[0]['availability'] == 'available', profiles
        expected = {'commands', 'files', 'pause', 'network_isolation', 'artifacts'}
        assert set(profiles[0]['capabilities']) == expected, profiles
        report['observations']['profiles'] = profiles
        report['cases'].append('native_only_worker_probes_real_KVM_with_no_Docker_profiles_or_connection')

        before = client.list()['items']
        for capability in ['memory_snapshot', 'rootfs_snapshot', 'volume_snapshot', 'network_policy', 'secret_injection', 'isolated_sessions', 'pty']:
            request = create(); request['required_capabilities'] = [capability]
            try:
                client.create(request, str(uuid.uuid4()))
            except ApiError as error:
                assert error.code == 'unsupported_capability', (capability, error)
            else:
                raise AssertionError('unverified capability admitted: ' + capability)
        request = create(); request['network'] = {'default_action': 'allow', 'rules': []}
        try:
            client.create(request, str(uuid.uuid4()))
        except ApiError as error:
            assert error.code == 'unsupported_capability', error
        else:
            raise AssertionError('unimplemented native network policy admitted')
        assert client.list()['items'] == before
        report['cases'].append('public_admission_refuses_unverified_features_and_network_without_runtime_fallback')

        request = create(); key = str(uuid.uuid4())
        created = client.create(request, key)
        sid = created['sandbox']['id']; sandboxes.append(sid)
        repeated = client.create(request, key)
        assert repeated['sandbox']['id'] == sid and repeated['operation']['id'] == created['operation']['id']
        complete(created['operation'])
        assert client.sandbox(sid)['state'] == 'running'
        generation = record(sid)['owner']['generation']
        nonce = uuid.uuid4().hex
        binary = b'\x00\xff' + nonce.encode()
        client.write_file(sid, 'native-public.bin', binary)
        assert client.read_file(sid, 'native-public.bin') == binary
        result = client.run(sid, Command(['python3', '-c',
            f"import os; assert os.getuid()==1000; assert sorted(os.listdir('/sys/class/net'))==['lo']; print({nonce!r},end='')"]))
        assert result.stdout == nonce.encode() and result.execution['cleanup'] == 'complete'
        report['cases'].append('Python_SDK_idempotent_create_actual_file_and_command_stdout')

        cli_env = dict(env, GOLDENHOOP_ENDPOINT=endpoint)
        observed = subprocess.run([str(cli), 'profiles'], env=cli_env, capture_output=True, timeout=35, check=True)
        assert json.loads(observed.stdout)[0]['id'] == 'local-firecracker'
        inspected = subprocess.run([str(cli), 'get', sid], env=cli_env, capture_output=True, timeout=35, check=True)
        assert json.loads(inspected.stdout)['id'] == sid
        executed = subprocess.run([str(cli), 'exec', sid, '--', 'printf', '%s', nonce],
                                  env=cli_env, capture_output=True, timeout=45, check=True)
        assert executed.stdout == nonce.encode(), (executed.stdout, executed.stderr)
        report['cases'].append('Rust_CLI_and_Rust_client_observe_same_generation_and_actual_stdout')

        complete(client.pause(sid, str(uuid.uuid4())))
        assert client.sandbox(sid)['state'] == 'paused'
        complete(client.resume(sid, str(uuid.uuid4())))
        assert client.read_file(sid, 'native-public.bin') == binary
        report['cases'].append('public_pause_resume_preserves_guest_file')

        # Keep the actual execution live until the post-restart release, so a
        # transient three-second state cannot be missed by control-plane polls.
        command = Command(['python3', '-c', recovery_program(nonce)])
        command_key = str(uuid.uuid4())
        execution = client.start(sid, command, command_key)
        submitted = time.monotonic()
        until = time.monotonic() + 25
        transitions = report['observations']['recovery_execution_transitions'] = []
        while True:
            current = client.execution(execution['id'])
            if not transitions or transitions[-1] != current:
                transitions.append(current)
                del transitions[:-64]
            assert time.monotonic() < until, f'command readiness deadline: {current}'
            if current['state'] == 'running':
                report['observations']['recovery_running_seconds'] = round(time.monotonic() - submitted, 3)
                break
            assert current['state'] == 'pending', f'command ended before fault injection: {current}'
            time.sleep(.05)
        assert client.read_file(sid, 'ready-' + nonce) == b'ready'
        report['observations']['recovery_guest_ready_seconds'] = round(time.monotonic() - submitted, 3)
        assert time.monotonic() < until, 'guest readiness readback exceeded original fault-injection budget'
        report['observations']['recovery_guest_ready_before_kill'] = True
        stop('worker', kill=True)
        start('worker')
        assert record(sid)['owner']['generation'] == generation
        assert client.create(request, key)['sandbox']['id'] == sid
        assert client.start(sid, command, command_key)['id'] == execution['id']
        assert client.execution(execution['id'])['state'] == 'running'
        client.write_file(sid, 'release-' + nonce, b'release')
        assert client.wait_execution(execution['id'])['state'] == 'succeeded'
        assert client.read_file(sid, 'once') == b'once'
        assert client.read_file(sid, 'native-public.bin') == binary
        report['cases'].append('public_worker_SIGKILL_recovers_same_VM_and_execution_without_replay')

        if manager_recovery:
            from firecracker_manager_recovery_contract import exercise
            observations = report['observations']['manager_crash_recovery'] = {}
            checks, observations = exercise(native, cfg, config, root, manager, client, sid, complete, observed=observations)
            report['cases'] += ['manager_recovery:'+check for check in checks]
            report['observations']['manager_crash_recovery'] = observations

        captured = client.create_artifact(sid, CreateArtifact('native-public.bin', 'native-public.bin'), str(uuid.uuid4()))
        complete(captured['operation']); artifact_id = captured['artifact']['id']
        assert client.artifact_bytes(artifact_id) == binary
        terminate(sid)
        assert client.artifact_bytes(artifact_id) == binary
        complete(client.delete_artifact(artifact_id, str(uuid.uuid4())))
        deleted = client.artifact(artifact_id)
        assert deleted['state'] == 'deleted' and deleted['cleanup'] == 'complete'
        report['cases'].append('native_file_artifact_survives_VM_collection_then_confirms_storage_collection')

        expiring = client.create(create(ttl=75), str(uuid.uuid4()))
        eid = expiring['sandbox']['id']; sandboxes.append(eid)
        complete(expiring['operation'])
        complete(client.pause(eid, str(uuid.uuid4())))
        expired_record = record(eid)
        stop('worker', kill=True)
        if manager_recovery:
            report['observations']['expiry_actual_manager_death'] = manager.hard_kill()
        until = time.monotonic() + 90
        samples = report['observations']['independent_expiry'] = []
        manager.wait_collected(expired_record, until, samples)
        if manager_recovery:
            owner = manager.start()
            previous = report['observations']['expiry_actual_manager_death']['owner']
            assert owner['epoch'] != previous['epoch'] and owner['recovery']['previous_process']==previous['process']
            assert not Path(previous['cgroup']).exists()
            report['observations']['expiry_recovered_manager'] = owner
            report['cases'].append('paused_VM_expires_with_worker_and_manager_dead_before_fenced_restart_and_collection')
        start('worker')
        terminate(eid)
        report['cases'].append('paused_VM_expires_with_worker_dead_and_public_recovery_confirms_physical_collection')
        report['result'] = 'passed'
    except Exception as error:
        report['error'] = f'{type(error).__name__}: {error}'
        report['failure_site'] = [{'file': Path(frame.filename).name, 'line': frame.lineno,
                                   'function': frame.name} for frame in traceback.extract_tb(error.__traceback__)]
    finally:
        cleanup_errors = []
        for name in ['worker', 'api']:
            try:
                stop(name)
            except Exception as error:
                cleanup_errors.append(str(error))
        if client:
            client.close()
        if manager:
            try:
                manager.ensure_collection_owner()
            except Exception as error:
                cleanup_errors.append(f'collection owner: {type(error).__name__}: {error}')
        if config.exists() and (root / 'records').exists():
            records = []
            for path in sorted((root / 'records').glob('*.json')):
                try:
                    value = json.loads(path.read_text()); records.append(value)
                    if manager:
                        value['live_resources_before_final_collection'] = manager.observe(value)
                    assert value['owner']['installation_id'] == installation
                    handle = {'sandbox_id': value['owner']['sandbox_id'], 'profile': 'local-firecracker',
                              'backend_ref': f'fc1:{installation}:{value["owner"]["generation"]}'}
                    call_file = fixture / 'public-collect.json'
                    call_file.write_text(json.dumps({'operation': 'remove', 'handle': handle})); call_file.chmod(0o600)
                    result = subprocess.run([str(native), 'driver-call', '--config', str(config), '--request', str(call_file)],
                                            capture_output=True, timeout=40)
                    assert result.returncode == 0 and json.loads(result.stdout)['ok'], result.stderr.decode(errors='replace')[-1000:]
                    assert all(not p.exists() for p in paths(value))
                    collected = manager.observe(value)
                    value['live_resources_after_final_collection'] = collected
                    assert not any(collected['paths'].values()) and all(
                        not process['present'] or process.get('identity_start_matches') is False
                        for process in collected['processes'].values()), collected
                except Exception as error:
                    cleanup_errors.append(f'generation collection: {type(error).__name__}: {error}')
            report['observations']['records_before_final_collection'] = records
        if manager:
            try:
                stop_error = manager.close()
                if stop_error:
                    report['manager_stop_error'] = stop_error
                    report['result'] = 'failed'
            except Exception as error:
                cleanup_errors.append(str(error))
            report['observations']['manager'] = manager.diagnostics()
        report['observations']['service_log_tails'] = {name: path.read_text(errors='replace')[-5000:]
                                                       for name, path in logs.items() if path.exists()}
        report['cleanup'] = 'complete' if not cleanup_errors else 'unknown'
        if cleanup_errors:
            report['cleanup_errors'] = cleanup_errors
            report['result'] = 'failed'
    return report
