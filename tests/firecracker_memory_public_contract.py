"""Actual public continuation; no fixture can supply the advertised capability."""
import base64
import copy
import datetime
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

import httpx
from goldenhoop import ApiError, Client, Command


def check_reconnection(previous, current, before, after, kernel):
    assert current['ready'] and previous['ready']
    assert current['installation_id'] == previous['installation_id'] == after['owner']['installation_id']
    assert current['epoch'] != previous['epoch'] and current['process'] != previous['process']
    assert current['config_sha256'] == previous['config_sha256']
    assert current['process']['boot_id'] == previous['process']['boot_id'] == after['owner']['host_boot_id']
    recovery = current['recovery']
    assert recovery['previous_epoch'] == previous['epoch'] and recovery['previous_process'] == previous['process']
    for field in ['owner', 'restore', 'process', 'supervisor']:
        assert after[field] == before[field], field
    assert after['phase'] == 'running', after['phase']
    entries = [entry for entry in recovery['generations']
               if entry['sandbox_id'] == after['owner']['sandbox_id'] and entry['generation'] == after['owner']['generation']]
    assert len(entries) == 1 and entries[0]['authenticated'] and entries[0]['observed_state'] == 'running', entries
    assert len(kernel['paths']) == 3 and all(kernel['paths'].values()), kernel
    suffix = uuid.UUID(current['installation_id']).hex + '-' + uuid.UUID(after['owner']['generation']).hex
    for role, prefix in [('supervisor', 'ghs-'), ('process', 'ghv-')]:
        value = kernel['processes'][role]
        assert value['present'] and value['identity_start_matches'] and value['state'] not in ['Z', 'X', 'x'], value
        assert '0::/' + prefix + suffix in value['cgroup'].splitlines(), value
    # A surviving supervisor can be reparented after its original manager dies.
    # It remains the original authenticated parent of this same VMM.
    assert kernel['processes']['process']['parent_pid'] == after['supervisor']['pid'], kernel


def exercise(client, endpoint, token, cli, native, config, fixture, root,
             manager, start, stop, terminate, report, sandboxes, snapshots):
    observed = report['observations']['public_memory'] = {}
    cfg = json.loads(config.read_text())
    original = {'profile': 'local-firecracker', 'image': cfg['image'], 'ttl_seconds': 300,
                'resources': {'cpu_millis': 500, 'memory_bytes': 256 * 1024**2, 'pids': 40},
                'required_capabilities': ['commands', 'files', 'pause', 'network_isolation', 'memory_snapshot', 'artifacts']}
    request = {'target': original}
    cli_env = dict(os.environ, GOLDENHOOP_ENDPOINT=endpoint, GOLDENHOOP_API_TOKEN=token,
                   DOCKER_HOST='unix:///var/empty/goldenhoop-no-docker.sock')

    def complete(operation):
        result = client.wait_operation(operation['id'], timeout=150)
        assert result['state'] == 'succeeded', result
        return result

    def record(sid):
        return json.loads((root / 'records' / f'{sid}.json').read_text())

    def native_call(value, expected=True):
        path = fixture / 'memory-native-request.json'
        path.write_text(json.dumps(value)); path.chmod(0o600)
        result = subprocess.run([str(native), 'driver-call', '--config', str(config), '--request', str(path)],
                                capture_output=True, timeout=160)
        answer = json.loads(result.stdout)
        assert answer['ok'] is expected and result.returncode == (0 if expected else 2), answer
        return answer['data'] if expected else answer['error']

    def key(resources, permissions=('read', 'write', 'execute')):
        expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        return client.issue_api_key({'permissions': list(permissions), 'resources': resources,
                                     'expires_at': expiry.isoformat()})['token']

    def denied(bearer, method, path, value=None, retry_key=None):
        headers = {'authorization': 'Bearer ' + bearer}
        if retry_key:
            headers['idempotency-key'] = retry_key
        response = httpx.request(method, endpoint + '/v1/' + path, headers=headers, json=value, timeout=30)
        assert response.status_code == 403 and response.json()['code'] == 'forbidden', (response.status_code, response.text)

    def stdout(eid, after=0, stop_at_newline=False, owner=client):
        events, raw = [], b''
        stream = owner.events(eid, after, _deadline=time.monotonic() + 30)
        try:
            for event in stream:
                assert event['execution_id'] == eid, event
                events.append(event)
                if event['kind'] == 'stdout':
                    assert event['data']['encoding'] == 'base64', event
                    raw += base64.b64decode(event['data']['data'], validate=True)
                if stop_at_newline and b'\n' in raw:
                    break
        finally:
            stream.close()
            sample = {'events': events, 'stdout_base64': base64.b64encode(raw).decode()}
            observed.setdefault('execution_output_observations', {})[eid] = sample
            try:
                sample['execution'] = owner.execution(eid)
            except Exception as error:
                sample['inspection_error'] = type(error).__name__ + ': ' + str(error)
        return events, raw

    def running_execution(eid):
        until = time.monotonic() + 20
        samples = observed.setdefault('execution_start_observations', {}).setdefault(eid, [])
        while True:
            value = client.execution(eid)
            if not samples or samples[-1] != value:
                samples.append(value)
            if value['state'] == 'running' and value['started_at']:
                return value
            assert value['state'] not in ['succeeded', 'failed', 'cancelled', 'timed_out'], value
            assert time.monotonic() < until, value
            time.sleep(.1)

    probes = [json.loads(path.read_text()) for path in (root / 'memory-probes').glob('*.json')]
    assert len(probes) == 1 and probes[0]['checked'] and probes[0]['collected'], probes
    proof = probes[0]
    observed['capability_probe'] = {'receipt': proof}
    for sid in [proof['source']['id'], proof['target']['id']]:
        value = record(sid)
        assert value['phase'] == 'collected' and not any(manager.observe(value)['paths'].values()), value
    proof_status = native_call({'operation': 'checkpoint_collect', 'capture': proof['capture']})
    observed['capability_probe']['checkpoint'] = proof_status
    assert proof_status['objects_absent'] and proof_status['reserved_bytes'] == 0, proof_status
    report['cases'].append('memory_capability_requires_actual_RAM_continuation_and_positive_probe_VM_and_object_collection')

    created = client.create(original, 'memory-source'); sid = created['sandbox']['id']; sandboxes.append(sid)
    complete(created['operation'])
    source_owner = key({'sandboxes': [sid]})
    global_owner = key('all')
    payload = ('public-memory-disk-' + uuid.uuid4().hex).encode()
    client.write_file(sid, 'public-memory-disk', payload)
    program = ("import os,time\nfrom pathlib import Path\ntoken=os.urandom(32).hex()\n"
               "with Path('/workspace/public-memory-once').open('a') as f: f.write('once')\n"
               "print(token,flush=True)\n"
               "while not Path('/workspace/public-memory-release').exists(): time.sleep(.05)\n"
               "print('resumed:'+token,flush=True)\n")
    running = client.start(sid, Command(['python3', '-c', program], timeout_seconds=240, max_output_bytes=1024), 'retained-memory-job')
    old = running['id']
    source_events, raw = stdout(old, stop_at_newline=True)
    ram_token = raw.decode().strip(); assert len(ram_token) == 64 and len(bytes.fromhex(ram_token)) == 32
    running = running_execution(old)
    captured = client.create_snapshot(sid, {'kind': 'memory_and_disk'}, 'public-capture')
    observed['capture_admission'] = captured
    snapshot = captured['snapshot']['id']; snapshots.append(snapshot)
    complete(captured['operation'])
    ready = client.snapshot(snapshot)
    observed['capture_ready'] = ready
    assert ready['state'] == 'ready' and ready['manifest']['source_sandbox_id'] == sid, ready
    assert client.create_snapshot(sid, {'kind': 'memory_and_disk'}, 'public-capture')['snapshot']['id'] == snapshot
    before = client.list()['items']
    try:
        client.restore_snapshot(snapshot, request, 'source-live-refusal')
    except ApiError as error:
        assert error.code == 'invalid_state', error
    else:
        raise AssertionError('live captured source acquired a second execution authority')
    assert [s['id'] for s in client.list()['items']] == [s['id'] for s in before]
    try:
        client.write_file(sid, 'public-memory-release', b'forbidden')
    except ApiError as error:
        assert error.code == 'invalid_state', error
    else:
        raise AssertionError('captured source accepted a normal guest RPC')
    source_native = record(sid)
    source_handle = {'sandbox_id': sid, 'profile': 'local-firecracker',
                     'backend_ref': f'fc1:{cfg["installation_id"]}:{source_native["owner"]["generation"]}'}
    terminate(sid)
    source_after = manager.observe(source_native)
    assert not any(source_after['paths'].values()), source_after
    assert all(not value['present'] or value.get('identity_start_matches') is False for value in source_after['processes'].values()), source_after
    report['cases'].append('public_capture_fences_source_and_requires_positive_source_collection_before_new_authority')

    status = native_call({'operation': 'checkpoint_inspect', 'capture': snapshot})
    now = datetime.datetime.now(datetime.timezone.utc)
    candidate = copy.deepcopy(created['sandbox'])
    candidate.update(id=str(uuid.uuid4()), state='pending', desired_state='running', cleanup='pending',
                     created_at=now.isoformat(), expires_at=(now + datetime.timedelta(seconds=300)).isoformat(),
                     observed_at=None, reason=None)
    foreign = copy.deepcopy(source_handle); foreign['backend_ref'] = f'fc1:{cfg["installation_id"]}:{uuid.uuid4()}'
    private_intent = {'sandbox': candidate, 'request': {**original, 'required_capabilities': ['commands', 'files']},
                      'reference': status['reference'], 'restoration': str(uuid.uuid4()), 'expected_source': foreign}
    error = native_call({'operation': 'checkpoint_restore', 'restore': private_intent}, expected=False)
    assert error['code'] == 'conflict' and not (root / 'records' / f'{candidate["id"]}.json').exists(), error
    assert native_call({'operation': 'checkpoint_inspect', 'capture': snapshot}).get('restoration') is None
    report['cases'].append('validly_encoded_foreign_source_generation_is_refused_before_target_allocation_or_capture_claim')

    denied(source_owner, 'POST', f'snapshots/{snapshot}/restore', request, 'source-owner-refusal')
    with Client(endpoint, global_owner) as creator:
        reply = creator.restore_snapshot(snapshot, request, 'public-restore')
    target = reply['sandbox']['id']; sandboxes.append(target)
    observed['restoration_admission'] = reply
    assert target != sid and reply['operation']['resource_id'] == target
    bindings = {binding['source_execution_id']: binding['execution'] for binding in reply['executions']}
    assert set(bindings) == {old}, bindings
    new = bindings[old]['id']
    assert new != old
    request_file = fixture / 'public-restore.json'; request_file.write_text(json.dumps(request)); request_file.chmod(0o600)
    retried = subprocess.run([str(cli), 'snapshots', 'restore', snapshot, '--request', str(request_file),
                              '--idempotency-key', 'public-restore', '--no-wait'], env=cli_env,
                             capture_output=True, timeout=45, check=True)
    recovered = json.loads(retried.stdout)
    assert recovered['sandbox']['id'] == target and recovered['operation']['id'] == reply['operation']['id']
    complete(reply['operation'])
    target_native = record(target)
    assert target_native['restore']['expected_source'] == source_handle
    assert target_native['owner']['generation'] != source_native['owner']['generation']
    manager.assert_parent(target_native)
    for path in [f'sandboxes/{target}', f'sandboxes/{target}/restoration', f'operations/{reply["operation"]["id"]}', f'executions/{new}']:
        denied(source_owner, 'GET', path)
    denied(source_owner, 'POST', f'executions/{new}/cancel')
    target_owner = key({'sandboxes': [target]})
    readonly = key({'sandboxes': [target]}, ('read',))
    denied(readonly, 'POST', f'executions/{new}/cancel')
    denied(target_owner, 'POST', f'snapshots/{snapshot}/restore', request, 'public-restore')
    observed.update(source=sid, target=target, snapshot=snapshot, source_execution=running,
                    source_events=source_events, restored_execution_ids={old: new},
                    target_before_restart=target_native)
    report['cases'].append('SDK_and_Rust_CLI_explicit_retry_recover_one_target_new_public_execution_IDs_and_exact_target_grants')

    # The original retained job remains alive through manager SIGKILL and worker
    # reconnect. Their native generation, supervisor and VMM must be unchanged.
    death = manager.hard_kill()
    observed['manager_death'] = death
    stop('worker', kill=True); manager.start(); start('worker')
    after_restart = record(target)
    observed['manager_after_restart'] = manager.owner
    observed['target_after_restart'] = after_restart
    observed['target_kernel_after_restart'] = manager.observe(after_restart)
    check_reconnection(death['owner'], manager.owner, target_native, after_restart,
                       observed['target_kernel_after_restart'])
    probes_after = [json.loads(path.read_text()) for path in (root / 'memory-probes').glob('*.json')]
    assert len(probes_after) == 1 and probes_after[0]['id'] == proof['id'], probes_after
    assert 'memory_snapshot' in client.profiles()[0]['capabilities']
    with Client(endpoint, target_owner) as owner:
        current = owner.snapshot_restoration(target)
        assert current['operation']['id'] == reply['operation']['id'] and current['sandbox']['state'] == 'running'
        for old_execution, new_execution in [(running, new)]:
            actual = owner.execution(new_execution)
            assert actual['sandbox_id'] == target and actual['state'] == 'running'
            assert actual['started_at'] == old_execution['started_at'], actual
        assert owner.read_file(target, 'public-memory-disk') == payload
        assert owner.read_file(target, 'public-memory-once') == b'once'
        owner.write_file(target, 'public-memory-release', b'release')
        done = owner.wait_execution(new, timeout=30)
        assert done['state'] == 'succeeded' and done['exit_code'] == 0 and done['cleanup'] == 'complete', done
        events, result = stdout(new, owner=owner)
        assert result == ('resumed:' + ram_token + '\n').encode(), (result, events)
        sequences = [event['sequence'] for event in events]
        assert sequences == sorted(set(sequences)) and all(value > 0 for value in sequences)
        completed = [event for event in events if event['kind'] == 'completed']
        assert len(completed) == 1 and completed[0]['data']['id'] == new and completed[0]['data']['sandbox_id'] == target
        assert owner.read_file(target, 'public-memory-once') == b'once'
        observed['retained_completion'] = {'execution': done, 'events': events, 'stdout': result.decode()}
    report['cases'].append('manager_SIGKILL_reconnects_same_native_generation_and_resumes_RAM_command_without_Start_replay')
    inspected = subprocess.run([str(cli), 'snapshots', 'restoration', target], env=cli_env,
                               capture_output=True, timeout=35, check=True)
    assert json.loads(inspected.stdout)['sandbox']['id'] == target
    # Snapshot objects remain pinned until the target is positively collected.
    try:
        client.delete_snapshot(snapshot, 'still-referenced')
    except ApiError as error:
        assert error.code == 'invalid_state', error
    else:
        raise AssertionError('live restored VM lost its file-backed memory objects')
    terminate(target)
    complete(client.delete_snapshot(snapshot, 'public-delete'))
    deleted = client.snapshot(snapshot)
    assert deleted['state'] == 'collected' and deleted['cleanup'] == 'complete', deleted
    closed = native_call({'operation': 'checkpoint_collect', 'capture': snapshot})
    assert closed['objects_absent'] and closed['reserved_bytes'] == 0, closed
    with Client(endpoint, global_owner) as creator:
        replay = creator.restore_snapshot(snapshot, request, 'public-restore')
        assert replay['sandbox']['id'] == target and replay['operation']['id'] == reply['operation']['id']
        try:
            creator.restore_snapshot(snapshot, request, 'another-target')
        except ApiError as error:
            assert error.code in ['conflict', 'invalid_state'], error
        else:
            raise AssertionError('single-use capture admitted another target')
    observed.update(target_after_collection=record(target), collected_snapshot=deleted, native_checkpoint=closed)
    report['cases'].append('public_deletion_retains_file_backing_until_VM_collection_and_permanently_preserves_single_use_restore_identity')

    # Commands share one UID and serialize (docs/agent.md). A separate source
    # retains cancellation coverage without assuming concurrent normal commands.
    cancel_observed = observed['retained_cancel'] = {}
    created_cancel = client.create(original, 'cancel-memory-source')
    cancel_source = created_cancel['sandbox']['id']; sandboxes.append(cancel_source)
    cancel_observed['source_admission'] = created_cancel
    complete(created_cancel['operation'])
    cancellable = client.start(cancel_source, Command(
        ['python3', '-c', "import time;print('cancel-ready',flush=True);time.sleep(240)"],
        timeout_seconds=240, max_output_bytes=1024), 'retained-cancel-job')
    cancel_observed['execution_admission'] = cancellable
    _, cancel_stdout = stdout(cancellable['id'], stop_at_newline=True)
    assert cancel_stdout == b'cancel-ready\n', cancel_stdout
    cancellable = running_execution(cancellable['id'])
    capture_cancel = client.create_snapshot(cancel_source, {'kind': 'memory_and_disk'}, 'cancel-public-capture')
    cancel_snapshot = capture_cancel['snapshot']['id']; snapshots.append(cancel_snapshot)
    cancel_observed['capture_admission'] = capture_cancel
    complete(capture_cancel['operation'])
    cancel_source_native = record(cancel_source)
    terminate(cancel_source)
    cancel_source_after = manager.observe(cancel_source_native)
    assert not any(cancel_source_after['paths'].values()), cancel_source_after
    assert all(not value['present'] or value.get('identity_start_matches') is False
               for value in cancel_source_after['processes'].values()), cancel_source_after
    with Client(endpoint, global_owner) as creator:
        cancel_reply = creator.restore_snapshot(cancel_snapshot, request, 'cancel-public-restore')
    cancel_target = cancel_reply['sandbox']['id']; sandboxes.append(cancel_target)
    cancel_observed['restoration_admission'] = cancel_reply
    assert cancel_target != cancel_source
    cancel_bindings = {binding['source_execution_id']: binding['execution'] for binding in cancel_reply['executions']}
    assert set(cancel_bindings) == {cancellable['id']}, cancel_bindings
    cancel_new = cancel_bindings[cancellable['id']]['id']
    assert cancel_new != cancellable['id']
    complete(cancel_reply['operation'])
    cancel_target_owner = key({'sandboxes': [cancel_target]})
    with Client(endpoint, cancel_target_owner) as owner:
        retained_cancel = owner.execution(cancel_new)
        assert retained_cancel['sandbox_id'] == cancel_target and retained_cancel['state'] == 'running', retained_cancel
        assert retained_cancel['started_at'] == cancellable['started_at'], retained_cancel
        owner.cancel(cancel_new)
        cancelled = owner.wait_execution(cancel_new, timeout=30)
        assert cancelled['state'] == 'cancelled' and cancelled['cleanup'] == 'complete', cancelled
        assert owner.sandbox(cancel_target)['state'] == 'running'
    terminate(cancel_target)
    complete(client.delete_snapshot(cancel_snapshot, 'cancel-public-delete'))
    cancel_closed = native_call({'operation': 'checkpoint_collect', 'capture': cancel_snapshot})
    assert cancel_closed['objects_absent'] and cancel_closed['reserved_bytes'] == 0, cancel_closed
    cancel_observed.update(source_execution=cancellable, retained_execution=retained_cancel,
                           cancellation=cancelled, source_after_collection=cancel_source_after,
                           target_after_collection=record(cancel_target), checkpoint=cancel_closed)
    report['cases'].append('retained_execution_cancel_uses_new_public_ID_and_confirms_descendant_cleanup_in_a_separate_sandbox')
