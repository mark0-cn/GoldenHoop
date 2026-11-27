"""Actual native manager capture; Python only injects faults and observes results."""
import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import uuid


def exercise(binary, config, root, cfg, manager, request, call, rpc, command,
             record, remove, handles, report):
    observations = report['observations']['managed_checkpoint'] = {}
    source = call(request(ttl=300)); handles[source['sandbox_id']] = source
    other = call(request(ttl=300)); handles[other['sandbox_id']] = other
    original = record(source['sandbox_id'])
    capture = str(uuid.uuid4())
    observations.update(capture=capture, source_before=original, other=other)
    payload = ('managed-checkpoint-'+uuid.uuid4().hex).encode()
    rpc(source, {'method':'write_file','path':'managed-checkpoint.txt',
                 'data_base64':base64.b64encode(payload).decode()}, 'ok')
    assert command(other, "print('other-before-capture')") == 'other-before-capture'

    # Send a real authenticated manager request and close the submitting client
    # without reading its reply. Persistent source/job leases belong to Rust.
    owner = manager.owner
    message = {key:owner[key] for key in ['installation_id','epoch','config_sha256']}
    message['operation'] = {'method':'call','call':{
        'operation':'checkpoint_capture','handle':source,'capture':capture}}
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(10)
        client.connect(str(root/'manager.sock'))
        client.sendall(json.dumps(message).encode()+b'\n')
        client.shutdown(socket.SHUT_WR)
    observations['submitting_client_closed_without_reply'] = True
    transitions = observations['capture_status'] = []
    until = time.monotonic()+150
    while True:
        answer = call({'operation':'checkpoint_inspect','capture':capture}, expect=None)
        if answer['ok']:
            status = answer['data']
            state = {key:status[key] for key in ['phase','capture_outcome','content_verified','reserved_bytes']}
            if not transitions or transitions[-1] != state:
                transitions.append(state)
            assert status['capture_outcome'] != 'failed', status
            if status['phase'] == 'ready':
                break
            assert status['capture_outcome'] == 'pending', status
        else:
            assert answer['error']['code'] == 'backend_unavailable' and answer['error']['retryable'] is False, answer
        assert time.monotonic() < until, {'capture_deadline':transitions}
        time.sleep(.1)
    assert status['content_verified'] and status['capture_outcome'] == 'ready'
    reference = status['reference']; observations['ready'] = status
    expected_reservation = 2*(original['resources']['memory_bytes']+16*1024**2)+original['artifacts']['rootfs']['size']
    assert status['reserved_bytes'] == expected_reservation
    assert status['manifest']['source']['source_generation'] == original['owner']['generation']
    assert status['manifest']['source']['request_sha256'] == original['owner']['request_sha256']
    assert call({'operation':'inspect','handle':source})['state'] == 'paused'
    assert record(source['sandbox_id'])['capture_hold'] == capture
    assert command(other, "print('other-during-source-hold')") == 'other-during-source-hold'
    report['cases'].append('managed_capture_completes_after_submitting_client_disconnect_with_independent_VM_operation')

    # Both public manager resume and the actual root supervisor endpoint enforce
    # the same persisted hold. A rejected operation never thaws the source.
    denied = call({'operation':'resume','handle':source}, expect=False)
    assert denied['retryable'] is False
    generation = uuid.UUID(original['owner']['generation'])
    control = root/'vm'/generation.hex[:12]/'control.sock'
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(12); client.connect(str(control))
        client.sendall(json.dumps({'owner':original['owner'],'operation':'resume'}).encode()+b'\n')
        with client.makefile('rb') as response:
            refused = json.loads(response.readline(65537))
    assert refused['generation'] == str(generation) and refused['error'], refused
    assert call({'operation':'inspect','handle':source})['state'] == 'paused'
    assert call({'operation':'checkpoint_capture','handle':source,'capture':capture})['reference'] == reference
    conflict = call({'operation':'checkpoint_capture','handle':other,'capture':capture}, expect=False)
    assert conflict['code'] == 'conflict', conflict
    call({'operation':'checkpoint_collect','capture':capture}, expect=False)
    assert call({'operation':'checkpoint_inspect','capture':capture})['reserved_bytes'] == expected_reservation
    report['cases'].append('managed_capture_exact_retry_conflict_source_hold_and_early_collection_refusal')

    observations['manager_death'] = manager.hard_kill()
    restarted = manager.start(); observations['manager_restart'] = restarted
    assert restarted['recovery']['previous_process'] == owner['process']
    now = record(source['sandbox_id'])
    assert now['owner'] == original['owner'] and now['process'] == original['process']
    assert now['capture_hold'] == capture
    assert call({'operation':'inspect','handle':source})['state'] == 'paused'
    call({'operation':'resume','handle':source}, expect=False)
    assert call({'operation':'checkpoint_inspect','capture':capture})['reference'] == reference
    assert command(other, "print('other-after-manager-reconnect')") == 'other-after-manager-reconnect'
    report['cases'].append('managed_capture_Ready_content_and_same_source_hold_survive_actual_manager_SIGKILL_reconnect')

    remove(source)
    retained = call({'operation':'checkpoint_inspect','capture':capture})
    assert retained['content_verified'] and retained['reference'] == reference
    disk = root/'checkpoints'/f'capture-{capture}-disk.bin'
    result = subprocess.run(['debugfs','-R','cat /workspace/managed-checkpoint.txt',str(disk)],
                            capture_output=True, timeout=20)
    assert result.returncode == 0 and result.stdout == payload, (result.returncode, result.stderr[-2048:])
    observations['disk_payload_verified_after_source_collection'] = True
    collected = call({'operation':'checkpoint_collect','capture':capture})
    assert collected['objects_absent'] and collected['reserved_bytes'] == 0
    assert collected['capture_outcome'] == 'ready'
    for role in ['state','memory','disk']:
        assert not os.path.lexists(root/'checkpoints'/f'capture-{capture}-{role}.bin')
    retry = call({'operation':'checkpoint_capture','handle':source,'capture':capture})
    assert retry['phase'] == 'collected' and retry['reference'] == reference and retry['reserved_bytes'] == 0
    observations['collection'] = collected
    remove(other)
    assert call({'operation':'discover'}) == []
    report['cases'].append('managed_capture_persists_independent_drive_after_source_collection_and_observes_exact_object_GC')
