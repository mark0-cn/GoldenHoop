"""Actual native manager restoration. The captured execution is never replayed."""
import base64
import copy
import json
import os
from pathlib import Path
import signal
import select
import socket
import time
import uuid


def exercise(root, cfg, manager, request, call, rpc, command, record, remove, handles, report):
    observed = report['observations']['managed_restore'] = {}
    source = call(request(ttl=300)); handles[source['sandbox_id']] = source
    source_record = record(source['sandbox_id'])
    execution = str(uuid.uuid4())
    script = ("import os,time;from pathlib import Path;token=os.urandom(32);print(token.hex(),flush=True)\n"
              "while not Path('/workspace/native-release').exists(): time.sleep(.1)\n"
              "Path('/workspace/native-resumed').write_text(token.hex())\n")
    spec = {'argv':['python3','-c',script], 'timeout_seconds':180, 'max_output_bytes':512}
    assert rpc(source, {'method':'start','id':execution,'command':spec}, 'execution')['id'] == execution
    until = time.monotonic()+20
    while True:
        events = rpc(source, {'method':'events','id':execution,'after':0}, 'events')
        raw = b''.join(base64.b64decode(e['data']['data'],validate=True)
                       for e in events if e['kind']=='stdout')
        if raw:
            token = raw.decode().strip(); assert len(token)==64 and len(bytes.fromhex(token))==32
            break
        assert time.monotonic()<until
        time.sleep(.05)
    payload = ('native-disk-'+uuid.uuid4().hex).encode()
    rpc(source, {'method':'write_file','path':'native-payload','data_base64':base64.b64encode(payload).decode()}, 'ok')
    capture = str(uuid.uuid4())
    ready = call({'operation':'checkpoint_capture','handle':source,'capture':capture})
    until=time.monotonic()+150
    while ready['phase']!='ready':
        assert ready['capture_outcome']=='pending' and time.monotonic()<until, ready
        time.sleep(.1)
        ready=call({'operation':'checkpoint_inspect','capture':capture})
    assert ready['capture_outcome']=='ready' and ready['content_verified']
    reference = ready['reference']
    assert ready['manifest']['source']['source_generation']==source_record['owner']['generation']
    remove(source)
    observed.update(source=source_record, execution=execution, token=token, capture=capture, ready=ready)
    report['cases'].append('native_manager_captures_original_running_execution_and_collects_source_before_restoration')

    creation = request(ttl=300)
    operation = {'operation':'checkpoint_restore','restore':{
        'sandbox':creation['sandbox'], 'request':creation['request'],
        'reference':reference, 'restoration':str(uuid.uuid4())}}
    identity = manager.owner
    message = {key:identity[key] for key in ['installation_id','epoch','config_sha256']}
    message['operation'] = {'method':'call','call':operation}
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
        client.settimeout(10); client.connect(str(root/'manager.sock'))
        client.sendall(json.dumps(message).encode()+b'\n'); client.shutdown(socket.SHUT_WR)
    observed['submitting_client_closed_without_reply'] = True
    target_id = creation['sandbox']['id']
    path = root/'records'/f'{target_id}.json'
    transitions = observed['target_phases'] = []
    until = time.monotonic()+150
    while True:
        if path.exists():
            current = record(target_id)
            if not transitions or transitions[-1]!=current['phase']:
                transitions.append(current['phase'])
            assert current['phase'] not in ['unknown','vm_collected','collected'], current
            if current['phase']=='running':
                break
        assert time.monotonic()<until, transitions
        time.sleep(.05)
    generation = current['owner']['generation']
    handle = {'sandbox_id':target_id,'profile':'local-firecracker',
              'backend_ref':f'fc1:{cfg["installation_id"]}:{generation}'}
    handles[target_id] = handle
    assert call(operation)==handle
    assert call({'operation':'inspect','handle':handle})['state']=='running'
    manager.assert_parent(current)
    assert current['restore']['intent']['reference']==reference
    assert current['restore']['intent']['generation']==generation
    status = call({'operation':'checkpoint_inspect','capture':capture})
    restored = status['restoration']; observed['activated'] = restored
    assert restored['phase']=='activated' and restored['outcome']=='activated'
    assert restored['producer']['process']==current['supervisor']
    assert restored['writer']['process']['pid']==current['process']['pid']
    assert status['reserved_bytes']==ready['reserved_bytes']+ready['manifest']['disk']['size_bytes']
    assert rpc(handle,{'method':'read_file','path':'native-payload','max_bytes':128},'file')['data_base64']==base64.b64encode(payload).decode()
    report['cases'].append('native_supervisor_owns_single_use_claim_and_restores_live_target_after_submitting_client_disconnect')

    before = path.read_bytes()
    changed = copy.deepcopy(operation); changed['restore']['restoration']=str(uuid.uuid4())
    assert call(changed,expect=False)['code']=='conflict'
    competitor = request(ttl=300)
    second = copy.deepcopy(operation); second['restore'].update(sandbox=competitor['sandbox'], request=competitor['request'], restoration=str(uuid.uuid4()))
    assert call(second,expect=False)['code']=='conflict'
    assert not os.path.lexists(root/'records'/f'{competitor["sandbox"]["id"]}.json')
    assert path.read_bytes()==before
    assert call(creation,expect=False)['code']=='conflict'
    report['cases'].append('native_live_retry_keeps_original_generation_and_changed_or_competing_intent_refuses_before_allocation')

    observed['manager_death'] = manager.hard_kill()
    restarted = manager.start(); observed['manager_restart'] = restarted
    assert restarted['recovery']['previous_process']==identity['process']
    after = record(target_id)
    assert after['owner']==current['owner'] and after['process']==current['process'] and after['supervisor']==current['supervisor']
    assert call(operation)==handle
    assert call({'operation':'inspect','handle':handle})['state']=='running'
    rpc(handle,{'method':'write_file','path':'native-release','data_base64':''},'ok')
    until = time.monotonic()+25
    while True:
        state = rpc(handle,{'method':'inspect','id':execution},'execution')
        if state['state'] in ['succeeded','failed','cancelled','timed_out']:
            break
        assert time.monotonic()<until
        time.sleep(.05)
    assert state['id']==execution and state['state']=='succeeded' and state['exit_code']==0 and state['cleanup']=='complete', state
    resumed = rpc(handle,{'method':'read_file','path':'native-resumed','max_bytes':128},'file')
    assert base64.b64decode(resumed['data_base64'],validate=True)==token.encode()
    observed['original_execution_after_manager_reconnect'] = state
    assert command(handle,"print('native-after-reconnect')")=='native-after-reconnect'
    report['cases'].append('native_restored_target_survives_manager_SIGKILL_and_original_execution_finishes_with_RAM_token_without_Start_replay')

    supervisor = current['supervisor']
    proc = Path('/proc')/str(supervisor['pid'])
    fd = os.pidfd_open(supervisor['pid'])
    try:
        assert int((proc/'stat').read_text().rsplit(')',1)[1].split()[19])==supervisor['start_ticks']
        signal.pidfd_send_signal(fd,signal.SIGKILL)
        exited=select.poll(); exited.register(fd,select.POLLIN)
        assert any(events & select.POLLIN for _,events in exited.poll(15000)), 'original supervisor exit unconfirmed'
    finally:
        os.close(fd)
    observed['target_supervisor_SIGKILL'] = supervisor
    collected = remove(handle)
    observed['target_collected'] = collected
    retained = call({'operation':'checkpoint_inspect','capture':capture})
    assert retained['content_verified'] and retained['reference']==reference
    assert retained['restoration']['phase']=='closed' and retained['restoration']['outcome']=='activated'
    assert retained['reserved_bytes']==ready['reserved_bytes']
    assert call(operation)==handle
    assert record(target_id)['owner']==current['owner'] and record(target_id)['phase']=='collected'
    report['cases'].append('native_manager_recovers_killed_restored_supervisor_collects_original_VMM_and_closes_only_original_target_quota_without_relaunch')

    final = call({'operation':'checkpoint_collect','capture':capture})
    assert final['objects_absent'] and final['reserved_bytes']==0
    assert call(operation)==handle
    assert all(not os.path.lexists(root/'checkpoints'/f'capture-{capture}-{role}.bin') for role in ['state','memory','disk'])
    assert call({'operation':'discover'})==[]
    observed['content_collection'] = final
    report['cases'].append('native_closed_retry_works_after_exact_snapshot_object_GC_without_content_reopen_or_new_allocation')
