"""Actual guest authority protocol on one owned VM, before native restore exists.

The physical VMM stays the same. This does not establish source termination,
memory restoration, a host restore claim or a public snapshot capability.
"""
import base64
import uuid

from firecracker_barrier_contract import guest_channel, guest_exchange, guest_frame, guest_reply


def exercise(handle, record, runtime, call, rpc, report):
    source = record['owner']['generation']
    target, barrier, restoration = [str(uuid.uuid4()) for _ in range(3)]
    observations = report['observations']['guest_authority'] = {
        'scope': 'same physical VM, actual private guest protocol only; not memory restore',
        'source_generation': source, 'target_generation': target,
        'original_process': record['process'],
    }

    def exchange(request, generation=source, bind=True):
        return guest_exchange(record, runtime, request, generation, bind)

    def closed(request):
        try: exchange(request)
        except ConnectionError: return
        raise AssertionError('changed authority intent unexpectedly received acknowledgement')

    token = uuid.uuid4().hex.encode()
    retained, pending, stale, accepted = ['authority-'+uuid.uuid4().hex for _ in range(4)]
    payload = base64.b64encode(token).decode()
    rpc(handle, {'method': 'write_file', 'path': retained, 'data_base64': payload}, 'ok')
    assert exchange({'guest_control': 'info'})['generation'] == source
    try: exchange({'method': 'ping'}, bind=False)
    except ConnectionError: pass
    else: raise AssertionError('unbound native agent frame was accepted')
    assert rpc(handle, {'method': 'ping'})['status'] == 'success'
    report['cases'].append('actual_guest_refuses_unbound_agent_frames_while_generation_bound_source_RPC_remains_usable')

    transfer = {'source_generation': source, 'target_generation': target,
                'barrier': barrier, 'restoration': restoration}
    closed({'guest_control': 'transfer_authority', 'transfer': transfer})
    assert exchange({'guest_control': 'info'})['generation'] == source

    # Establish an actual pre-transition proxy, but withhold its frame terminator
    # so it has not yet acquired guest effect admission.
    with guest_channel(record, runtime) as (channel, reader):
        delayed = guest_frame(record, {'method': 'write_file', 'path': pending, 'data_base64': payload})
        channel.sendall(delayed[:-1])
        receipt = exchange({'guest_control': 'quiesce', 'generation': source, 'barrier': barrier})
        assert receipt == {'protocol': 3, 'generation': source, 'barrier': barrier,
                           'phase': 'quiesced', 'workload_frozen': True, 'rootfs_synced': True}
        applied = exchange({'guest_control': 'transfer_authority', 'transfer': transfer})
        assert applied == {'protocol': 3, 'transfer': transfer, 'phase': 'quiesced', 'workload_frozen': True}, applied
        assert exchange({'guest_control': 'info'})['generation'] == target
        assert exchange({'guest_control': 'transfer_authority', 'transfer': transfer}) == applied
        for changed in [dict(transfer, restoration=str(uuid.uuid4())),
                        dict(transfer, target_generation=str(uuid.uuid4()))]:
            closed({'guest_control': 'transfer_authority', 'transfer': changed})
        closed({'guest_control': 'thaw', 'generation': source, 'barrier': barrier})
        before_thaw = exchange({'method': 'ping'}, generation=target)
        assert before_thaw['status'] == 'error' and before_thaw['data']['code'] == 'invalid_state'
        thawed = exchange({'guest_control': 'thaw', 'generation': target, 'barrier': barrier})
        assert thawed == dict(receipt, generation=target, phase='resumed', workload_frozen=False, rootfs_synced=False)
        assert exchange({'guest_control': 'transfer_authority', 'transfer': transfer}) == dict(applied, phase='resumed', workload_frozen=False)
        channel.sendall(delayed[-1:])
        refused = guest_reply(reader)
        assert refused['status'] == 'error' and refused['data']['code'] == 'invalid_state', refused
    observations['frozen_transfer'] = applied
    observations['target_thaw'] = thawed
    report['cases'].append('actual_frozen_authority_transition_is_idempotent_keeps_workloads_closed_and_refuses_changed_intent_or_old_generation_thaw')

    old = exchange({'method': 'write_file', 'path': stale, 'data_base64': payload})
    assert old['status'] == 'error' and old['data']['code'] == 'invalid_state'
    # The physical native handle still describes the original VMM. Its host
    # client must reject a guest identity that no longer matches that handle.
    host_refusal = call({'operation': 'rpc', 'handle': handle, 'request': {'method': 'ping'}}, expect=False)
    observations['original_native_handle_refusal'] = host_refusal
    written = exchange({'method': 'write_file', 'path': accepted, 'data_base64': payload}, generation=target)
    assert written['status'] == 'success' and written['data']['kind'] == 'ok'
    for name in [retained, accepted]:
        value = exchange({'method': 'read_file', 'path': name, 'max_bytes': 128}, generation=target)
        assert value['status'] == 'success' and value['data']['kind'] == 'file'
        assert base64.b64decode(value['data']['value']['data_base64'], validate=True) == token
    for name in [pending, stale]:
        value = exchange({'method': 'read_file', 'path': name, 'max_bytes': 128}, generation=target)
        assert value['status'] == 'error' and value['data']['code'] == 'not_found', value
    observations['old_or_delayed_effect_paths_absent'] = [pending, stale]
    observations['new_authority_effect_and_original_file_verified'] = [accepted, retained]
    report['cases'].append('actual_delayed_old_frame_and_new_old_generation_RPC_have_no_file_effect_after_thaw_while_target_scoped_RPC_works')

    # Source/capture ownership remains the fixture's original native generation.
    # Rust removal is still authenticated against that unchanged process/root.
    assert call({'operation': 'inspect', 'handle': handle})['state'] == 'running'
