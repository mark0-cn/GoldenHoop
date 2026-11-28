"""Actual Rust manager-owned capture/recovery; Python constructs and asserts.

Disk production, guest/VMM control and persistent ownership are Rust. The
isolated inspector parent below remains a test fixture, not product transport.
"""
import base64
import hashlib
import io
import json
from pathlib import Path
import signal
import stat
import subprocess
import tarfile
import time
import uuid

from firecracker_barrier_contract import guest_exchange
from firecracker_rootfs_barrier_contract import CapturedDiskInspection
from image_builder_contract import docker, digest


def policy(image, owner, disk_bytes, inspector_parent=False):
    actual = json.loads(docker('image', 'inspect', image))[0]
    assert actual['Config']['Labels']['dev.goldenhoop.owner'] == owner
    assert actual['Config']['Labels']['dev.goldenhoop.task'] == 'm4-image-builder-fixture'
    cid = docker('create', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                 '--label', 'dev.goldenhoop.task=m4-rootfs-policy-fixture',
                 '--label', 'dev.goldenhoop.owner='+owner, '--entrypoint', '/bin/true', actual['Id']).decode().strip()
    try:
        archive = docker('cp', cid+':/opt/goldenhoop/rootfs-inventory.json', '-')
        assert len(archive) <= 1024*1024
        with tarfile.open(fileobj=io.BytesIO(archive)) as packet:
            files = packet.getmembers()
            assert len(files) == 1 and files[0].isfile() and files[0].name == 'rootfs-inventory.json'
            assert 0 < files[0].size <= 65536
            inventory = json.loads(packet.extractfile(files[0]).read())
        assert json.loads(docker('inspect', cid))[0]['State']['Status'] == 'created'
    finally:
        value = json.loads(docker('inspect', cid))[0]
        assert value['Config']['Labels']['dev.goldenhoop.owner'] == owner and value['State']['Status'] == 'created'
        docker('rm', cid)
        assert cid not in docker('ps', '-aq', '--no-trunc').decode().splitlines()
    # Pin trusted build input, never a self-selected value read from the disk.
    config = (Path(__file__).resolve().parents[1]/'images/microvm/guest.json').read_bytes()
    result = dict(store=dict(max_bytes=3*disk_bytes, max_captures=3), inventory=inventory,
                  guest=json.loads(config), guest_config=dict(sha256=hashlib.sha256(config).hexdigest(), size_bytes=len(config)))
    if inspector_parent:
        result['inspector_image'] = actual['Id']
    return result


def exercise(handle, initial, runtime, cfg, manager, call, rpc, record, report,
             inspector_image, inspector_owner, source_commit, fixture, inspector_parent=False):
    root = Path(cfg['data_root'])/'rootfs'
    generation = initial['owner']['generation']
    seen = report['observations']['rootfs_producer'] = dict(generation=generation)
    def meta(capture):
        return json.loads((root/f'capture-{capture}.json').read_bytes())
    def read_counter(name):
        value = rpc(handle, dict(method='read_file', path=name, max_bytes=128), 'file')
        return int(base64.b64decode(value['data_base64'], validate=True))
    counter = 'rootfs-counter-'+uuid.uuid4().hex
    execution = str(uuid.uuid4())
    script = ("import os,time;from pathlib import Path;"+f"p=Path({counter!r});q=Path({(counter+'-pending')!r})\n"
              "for i in range(100000):\n"
              " with q.open('w') as f:f.write(str(i));f.flush();os.fsync(f.fileno())\n"
              " os.replace(q,p);time.sleep(.02)\n")
    rpc(handle, dict(method='start', id=execution, command=dict(argv=['python3', '-c', script], timeout_seconds=290, max_output_bytes=128)), 'execution')
    deadline = time.monotonic()+15
    while True:
        answer = rpc(handle, dict(method='read_file', path=counter, max_bytes=128))
        if answer['status'] == 'success': break
        assert answer['data']['code'] == 'not_found' and time.monotonic() < deadline
        time.sleep(.02)
    nil = str(uuid.UUID(int=0))
    refused = call(dict(operation='rootfs_capture', handle=handle, capture=nil), expect=False)
    assert refused['code'] == 'invalid_request' and not (root/f'capture-{nil}.json').exists()
    assert rpc(handle, dict(method='inspect', id=execution), 'execution')['state'] == 'running'
    report['cases'].append('rootfs_nil_capture_refused_before_source_or_store_effects')
    unused = str(uuid.uuid4())
    closed = guest_exchange(initial, runtime, dict(guest_control='rootfs_thaw', generation=generation, barrier=unused))
    assert closed['phase'] == 'resumed' and closed['filesystem'] == 'not_dispatched' and closed['root'] is None
    assert closed['thaw_started'] and not closed['workload_frozen']
    assert guest_exchange(initial, runtime, dict(guest_control='rootfs_status', generation=generation, barrier=unused)) == closed
    try:
        guest_exchange(initial, runtime, dict(guest_control='rootfs_quiesce', generation=generation, barrier=unused))
    except ConnectionError:
        pass
    else:
        raise AssertionError('closed unused rootfs operation refroze the source')
    seen['unused_operation_closed'] = closed
    report['cases'].append('actual_unused_rootfs_operation_closes_without_filesystem_thaw_and_cannot_refreeze')

    # Kill the actual producer process at a durable Capturing boundary. Reuse
    # the original supervisor/VMM and operation; do not restart disk capture.
    interrupted = str(uuid.uuid4())
    call(dict(operation='rootfs_capture', handle=handle, capture=interrupted))
    deadline = time.monotonic()+20
    while True:
        current = meta(interrupted)
        if current['phase'] == 'capturing' and current['vm_control']['pause_observed']: break
        assert current['phase'] in ['reserved', 'capturing'] and time.monotonic() < deadline, current['phase']
        time.sleep(.002)
    old_writer = current['source_writer']
    death = manager.hard_kill()
    assert death['actual_process_absent'] and death['exit_status'] == -signal.SIGKILL
    manager.start()
    assert record(handle['sandbox_id'])['rootfs_hold'] == interrupted
    for operation in ['pause', 'resume']:
        refused = call(dict(operation=operation, handle=handle), expect=False)
        assert refused['code'] == 'invalid_state', refused
    refused = call(dict(operation='rpc', handle=handle, request=dict(method='ping')), expect=False)
    assert refused['code'] == 'invalid_state'
    assert record(handle['sandbox_id'])['rootfs_hold'] == interrupted
    report['cases'].append('actual_durable_rootfs_hold_blocks_pause_resume_and_workload_dispatch_after_manager_death')
    call(dict(operation='rootfs_capture', handle=handle, capture=interrupted))
    deadline = time.monotonic()+45
    while True:
        status = call(dict(operation='rootfs_inspect', handle=handle, capture=interrupted))
        after = record(handle['sandbox_id'])
        seen['producer_recovery_poll'] = dict(status=status, source=after)
        assert after['owner'] == initial['owner'], after
        assert after['process'] == initial['process'] and after['supervisor'] == initial['supervisor'], after
        if status['source_resumed'] and status['producer_settled'] and not after.get('rootfs_hold'): break
        assert time.monotonic() < deadline, status
        time.sleep(.05)
    assert status['phase'] == 'failed' and status['reference'] is None
    after = record(handle['sandbox_id'])
    assert not after.get('rootfs_hold') and after['owner'] == initial['owner'], after
    assert after['process'] == initial['process'] and after['supervisor'] == initial['supervisor']
    assert meta(interrupted)['source_writer'] == old_writer
    assert rpc(handle, dict(method='inspect', id=execution), 'execution')['state'] == 'running'
    seen['producer_kill'] = dict(death=death, recovered_status=status, original_writer=old_writer)
    assert call(dict(operation='rootfs_capture', handle=handle, capture=interrupted))['phase'] == 'failed'
    call(dict(operation='rootfs_collect', handle=handle, capture=interrupted))
    assert call(dict(operation='rootfs_inspect', handle=handle, capture=interrupted))['reserved_bytes'] == 0
    report['cases'].append('SIGKILL_original_rootfs_producer_recovers_same_source_without_replaying_incomplete_capture')

    capture = str(uuid.uuid4())
    call(dict(operation='rootfs_capture', handle=handle, capture=capture))
    deadline = time.monotonic()+80
    while True:
        status = call(dict(operation='rootfs_inspect', handle=handle, capture=capture))
        assert status['phase'] != 'failed', status
        if status['phase'] == 'captured' and status['source_resumed'] and status['producer_settled']: break
        assert time.monotonic() < deadline, status
        time.sleep(.05)
    data = meta(capture)
    assert data['format'] == 2 and data['resumed']['phase'] == 'resumed'
    assert data['resumed']['filesystem'] == 'thawed' and data['resumed']['thaw_started']
    assert data['manifest']['barrier']['filesystem'] == 'frozen' and not data['manifest']['barrier']['thaw_started']
    assert data['inspection'] is None and not status['inspection_verified']
    disk = root/f'capture-{capture}.disk'
    original_disk = runtime/'j/firecracker'/generation/'root/rootfs.ext4'
    left, right = original_disk.stat(), disk.stat()
    assert stat.S_ISREG(right.st_mode) and right.st_uid == 0 and stat.S_IMODE(right.st_mode) == 0o400 and right.st_nlink == 1
    assert (left.st_dev,left.st_ino) != (right.st_dev,right.st_ino)
    assert digest(disk) == data['manifest']['disk']
    assert data['source_disk']['uid'] == initial['process']['uid'] and data['source_disk']['bytes'] == left.st_size
    assert (data['source_disk']['identity']['device'],data['source_disk']['identity']['inode']) == (left.st_dev,left.st_ino)
    assert call(dict(operation='rootfs_capture', handle=handle, capture=capture)) == status
    assert meta(capture)['manifest'] == data['manifest']
    first = read_counter(counter)
    deadline = time.monotonic()+10
    while read_counter(counter) <= first:
        assert time.monotonic() < deadline
        time.sleep(.02)
    assert digest(disk) == data['manifest']['disk']
    assert record(handle['sandbox_id'])['process'] == initial['process']
    seen['captured'] = dict(status=status, manifest=data['manifest'], resumed=data['resumed'], source_disk=data['source_disk'])
    report['cases'].append('actual_Rust_capture_freezes_pauses_publishes_independent_disk_and_explicitly_recovers_original_source')
    report['cases'].append('rootfs_exact_retry_does_not_refreeze_or_replace_the_original_published_content')

    if inspector_parent:
        from firecracker_rootfs_inspector_parent_contract import exercise as parent_exercise
        parent_exercise(handle, capture, cfg, manager, call, rpc, record, report)
    inspector = CapturedDiskInspection(inspector_image, inspector_owner, source_commit, fixture/'rootfs-producer-inspection.json', counter)
    inspector.sources.append(Path(__file__).resolve())
    project = Path(__file__).resolve().parents[1]
    inspector.source_hashes = {p.relative_to(project).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in inspector.sources}
    inspector.disk = disk
    inspector.ready = True
    outcome = inspector.run()
    isolated = json.loads(inspector.args.output.read_bytes())
    seen['isolated_inspection'] = isolated
    assert outcome == 0 and isolated['result'] == 'passed' and isolated['cleanup'] == 'complete'
    assert isolated['observations']['inspection']['disk'] == data['manifest']['disk']
    assert isolated['observations']['inspection']['agent']['content'] == cfg['rootfs']['inventory']['agent']
    assert isolated['observations']['inspection']['init']['content'] == cfg['rootfs']['inventory']['init']
    assert isolated['observations']['inspection']['guest_config']['content'] == cfg['rootfs']['guest_config']
    later = read_counter(counter)
    assert later > isolated['observations']['captured_counter'] and digest(disk) == data['manifest']['disk']
    seen['continued_counter'] = dict(captured=isolated['observations']['captured_counter'], later=later, execution=execution)
    report['cases'].append('Rust_published_disk_is_clean_and_pinned_assets_and_copied_counter_pass_actual_runsc_inspection')

    rpc(handle, dict(method='cancel', id=execution), 'execution')
    deadline = time.monotonic()+20
    while True:
        cancelled = rpc(handle, dict(method='inspect', id=execution), 'execution')
        if cancelled['state'] == 'cancelled' and cancelled['cleanup'] == 'complete': break
        assert time.monotonic() < deadline, cancelled
        time.sleep(.05)
    seen['original_execution_collected'] = cancelled
    call(dict(operation='rootfs_collect', handle=handle, capture=capture))
    assert not disk.exists()
    assert call(dict(operation='rootfs_inspect', handle=handle, capture=capture))['reserved_bytes'] == 0
    assert call(dict(operation='rootfs_capture', handle=handle, capture=capture))['phase'] == 'collected'
    assert rpc(handle, {'method':'ping'})['status'] == 'success'
    seen['independent_objects_absent'] = True
    report['cases'].append('rootfs_positive_independent_object_collection_releases_quota_while_source_stays_live_and_spent_id_stays_closed')
