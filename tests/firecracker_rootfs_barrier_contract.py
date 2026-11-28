"""Actual disk-only guest freeze, independent fixture copy and source thaw.

The copy is a test fixture, not the future Rust snapshot store or a cold boot.
Untrusted ext4 parsing is delegated to the isolated source-built Rust inspector.
"""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import time
import uuid

from firecracker_barrier_contract import guest_channel, guest_exchange, guest_frame
from rootfs_inspection_contract import RootfsContract
from image_builder_contract import docker, digest


def sparse_fixture(source, destination, expected_uid):
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_uid == expected_uid and before.st_nlink == 1
        assert 64*1024**2 <= before.st_size <= 16*1024**3
        started = time.monotonic(); total = 0; checksum = hashlib.sha256(); zero = bytes(65536)
        with destination.open('xb') as output:
            while block := os.read(fd, 65536):
                assert time.monotonic()-started < 120
                checksum.update(block); total += len(block)
                assert total <= before.st_size
                if block == zero[:len(block)]: output.seek(len(block), os.SEEK_CUR)
                else: output.write(block)
            output.truncate(total); output.flush(); os.fsync(output.fileno())
        after = os.fstat(fd)
        assert (before.st_dev, before.st_ino, before.st_size, before.st_uid, before.st_nlink) == (after.st_dev, after.st_ino, after.st_size, after.st_uid, after.st_nlink)
        assert total == before.st_size
        content = dict(sha256=checksum.hexdigest(), size_bytes=total)
        assert digest(destination) == content
        copied = destination.stat()
        assert (copied.st_dev, copied.st_ino) != (before.st_dev, before.st_ino)
        return dict(content=content, source_device=before.st_dev, source_inode=before.st_ino,
                    copy_device=copied.st_dev, copy_inode=copied.st_ino)
    finally:
        os.close(fd)


class CapturedDiskInspection(RootfsContract):
    def __init__(self, image, image_owner, source_commit, output, counter):
        args = argparse.Namespace(image=image, image_owner=image_owner, source_commit=source_commit, output=output,
                                  runtime='runsc', allow_runc_development=False, remove_image=False,
                                  owner=None, case=None, preflight=False)
        super().__init__(args)
        self.sources.append(Path(__file__).resolve())
        root = Path(__file__).resolve().parents[1]
        self.source_hashes = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in self.sources}
        self.report['suite'] = 'actual-isolated-inspection-of-frozen-KVM-disk-copy'
        self.ready = False
        self.disk = self.context/'rootfs.ext4'
        assert re.fullmatch(r'rootfs-counter-[0-9a-f]{32}', counter)
        self.counter_path = counter

    def exercise(self):
        assert self.ready, 'independent frozen disk copy is not confirmed'
        actual = json.loads(docker('image', 'inspect', self.args.image))[0]
        assert actual['Config']['Labels']['dev.goldenhoop.task'] == 'm4-image-builder-fixture'
        assert actual['Config']['Labels']['dev.goldenhoop.owner'] == self.args.image_owner
        self.image = actual['Id']; self.report['image_id'] = self.image
        inventory = json.loads(self.inspected(None, '/bin/cat', ['/opt/goldenhoop/rootfs-inventory.json']))
        content = digest(self.disk)
        source = self.volume()
        cid = self.container([], entrypoint='/bin/true', mounts=[(source, '/input', False)])
        packet = self.context/(uuid.uuid4().hex+'-input.tar')
        with tarfile.open(packet, 'w') as output:
            header = output.gettarinfo(str(self.disk), arcname='rootfs.ext4')
            header.uid = header.gid = 0; header.mode = 0o400
            with self.disk.open('rb') as stream: output.addfile(header, stream)
        try:
            with packet.open('rb') as stream: docker('cp', '-', cid+':/input', stdin=stream)
            assert json.loads(docker('inspect', cid))[0]['State']['Status'] == 'created'
        finally:
            self.remove_container(cid)
        request = dict(generation=str(uuid.uuid4()), disk=content, agent=inventory['agent'], init=inventory['init'],
                       guest=dict(control_port=52, pids=256))
        found = self.inspect(source, request)
        assert found['passed'], found
        assert found['inspection']['inventory'] == inventory and found['inspection']['disk'] == content
        assert digest(self.disk) == content and self.disk_content(source) == content
        captured = self.inspected(source, '/usr/sbin/debugfs', ['-R', 'cat /workspace/'+self.counter_path, '/output/rootfs.ext4'])
        assert 0 < len(captured) <= 128 and captured.isdigit(), captured[:128]
        self.report['observations']['captured_counter'] = int(captured)
        self.report['observations']['inspection'] = found['inspection']
        self.report['cases'].append('actual_frozen_KVM_disk_passes_clean_ext4_and_pinned_boot_asset_inspection_in_runsc')
        self.report['result'] = 'passed'


def exercise(handle, record, runtime, call, rpc, command, report, inspector_image, inspector_owner, source_commit, fixture):
    generation = record['owner']['generation']
    disk = runtime/'j/firecracker'/generation/'root/rootfs.ext4'
    observations = report['observations']['rootfs_barrier'] = dict(generation=generation)
    def control(kind, token, identity=generation):
        return guest_exchange(record, runtime, dict(guest_control=kind, generation=identity, barrier=token))
    def refused(request):
        try: guest_exchange(record, runtime, request)
        except ConnectionError: return
        raise AssertionError('foreign or spent rootfs authority received an acknowledgement')
    def superblock():
        fd = os.open(disk, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            metadata = os.fstat(fd)
            assert stat.S_ISREG(metadata.st_mode) and metadata.st_uid == record['process']['uid']
            value = os.pread(fd, 1024, 1024)
            assert len(value) == 1024 and value[0x38:0x3a] == b'\x53\xef'
            return dict(state=int.from_bytes(value[0x3a:0x3c], 'little'), flags=int.from_bytes(value[0x60:0x64], 'little'))
        finally: os.close(fd)
    def frozen_receipt(value, token):
        assert value['protocol'] == 3 and value['format'] == 1 and value['generation'] == generation and value['barrier'] == token
        assert value['phase'] == 'quiesced' and value['workload_frozen'] and value['filesystem'] == 'frozen' and not value['thaw_started'], value
        assert value['root']['device'] > 0 and value['root']['inode'] == 2 and value['root']['mount_id'] > 0
        assert superblock()['state'] == 1 and not superblock()['flags'] & 4

    token = str(uuid.uuid4())
    for identity, operation in [(str(uuid.uuid4()), token), (generation, str(uuid.UUID(int=0)))]:
        refused(dict(guest_control='rootfs_quiesce', generation=identity, barrier=operation))
    assert rpc(handle, {'method': 'ping'})['status'] == 'success'
    observations['mounted_before_capture'] = superblock()
    assert observations['mounted_before_capture']['flags'] & 4
    report['cases'].append('rootfs_wrong_generation_and_nil_operation_refused_before_filesystem_effects')

    counter = 'rootfs-counter-'+uuid.uuid4().hex
    execution = str(uuid.uuid4())
    script = ("import os,time;from pathlib import Path;"+f"p=Path({counter!r});q=Path({(counter+'-pending')!r})\n"
              "for i in range(10000):\n"
              " with q.open('w') as f:f.write(str(i));f.flush();os.fsync(f.fileno())\n"
              " os.replace(q,p);time.sleep(.02)\n")
    rpc(handle, dict(method='start', id=execution, command=dict(argv=['python3', '-c', script], timeout_seconds=180, max_output_bytes=128)), 'execution')
    deadline = time.monotonic()+15
    while True:
        answer = rpc(handle, dict(method='read_file', path=counter, max_bytes=128))
        if answer['status'] == 'success': break
        assert answer['data']['code'] == 'not_found' and time.monotonic() < deadline
        time.sleep(.02)
    receipt = control('rootfs_quiesce', token); frozen_receipt(receipt, token)
    assert control('rootfs_status', token) == receipt and control('rootfs_quiesce', token) == receipt
    observations['frozen'] = receipt; observations['clean_superblock'] = superblock()
    report['cases'].append('actual_original_ext4_descriptor_freeze_clears_recovery_and_exact_retry_keeps_ownership')
    for kind in ['quiesce', 'thaw', 'rootfs_thaw']:
        refused(dict(guest_control=kind, generation=generation, barrier=str(uuid.uuid4())))
    refused(dict(guest_control='quiesce', generation=generation, barrier=token))
    assert control('rootfs_status', token) == receipt
    blocked = rpc(handle, dict(method='write_file', path=counter+'-late', data_base64='YQ=='))
    assert blocked['status'] == 'error' and blocked['data']['code'] == 'invalid_state'
    report['cases'].append('active_rootfs_fences_memory_barriers_foreign_thaw_and_new_workload_effects')

    inspector = CapturedDiskInspection(inspector_image, inspector_owner, source_commit, fixture/'rootfs-inspection.json', counter)
    inspected = False
    try:
        call(dict(operation='pause', handle=handle))
        assert call(dict(operation='inspect', handle=handle))['state'] == 'paused'
        copied = sparse_fixture(disk, inspector.disk, record['process']['uid'])
        observations['independent_copy'] = copied
        call(dict(operation='resume', handle=handle))
        assert control('rootfs_status', token) == receipt
        thawed = control('rootfs_thaw', token)
        assert thawed == dict(receipt, phase='resumed', workload_frozen=False, filesystem='thawed', thaw_started=True), thawed
        assert control('rootfs_thaw', token) == thawed
        refused(dict(guest_control='rootfs_quiesce', generation=generation, barrier=token))
        refused(dict(guest_control='quiesce', generation=generation, barrier=token))
        assert superblock()['flags'] & 4
        observations['resumed'] = thawed
        assert rpc(handle, dict(method='inspect', id=execution), 'execution')['state'] == 'running'
        first = int(base64.b64decode(rpc(handle, dict(method='read_file', path=counter, max_bytes=128), 'file')['data_base64'], validate=True))
        deadline = time.monotonic()+10
        while True:
            current = int(base64.b64decode(rpc(handle, dict(method='read_file', path=counter, max_bytes=128), 'file')['data_base64'], validate=True))
            if current > first: break
            assert time.monotonic() < deadline
            time.sleep(.02)
        assert digest(inspector.disk) == copied['content']
        observations['continued_counter'] = dict(first=first, later=current, execution=execution)
        report['cases'].append('explicit_filesystem_then_workload_thaw_resumes_same_command_and_preserves_independent_copy')
        inspector.ready = True
        inspected = True
        result = inspector.run()
        isolated = json.loads(inspector.args.output.read_bytes())
        observations['isolated_inspection'] = isolated
        assert result == 0 and isolated['result'] == 'passed' and isolated['cleanup'] == 'complete', isolated.get('error')
        after_inspection = int(base64.b64decode(rpc(handle, dict(method='read_file', path=counter, max_bytes=128), 'file')['data_base64'], validate=True))
        assert after_inspection > isolated['observations']['captured_counter']
        observations['source_counter_after_isolated_copy_check'] = after_inspection
        report['cases'].append('independent_live_source_copy_is_clean_and_boot_assets_verified_by_actual_runsc_inspector')
    finally:
        if not inspected: inspector.run()
    rpc(handle, dict(method='cancel', id=execution), 'execution')
    deadline = time.monotonic()+20
    while True:
        cancelled = rpc(handle, dict(method='inspect', id=execution), 'execution')
        assert cancelled['id'] == execution, cancelled
        if cancelled['state'] == 'cancelled' and cancelled['cleanup'] == 'complete': break
        assert time.monotonic() < deadline, cancelled
        time.sleep(.05)
    observations['original_counter_after_cancel'] = cancelled

    memory = str(uuid.uuid4())
    mem_receipt = control('quiesce', memory)
    assert mem_receipt['phase'] == 'quiesced' and superblock()['flags'] & 4
    deferred = str(uuid.uuid4())
    refused(dict(guest_control='rootfs_quiesce', generation=generation, barrier=deferred))
    assert control('barrier_status', memory) == mem_receipt
    assert control('thaw', memory)['phase'] == 'resumed'
    report['cases'].append('sync_only_memory_barrier_remains_distinct_and_blocks_rootfs_freeze_until_thawed')

    lost = deferred
    with guest_channel(record, runtime) as (stream, _):
        stream.sendall(guest_frame(record, dict(guest_control='rootfs_quiesce', generation=generation, barrier=lost)))
    deadline = time.monotonic()+15
    while True:
        try:
            original = control('rootfs_status', lost)
            if original['phase'] == 'quiesced': break
        except ConnectionError: pass
        assert time.monotonic() < deadline
        time.sleep(.02)
    frozen_receipt(original, lost)
    with guest_channel(record, runtime) as (stream, _):
        stream.sendall(guest_frame(record, dict(guest_control='rootfs_thaw', generation=generation, barrier=lost)))
    deadline = time.monotonic()+15
    while True:
        current = control('rootfs_status', lost)
        if current['phase'] == 'resumed': break
        assert time.monotonic() < deadline
        time.sleep(.02)
    assert current['filesystem'] == 'thawed' and current['thaw_started']
    refused(dict(guest_control='rootfs_quiesce', generation=generation, barrier=lost))
    assert rpc(handle, dict(method='ping'))['status'] == 'success'
    observations['lost_reply_original_barrier'] = dict(frozen=original, resumed=current)
    report['cases'].append('lost_freeze_and_thaw_replies_reconcile_original_operation_without_implicit_resume_or_refreeze')
