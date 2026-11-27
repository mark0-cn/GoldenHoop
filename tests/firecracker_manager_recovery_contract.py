"""Actual KVM manager death/reconnect through the existing public SDK.

Python supplies controlled faults and observations only. Rust owns manager
recovery, VMM/guest control, lifetime enforcement and resource collection.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import time
import uuid

from goldenhoop import ApiError, Command


def exercise(native, cfg, config, root, manager, client, sid, complete, observed=None):
    cases = []
    observed = {} if observed is None else observed
    observed['checks_completed'] = cases
    marker, stored_config = root/'manager.json', root/'config.json'
    record_path = root/'records'/f'{sid}.json'
    assert str(uuid.UUID(sid)) == sid and root == Path(cfg['data_root'])

    def record():
        value = json.loads(record_path.read_bytes())
        assert value['owner']['installation_id'] == cfg['installation_id'] and value['owner']['sandbox_id'] == sid
        return value

    def identity(path):
        value = path.lstat()
        return dict(device=value.st_dev, inode=value.st_ino)

    def control_snapshot():
        owner = json.loads(marker.read_bytes())
        return dict(marker_sha256=hashlib.sha256(marker.read_bytes()).hexdigest(),
                    config_sha256=hashlib.sha256(stored_config.read_bytes()).hexdigest(),
                    socket=identity(root/'manager.sock'), cgroup=identity(Path(owner['cgroup'])))

    def refused(path):
        before = control_snapshot()
        result = subprocess.run([str(native),'manage','--config',str(path)], capture_output=True,
                                timeout=12, env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
        assert result.returncode != 0, 'invalid manager startup was accepted'
        assert control_snapshot() == before, 'rejected startup mutated owned/foreign control state'
        return dict(exit_code=result.returncode, stderr=result.stderr.decode(errors='replace')[-2048:], preserved=before)

    def call(value, expect=True):
        path = config.with_name('manager-recovery-request.json')
        path.write_text(json.dumps(value)); path.chmod(0o600)
        result = subprocess.run([str(native),'driver-call','--config',str(config),'--request',str(path)],
                                capture_output=True, timeout=240,
                                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
        answer = json.loads(result.stdout)
        assert answer['ok'] is expect and result.returncode == (0 if expect else 2), (answer,result.stderr[-2048:])
        return answer['data'] if expect else answer['error']

    def same_processes(before):
        after = manager.observe(before)
        for role in ['process','supervisor']:
            value = after['processes'][role]
            assert value['present'] and value['identity_start_matches'] and value['state'] not in ['Z','X','x'], after
        now = record()
        assert now['owner'] == before['owner'] and now['process'] == before['process']
        return after

    def replace_record(value):
        # Atomic fixture injection avoids exposing a partial JSON record to the
        # running worker. Never overwrite another generation or unlink by name.
        assert record()['owner'] == value['owner']
        temporary = record_path.with_name('.'+uuid.uuid4().hex+'.fixture')
        descriptor = os.open(temporary, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
        owned = os.fstat(descriptor)
        try:
            with os.fdopen(descriptor,'wb') as output:
                output.write(json.dumps(value).encode()); output.flush(); os.fsync(output.fileno())
            os.replace(temporary, record_path)
            directory = os.open(record_path.parent, os.O_RDONLY|os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if temporary.exists():
                current = temporary.lstat()
                assert (current.st_dev,current.st_ino)==(owned.st_dev,owned.st_ino) and stat.S_ISREG(current.st_mode)
                temporary.unlink()

    nonce = uuid.uuid4().hex
    ready, release, once = 'manager-ready-'+nonce, 'manager-release-'+nonce, 'manager-once-'+nonce
    script = ("from pathlib import Path; import os,time; r=Path('/workspace'); "
              f"(r/{ready!r}).write_text(str(os.getpid())); release=r/{release!r}\n"
              "while not release.exists(): time.sleep(.05)\n"
              f"with (r/{once!r}).open('a') as output: output.write('once')\n"
              "print('manager-once',end='')")
    command = Command(['python3','-c',script], timeout_seconds=160, max_output_bytes=4096)
    key = str(uuid.uuid4())
    execution = client.start(sid, command, key)
    until = time.monotonic()+25
    while client.execution(execution['id'])['state'] != 'running':
        assert time.monotonic() < until, 'guest command did not start before manager fault'
        time.sleep(.05)
    # A running host record is insufficient: require an actual guest file.
    while True:
        try:
            ready_bytes = client.read_file(sid, ready)
            break
        except ApiError:
            assert time.monotonic() < until
            time.sleep(.05)
    assert int(ready_bytes) > 1
    before = record()
    observed['before_fault'] = dict(journal=before, kernel=manager.observe(before), guest_pid=int(ready_bytes))
    observed['live_owner_refusal'] = refused(config)
    assert manager.process.poll() is None
    cases.append('actual_live_manager_excludes_duplicate_owner_before_control_or_configuration_mutation')

    death = manager.hard_kill()
    observed['first_actual_manager_death'] = death
    observed['kernel_with_manager_absent'] = same_processes(before)
    try:
        client.read_file(sid, ready)
    except ApiError as error:
        assert error.code in ['backend_unavailable','invalid_state'], error
        observed['public_refusal_during_outage'] = error.code
    else:
        raise AssertionError('guest dispatch succeeded through a dead manager')

    changed = copy.deepcopy(cfg); changed['capacity']['cpu_millis'] += 1
    changed_path = config.with_name('manager-recovery-changed.json')
    changed_path.write_text(json.dumps(changed)); changed_path.chmod(0o600)
    observed['changed_config_refusal'] = refused(changed_path)
    same_processes(before)
    cases.append('killed_manager_rejects_changed_configuration_without_mutating_original_inventory_or_guest')

    endpoint = root/'manager.sock'; backup = root/'manager-owned-backup.sock'
    old_socket = identity(endpoint)
    assert old_socket == death['owner']['socket_identity']
    endpoint.rename(backup)
    foreign = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    foreign_identity = None
    try:
        foreign.bind(str(endpoint)); endpoint.chmod(0o600); foreign.listen(1)
        foreign_identity = identity(endpoint)
        assert foreign_identity != old_socket
        observed['foreign_socket_refusal'] = refused(config)
        assert identity(endpoint) == foreign_identity
    finally:
        foreign.close()
        if foreign_identity:
            assert identity(endpoint)==foreign_identity and stat.S_ISSOCK(endpoint.lstat().st_mode)
            endpoint.unlink()
        assert identity(backup)==old_socket and not endpoint.exists()
        backup.rename(endpoint)
    cases.append('replacement_socket_inode_is_refused_and_preserved_before_owned_endpoint_restoration')

    group = Path(death['owner']['cgroup'])
    suffix = uuid.UUID(cfg['installation_id']).hex+'-'+uuid.UUID(death['owner']['epoch']).hex
    assert group == Path('/sys/fs/cgroup')/('ghm-'+suffix)
    old_group = identity(group)
    assert old_group == death['owner']['cgroup_identity']
    assert 'populated 0' in (group/'cgroup.events').read_text().splitlines()
    # cgroup v2 has no rename operation. Collect only the recorded empty
    # fixture group, then create a genuinely different kernel object at its
    # path. Keep its descriptor pinned while checking replacement identity.
    old_descriptor = os.open(group, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    pinned = os.fstat(old_descriptor)
    assert old_group == dict(device=pinned.st_dev,inode=pinned.st_ino)
    foreign_group = None
    try:
        assert identity(group)==old_group
        group.rmdir()
        observed['owned_old_empty_cgroup_collection'] = dict(identity=old_group,absent=not group.exists())
        assert not group.exists()
        group.mkdir()
        foreign_group = identity(group)
        assert foreign_group != old_group
        observed['foreign_cgroup_refusal'] = refused(config)
        assert identity(group)==foreign_group
    finally:
        try:
            if foreign_group:
                assert identity(group)==foreign_group and 'populated 0' in (group/'cgroup.events').read_text().splitlines()
                group.rmdir()
        finally:
            os.close(old_descriptor)
    assert not group.exists()
    same_processes(before)
    cases.append('replacement_empty_cgroup_inode_is_refused_and_preserved_without_signalling_processes')

    # Explicitly labeled metadata fault: this is not a claimed real PID reuse.
    changed_record = copy.deepcopy(before)
    changed_record['supervisor']['start_ticks'] += 1
    observed['supervisor_identity_fixture_fault'] = dict(field='supervisor.start_ticks',
                                                       original=before['supervisor'], injected=changed_record['supervisor'])
    replace_record(changed_record)
    try:
        new_owner = manager.start()
        assert new_owner['epoch'] != death['owner']['epoch']
        assert new_owner['recovery']['previous_process'] == death['owner']['process']
        entry = next(item for item in new_owner['recovery']['generations'] if item['sandbox_id']==sid)
        assert not entry['authenticated'] and entry['observed_state']=='unknown'
        observed['unconfirmed_generation'] = entry
        error = call({'operation':'inspect','handle':{'sandbox_id':sid,'profile':'local-firecracker',
                      'backend_ref':f"fc1:{cfg['installation_id']}:{before['owner']['generation']}"}},expect=False)
        assert error['code']=='backend_unavailable', error
        assert manager.process.poll() is None
        same_processes(before)
        # Exercise a different real generation while this one is still
        # unconfirmed; the pending reservation must remain in quota accounting.
        profile = call({'operation':'probe'})
        assert profile['availability']=='available'
        observed['actual_probe_with_unconfirmed_generation'] = profile
    finally:
        current = record()
        assert current['supervisor'] in [before['supervisor'], changed_record['supervisor']]
        current['supervisor'] = before['supervisor']
        replace_record(current)
    cases.append('changed_supervisor_identity_stays_unconfirmed_without_VM_restart_or_installation_wide_shutdown')

    handle={'sandbox_id':sid,'profile':'local-firecracker','backend_ref':f"fc1:{cfg['installation_id']}:{before['owner']['generation']}"}
    assert call({'operation':'inspect','handle':handle})['state']=='running'
    until = time.monotonic()+20
    while client.sandbox(sid)['state'] != 'running':
        assert time.monotonic()<until
        time.sleep(.1)
    assert client.start(sid,command,key)['id']==execution['id']
    assert client.read_file(sid,ready)==ready_bytes
    client.write_file(sid,release,b'release')
    result=client.wait_execution(execution['id'])
    assert result['state']=='succeeded' and result['exit_code']==0 and result['cleanup']=='complete',result
    assert client.read_file(sid,once)==b'once'
    observed['running_reconnected'] = dict(owner=manager.owner, kernel=same_processes(before),execution=result,
                                         guest_pid=int(client.read_file(sid,ready)))
    assert observed['running_reconnected']['kernel']['processes']['supervisor']['parent_pid'] != manager.process.pid
    cases.append('actual_manager_SIGKILL_recovers_same_VM_and_running_public_execution_once_with_nonchild_supervisor')

    stale = dict(installation_id=cfg['installation_id'],epoch=death['owner']['epoch'],
                 config_sha256=death['owner']['config_sha256'],operation={'method':'shutdown'})
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as stream:
        stream.settimeout(3); stream.connect(str(endpoint)); stream.sendall(json.dumps(stale).encode()+b'\n')
        try:
            answer=stream.recv(65536)
        except ConnectionResetError:
            answer=b''
        assert not answer, 'stale manager epoch received an accepted reply'
    assert manager.process.poll() is None
    assert call({'operation':'inspect','handle':handle})['state']=='running'
    cases.append('stale_manager_epoch_cannot_shutdown_the_replacement_service')

    complete(client.pause(sid,str(uuid.uuid4())))
    paused = record()
    assert paused['phase']=='paused'
    second = manager.hard_kill(); owner = manager.start()
    entry = next(item for item in owner['recovery']['generations'] if item['sandbox_id']==sid)
    assert entry['authenticated'] and entry['observed_state']=='paused',entry
    assert call({'operation':'inspect','handle':handle})['state']=='paused'
    assert record()['supervisor']==before['supervisor']
    observed['paused_reconnected'] = dict(death=second,owner=owner,kernel=same_processes(paused))
    assert not Path(second['owner']['cgroup']).exists()
    # The native listener's Ready and private Paused observation do not prove
    # that the independent worker has repaired its durable public projection.
    # Wait for the actual public state before issuing a new live-state request.
    until = time.monotonic()+25
    transitions = observed['paused_public_projection'] = []
    while True:
        public = client.sandbox(sid)
        if not transitions or transitions[-1]!=public:
            transitions.append(public);del transitions[:-32]
        assert public['desired_state']=='paused',public
        assert public['state'] not in ['failed','stopping','terminated'],public
        if public['state']=='paused':
            break
        assert time.monotonic()<until,f'public paused recovery deadline: {public}'
        time.sleep(.1)
    assert call({'operation':'inspect','handle':handle})['state']=='paused'
    complete(client.resume(sid,str(uuid.uuid4())))
    assert client.read_file(sid,once)==b'once' and client.read_file(sid,ready)==ready_bytes
    cases.append('paused_VM_survives_second_manager_SIGKILL_without_automatic_resume_or_identity_change')
    return cases, observed
