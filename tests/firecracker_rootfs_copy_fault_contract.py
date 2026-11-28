"""Observe actual original manager/supervisor death during a partial Rust disk copy."""
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import uuid


def _start(value, manager):
    path=manager.root/('rootfs-copy-call-'+uuid.uuid4().hex+'.json')
    path.write_text(json.dumps(value),encoding='utf-8');path.chmod(0o600)
    process=subprocess.Popen([str(manager.binary),'driver-call','--config',str(manager.config),
                              '--request',str(path)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    return process,path


def _stopped_partial(value,manager,record,seen):
    sid=value['boot']['sandbox']['id'];deadline=time.monotonic()+40
    while True:
        path=manager.root/'records'/f'{sid}.json'
        if path.exists():
            native=record(sid)
            jobpath=manager.root/'rootfs'/f'boot-{sid}.json'
            if native.get('supervisor') and native['phase']=='preparing' and jobpath.exists():
                job=json.loads(jobpath.read_bytes());disk=Path(native['artifacts']['rootfs']['path'])
                expected=native['artifacts']['rootfs']['size']
                if job['dispatched'] and job['copy'] is None and disk.exists() and 0<disk.stat().st_size<expected:
                    manager.assert_parent(native)
                    supervisor=native['supervisor'];pid=supervisor['pid'];descriptor=os.pidfd_open(pid)
                    try:
                        raw=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
                        assert int(raw[19])==supervisor['start_ticks'] and Path(f'/proc/{pid}').stat().st_uid==0
                        assert supervisor['executable_sha256']==manager.cfg['supervisor']['sha256']
                        signal.pidfd_send_signal(descriptor,signal.SIGSTOP)
                        stopped_until=time.monotonic()+5
                        while Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()[0] not in ['T','t']:
                            assert time.monotonic()<stopped_until;time.sleep(.001)
                        durable=json.loads(jobpath.read_bytes());native=record(sid)
                        size=disk.stat().st_size
                        assert durable['dispatched'] and durable['copy'] is None
                        assert 0<size<expected, 'the actual partial-copy cut was missed'
                        assert native['phase']=='preparing' and native.get('vm_root') and not native.get('process')
                        seen.update(native_at_stop=native,reference_at_stop=durable,actual_partial_bytes=size,expected_bytes=expected,
                                    actual_supervisor_stopped=True,stopped_pid=pid)
                        return descriptor,native,durable
                    except BaseException:
                        try:signal.pidfd_send_signal(descriptor,signal.SIGCONT)
                        except ProcessLookupError:pass
                        os.close(descriptor);raise
        assert time.monotonic()<deadline,'did not observe the original partial rootfs copy'
        time.sleep(.001)


def _finish_client(process):
    stdout,stderr=process.communicate(timeout=45)
    answer=json.loads(stdout)
    assert process.returncode==(0 if answer['ok'] else 2),(process.returncode,answer,stderr[-2000:])
    return answer


def _resume_and_collect_caller(descriptor,process):
    if descriptor is not None:
        try:signal.pidfd_send_signal(descriptor,signal.SIGCONT)
        except ProcessLookupError:pass
        finally:os.close(descriptor)
    if process.poll() is None:
        process.kill();process.communicate(timeout=10)


def boot_with_manager_kill(value,source,capture,manager,call,record,seen):
    process,path=_start(value,manager);descriptor=None
    try:
        descriptor,native,before=_stopped_partial(value,manager,record,seen)
        death=manager.hard_kill()
        assert death['actual_process_absent'] and death['exit_status']==-signal.SIGKILL
        answer=_finish_client(process)
        assert not answer['ok'],answer
        manager.start()
        # The original supervisor remains stopped with an incomplete copy. This
        # checks both the durable source reference and inherited shared lease.
        rejected=call(dict(operation='rootfs_collect',handle=source,capture=capture),expect=False)
        assert rejected['code'] in ['backend_unavailable','invalid_state'],rejected
        disk=manager.root/'rootfs'/f'capture-{capture}.disk';assert disk.exists()
        jobpath=manager.root/'rootfs'/f'boot-{native["owner"]["sandbox_id"]}.json'
        stopped=json.loads(jobpath.read_bytes());assert stopped==before
        signal.pidfd_send_signal(descriptor,signal.SIGCONT)
        target=call(value)
        resumed=record(target['sandbox_id'])
        assert resumed['phase']=='running' and resumed['owner']==native['owner']
        assert resumed['supervisor']==native['supervisor']
        materialized=json.loads(jobpath.read_bytes())
        assert materialized['target']==before['target'] and materialized['manager']==before['manager']
        assert materialized['copy'] and materialized['collection'] is None
        seen.update(actual_manager_death=death,failed_original_client=answer,source_gc_refused=rejected,
                    same_original_supervisor_and_generation=True,materialized_reference=materialized,request_file=str(path))
        return target
    finally:
        _resume_and_collect_caller(descriptor,process)


def kill_supervisor_during_copy(value,source,capture,manager,call,record,seen):
    process,path=_start(value,manager);descriptor=None
    try:
        descriptor,native,before=_stopped_partial(value,manager,record,seen)
        signal.pidfd_send_signal(descriptor,signal.SIGKILL)
        answer=_finish_client(process);assert not answer['ok'],answer
        sid=value['boot']['sandbox']['id']
        handle=dict(sandbox_id=sid,profile='local-firecracker',
                    backend_ref='fc1:'+manager.cfg['installation_id']+':'+native['owner']['generation'])
        call(dict(operation='remove',handle=handle))
        collected=record(sid)
        assert collected['phase']=='collected' and not collected['ever_ready']
        assert collected['owner']==native['owner']
        physical=manager.observe(collected)
        assert not any(physical['paths'].values()),physical
        supervisor=physical['processes']['supervisor']
        assert not supervisor['present'] or supervisor.get('identity_start_matches') is False,physical
        job=json.loads((manager.root/'rootfs'/f'boot-{sid}.json').read_bytes())
        assert job['target']==before['target'] and job['manager']==before['manager']
        assert job['copy'] is None and job['collection']
        assert call(value,expect=False)['code']=='invalid_state'
        assert record(sid)['owner']==native['owner'] and record(sid)['phase']=='collected'
        assert (manager.root/'rootfs'/f'capture-{capture}.disk').exists()
        seen.update(original_client=answer,collected_native=collected,collected_reference=job,
                    failed_unready_retry_refused=True,original_supervisor_collection=physical,request_file=str(path))
    finally:
        _resume_and_collect_caller(descriptor,process)
