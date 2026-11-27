"""Kill an actual restore supervisor after VMM launch, before writer receipt.

The observer delays matching openat calls; it neither supplies syscall return
values nor writes production metadata. Rust alone collects runtime resources.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import time
import uuid


def observe(pid):
    proc=Path('/proc')/str(pid)
    fields=(proc/'stat').read_text().rsplit(')',1)[1].split()
    status=dict(line.split(':',1) for line in (proc/'status').read_text().splitlines() if ':' in line)
    return {'pid':pid,'start_ticks':int(fields[19]),'state':fields[0],
            'parent':int(fields[1]),'uids':list(map(int,status['Uid'].split())),
            'tracer':int(status['TracerPid']), 'cgroup':(proc/'cgroup').read_text()}


def pending_writer(root,capture):
    for path in (root/'checkpoints').glob('.gh-meta-*.pending'):
        try:
            header=json.loads(os.getxattr(path,'user.goldenhoop.metadata.v1'))
            if header['binding']['target']!=f'capture-{capture}.json':
                continue
            value=json.loads(path.read_bytes()).get('restoration')
            if value and value.get('writer'):
                return True
        except FileNotFoundError:
            continue
    return False


def exercise(binary,root,cfg,manager,request,call,rpc,record,remove,handles,report):
    observed=report['observations']['restore_writer_cut']={}
    observed['strace_version']=subprocess.check_output(['strace','--version']).decode().splitlines()[0]
    source=call(request(ttl=300));handles[source['sandbox_id']]=source
    capture=str(uuid.uuid4())
    ready=call({'operation':'checkpoint_capture','handle':source,'capture':capture})
    until=time.monotonic()+150
    while ready['phase']!='ready':
        assert ready['capture_outcome']=='pending' and time.monotonic()<until,ready
        time.sleep(.1);ready=call({'operation':'checkpoint_inspect','capture':capture})
    assert ready['content_verified']
    observed['source_collected']=remove(source)
    observed['ready']=ready
    creation=request(ttl=300);sid=creation['sandbox']['id']
    operation={'operation':'checkpoint_restore','restore':{
        'sandbox':creation['sandbox'],'request':creation['request'],
        'reference':ready['reference'],'restoration':str(uuid.uuid4())}}
    owner=manager.owner
    message={key:owner[key] for key in ['installation_id','epoch','config_sha256']}
    message['operation']={'method':'call','call':operation}
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
        client.settimeout(10);client.connect(str(root/'manager.sock'))
        client.sendall(json.dumps(message).encode()+b'\n');client.shutdown(socket.SHUT_WR)
    tracer=None;sup_fd=None;vmm_fd=None;stopped=False;supervisor=None
    prefix=root.parent/'restore-writer-cut-trace'
    log=root.parent/'restore-writer-cut-tracer.log'
    try:
        until=time.monotonic()+45
        while True:
            path=root/'records'/f'{sid}.json'
            if path.exists():
                current=record(sid)
                if current.get('supervisor'):
                    supervisor=current['supervisor'];break
            assert time.monotonic()<until,'native supervisor acknowledgement deadline'
            time.sleep(.002)
        generation=uuid.UUID(current['owner']['generation'])
        suffix=uuid.UUID(cfg['installation_id']).hex+'-'+generation.hex
        vmroot=root/'vm'/generation.hex[:12]
        jail=vmroot/'j/firecracker'/str(generation)/'root'
        vmgroup=Path('/sys/fs/cgroup')/('ghv-'+suffix)
        supgroup=Path('/sys/fs/cgroup')/('ghs-'+suffix)
        handle={'sandbox_id':sid,'profile':'local-firecracker',
                'backend_ref':f'fc1:{cfg["installation_id"]}:{generation}'}
        handles[sid]=handle
        sup_fd=os.pidfd_open(supervisor['pid'])
        actual=observe(supervisor['pid'])
        assert actual['start_ticks']==supervisor['start_ticks'] and actual['uids']==[0]*4
        assert actual['parent']==manager.process.pid and actual['cgroup'].strip()=='0::/'+supgroup.name
        with (Path('/proc')/str(supervisor['pid'])/'exe').open('rb') as file:
            assert hashlib.file_digest(file,'sha256').hexdigest()==cfg['supervisor']['sha256']
        signal.pidfd_send_signal(sup_fd,signal.SIGSTOP);stopped=True
        # strace v6.8 and current source apply path filtering before injection.
        # Delay this supervisor's executable opens only. No fake return values.
        traced_path=f'/proc/{supervisor["pid"]}/exe'
        trace_command=['strace','-ff','-o',str(prefix),'-s','512','-p',str(supervisor['pid']),
                       '-P',traced_path,'-e','trace=openat','-e','inject=openat:delay_enter=1s']
        with log.open('ab') as output:
            tracer=subprocess.Popen(trace_command,stdin=subprocess.DEVNULL,stdout=output,stderr=output)
        observed['trace_command']=trace_command
        until=time.monotonic()+15
        while observe(supervisor['pid'])['tracer']!=tracer.pid:
            assert tracer.poll() is None and time.monotonic()<until,'owned syscall observer attach failed'
            time.sleep(.01)
        signal.pidfd_send_signal(sup_fd,signal.SIGCONT);stopped=False
        observed['original_supervisor']=supervisor
        until=time.monotonic()+110
        while True:
            assert tracer.poll() is None and time.monotonic()<until,'actual unacknowledged launch boundary missed'
            capture_record=json.loads((root/'checkpoints'/f'capture-{capture}.json').read_bytes())
            restoration=capture_record.get('restoration')
            current=record(sid)
            if restoration:
                assert restoration['phase'] in ['claimed','allocated','launching'],restoration
                assert restoration['writer'] is None,'writer was already durably acknowledged'
            try:
                raw=(jail/'firecracker.pid').read_bytes()
                pid=int(raw) if raw.strip().isdigit() else 0
                vmm=observe(pid) if pid>1 else None
            except (FileNotFoundError,ProcessLookupError):
                vmm=None
            if (restoration and restoration['phase']=='launching' and vmm
                    and vmm['uids']==[10000]*4 and vmm['state'] not in ['Z','X']
                    and vmm['cgroup'].strip()=='0::/'+vmgroup.name and not pending_writer(root,capture)):
                with (Path('/proc')/str(vmm['pid'])/'exe').open('rb') as file:
                    assert hashlib.file_digest(file,'sha256').hexdigest()==cfg['artifacts']['firecracker']['sha256']
                assert restoration['producer']['process']==supervisor
                assert current['vm_root'] and current['vm_cgroup_identity'] and current['supervisor_cgroup_identity']
                assert current['vm_root']['producer']==supervisor
                vmm_fd=os.pidfd_open(vmm['pid'])
                assert observe(vmm['pid'])['start_ticks']==vmm['start_ticks']
                observed['before_kill']={'native_journal':current,'restoration':restoration,'live_unacknowledged_VMM':vmm,
                                         'pending_writer_acknowledgement':False,'supervisor_observation':observe(supervisor['pid'])}
                signal.pidfd_send_signal(sup_fd,signal.SIGKILL)
                observed['original_supervisor_SIGKILL_sent']=True
                break
            time.sleep(.002)
        # End only the owned observer. Without --kill-on-exit it cannot replace
        # Rust's VMM collection proof. The exact VMM must be collected below.
        if tracer.poll() is None:tracer.kill()
        observed['tracer_exit_status']=tracer.wait(timeout=15)
        exited=select.poll();exited.register(sup_fd,select.POLLIN)
        assert any(flags&select.POLLIN for _,flags in exited.poll(15000)),'original supervisor exit unconfirmed'
        report['cases'].append('actual_live_UID10000_VMM_launch_observed_with_original_source_absent_and_no_durable_or_pending_writer_ack_before_supervisor_SIGKILL')
        collected=remove(handle);observed['native_collection']=collected
        assert all(not os.path.lexists(path) for path in [vmroot,vmgroup,supgroup])
        vmm=observed['before_kill']['live_unacknowledged_VMM']
        try:
            assert observe(vmm['pid'])['start_ticks']!=vmm['start_ticks'],'original VMM is not physically reaped'
        except (FileNotFoundError,ProcessLookupError):
            pass
        exited=select.poll();exited.register(vmm_fd,select.POLLIN)
        assert any(flags&select.POLLIN for _,flags in exited.poll(0)),'original VMM exit is unconfirmed'
        retained=call({'operation':'checkpoint_inspect','capture':capture})
        final=retained['restoration'];observed['closed_restoration']=final
        assert retained['content_verified'] and retained['reserved_bytes']==ready['reserved_bytes']
        assert final['phase']=='closed' and final['outcome']=='unconfirmed' and final['writer'] is None
        proof=final['native_collection']
        assert proof['producer']==supervisor and proof['intent']==current['restore']['intent']
        assert proof['directory']['receipt']==current['vm_root']
        assert proof['groups']==[[str(vmgroup),current['vm_cgroup_identity']],[str(supgroup),current['supervisor_cgroup_identity']]]
        assert call(operation)==handle
        competitor=request(ttl=300);changed=copy.deepcopy(operation)
        changed['restore'].update(sandbox=competitor['sandbox'],request=competitor['request'],restoration=str(uuid.uuid4()))
        assert call(changed,expect=False)['code']=='conflict'
        assert not os.path.lexists(root/'records'/f'{competitor["sandbox"]["id"]}.json')
        report['cases'].append('actual_native_cgroup_root_and_process_collection_closes_lost_writer_ack_as_Unconfirmed_with_original_receipt_and_no_relaunch')
        gc=call({'operation':'checkpoint_collect','capture':capture});observed['content_collection']=gc
        assert gc['objects_absent'] and gc['reserved_bytes']==0 and call(operation)==handle
        assert call({'operation':'discover'})==[]
        report['cases'].append('actual_unacknowledged_restore_releases_original_target_quota_and_exact_content_GC_without_manufacturing_Activated_or_another_target')
    finally:
        if tracer and tracer.poll() is None:
            tracer.kill();tracer.wait(timeout=15)
        if sup_fd is not None:
            if stopped:
                try:signal.pidfd_send_signal(sup_fd,signal.SIGCONT)
                except ProcessLookupError:pass
            os.close(sup_fd)
        if vmm_fd is not None:os.close(vmm_fd)
        observed['trace_tail']={p.name:p.read_text(errors='replace')[-4096:] for p in prefix.parent.glob(prefix.name+'.*')}
        if log.exists():observed['tracer_log']=log.read_text(errors='replace')[-4096:]
