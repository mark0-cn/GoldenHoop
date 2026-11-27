"""Actual release supervisor cuts; fixtures never fabricate root ownership."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import time
import traceback
import uuid

from firecracker_manager_fixture import Manager
from firecracker_metadata_contract import wait_original_absent
from firecracker_cgroup_contract import ROOT, inputs, digest

ATTRIBUTE='user.goldenhoop.vmroot.v1'
MOUNT_TEST='lifecycle::root::tests::actual_bind_mount_refusal_and_original_root_collection'


def authenticate(identity, executable):
    proc=Path('/proc')/str(identity['pid'])
    fields=(proc/'stat').read_text().rsplit(')',1)[1].split()
    assert int(fields[19])==identity['start_ticks'] and identity['uid']==0
    assert identity['executable_sha256']==executable==digest(proc/'exe')
    assert identity['boot_id']==Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    return fields


def kill_original(identity, executable):
    authenticate(identity,executable)
    descriptor=os.pidfd_open(identity['pid'])
    try:
        authenticate(identity,executable)
        signal.pidfd_send_signal(descriptor,signal.SIGKILL)
    finally:
        os.close(descriptor)


def local_mount_contract(manifest_path,fixture,owner):
    report={'result':'failed','cleanup':'unknown','cases':[]}
    try:
        manifest=json.loads(manifest_path.read_bytes())
        assert manifest['format']==1 and manifest['owner']==owner and manifest['source_files_sha256']==inputs()
        assert MOUNT_TEST in manifest.get('additional_tests',[])
        source=(ROOT/manifest['binary']).resolve(strict=True)
        assert source.is_relative_to(ROOT/'target') and source.is_file() and digest(source)==manifest['binary_sha256']
        binary=fixture/'root-filesystem-contract';shutil.copyfile(source,binary);binary.chmod(0o500)
        assert digest(binary)==manifest['binary_sha256']
        process=subprocess.run([str(binary),'--ignored','--exact',MOUNT_TEST,'--nocapture','--test-threads=1'],
            stdin=subprocess.DEVNULL,capture_output=True,timeout=60,
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
        report['binary_sha256']=manifest['binary_sha256'];report['compiled_inputs_verified']=len(inputs())
        report['output_sha256']=hashlib.sha256(process.stdout+process.stderr).hexdigest();report['exit_code']=process.returncode
        matches=[line.split('GH_ROOT_FILESYSTEM_CONTRACT=',1)[1] for line in process.stdout.decode().splitlines() if 'GH_ROOT_FILESYSTEM_CONTRACT=' in line]
        assert len(matches)==1,process.stdout.decode(errors='replace')[-6000:]
        actual=json.loads(matches[0]);report['observed']=actual;report['cases']=actual['cases']
        assert actual['cleanup']=='complete' and actual['observations']['fixture_absent']
        owned=Path(actual['observations']['fixture'])
        assert owned.parent==Path('/var/lib') and owned.name.startswith('ghr-') and not owned.exists()
        assert not any(Path(line.split()[4]).is_relative_to(owned) for line in Path('/proc/self/mountinfo').read_text().splitlines())
        report['cleanup']='complete'
        assert process.returncode==0 and actual['result']=='passed' and len(actual['cases'])==2
        report['result']='passed'
    except Exception as error:
        report['error']=f'{type(error).__name__}: {error}'
    return report


def suite(binary,boot,fixture,manifest_path,owner):
    report={'result':'failed','cleanup':'unknown','cases':[],'observations':[],
            'scope':'actual release root pre-ack refusal, pending receipt recovery, partial deletion and replacement refusal; fixture rollback is labeled separately'}
    cleanup_errors=[];binary_sha=digest(binary)
    mount=local_mount_contract(manifest_path,fixture,owner);report['mount']=mount
    if mount['result']!='passed' or mount['cleanup']!='complete':
        report['error']=mount.get('error','actual root mount contract failed');report['cleanup']=mount['cleanup'];return report
    report['cases']+=mount['cases']
    try:
        for number,kind,syscall,when,delay in [(1,'pre_ack','fsetxattr',2,'delay_enter'),
                (2,'pending_receipt','renameat2',2,'delay_enter'),
                (3,'partial_delete','unlinkat',1,'delay_exit'),
                (4,'replacement','unlinkat',1,'delay_enter')]:
            root=fixture/f'r{number}';installation=str(uuid.uuid4())
            cfg={'installation_id':installation,'data_root':str(root),'artifacts':boot,
                 'supervisor':{'path':str(binary),'size':binary.stat().st_size,'sha256':binary_sha},
                 'image':'sha256:'+boot['rootfs']['sha256'],
                 'max_resources':{'cpu_millis':2000,'memory_bytes':512*1024**2,'pids':256},
                 'capacity':{'cpu_millis':2000,'memory_bytes':2*1024**3,'max_vms':2},'max_ttl_seconds':300}
            config=fixture/f'root-{number}.json';config.write_text(json.dumps(cfg));config.chmod(0o600)
            manager=Manager(binary,config,cfg)
            observed={'kind':kind};report['observations'].append(observed)
            tracer=None;original_owner=None;record=None;witness=None;operation=None;held=None;replaced=None
            trace_prefix=fixture/f'root-trace-{number}';request_counter=0

            def launch(value):
                nonlocal request_counter
                request_counter+=1
                path=fixture/f'root-{number}-{request_counter}.json';path.write_text(json.dumps(value));path.chmod(0o600)
                return subprocess.Popen([str(binary),'driver-call','--config',str(config),'--request',str(path)],
                    stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                    env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})

            def call(value,expect=True,timeout=150):
                process=launch(value)
                try:stdout,stderr=process.communicate(timeout=timeout)
                except subprocess.TimeoutExpired:
                    process.kill();process.communicate(timeout=15);raise
                answer=json.loads(stdout)
                assert answer['ok'] is expect and process.returncode==(0 if expect else 2),(answer,stderr.decode(errors='replace')[-2000:])
                return answer.get('data') if expect else answer['error']

            def create_request():
                now=datetime.datetime.now(datetime.timezone.utc);ttl=240
                resources={'cpu_millis':500,'memory_bytes':256*1024**2,'pids':32}
                request={'profile':'local-firecracker','image':cfg['image'],'resources':resources,'ttl_seconds':ttl,
                    'required_capabilities':['commands','files','pause','network_isolation']}
                sandbox={'id':str(uuid.uuid4()),'profile':request['profile'],'image':request['image'],
                    'state':'pending','desired_state':'running','cleanup':'pending','created_at':now.isoformat(),
                    'expires_at':(now+datetime.timedelta(seconds=ttl)).isoformat(),'observed_at':None,
                    'resources':resources,'metadata':{},'reason':None}
                return {'operation':'create','sandbox':sandbox,'request':request}

            def paths(value):
                generation=uuid.UUID(value['owner']['generation']).hex
                suffix=uuid.UUID(installation).hex+'-'+generation
                return root/'vm'/generation[:12],Path('/sys/fs/cgroup')/('ghv-'+suffix),Path('/sys/fs/cgroup')/('ghs-'+suffix)

            def remove(handle):
                call({'operation':'remove','handle':handle})
                value=json.loads((root/'records'/(handle['sandbox_id']+'.json')).read_text())
                assert value['phase']=='collected' and not any(path.exists() for path in paths(value))
                for identity in [value.get('supervisor'),value.get('process')]:
                    if identity:wait_original_absent(identity)
                return value

            def fixture_empty_rollback():
                # Pre-ack production collection was deliberately refused. The
                # observer witnessed this actual create, holds its inode/parent
                # evidence and may remove only that still-empty fixture object.
                assert kind=='pre_ack' and witness and record and not record.get('vm_root')
                path,group,_=paths(record)
                assert not group.exists() and ATTRIBUTE not in os.listxattr(path)
                wait_original_absent(record['supervisor'])
                parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                descriptor=os.open(path.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                try:
                    value=os.fstat(descriptor);pvalue=os.fstat(parent)
                    assert {'device':value.st_dev,'inode':value.st_ino}==witness['inode']
                    assert {'device':pvalue.st_dev,'inode':pvalue.st_ino}==witness['parent']
                    assert value.st_uid==0 and stat.S_IMODE(value.st_mode)==0o700 and not os.listdir(descriptor)
                    os.rmdir(path.name,dir_fd=parent)
                    assert not path.exists() and os.fstat(descriptor).st_nlink==0
                finally:
                    os.close(descriptor);os.close(parent)
                observed['fixture_only_unacknowledged_empty_root_rollback']=True

            try:
                manager.start();assert manager.close() is None
                command=['strace','--kill-on-exit','-ff','-o',str(trace_prefix),'-s','512',
                    '-e','trace=fsetxattr,renameat2,unlinkat','-e',f'inject={syscall}:{delay}=30s:when={when}',
                    str(binary),'manage','--config',str(config)]
                observed['tracer_command']=command
                with (fixture/f'root-tracer-{number}.log').open('ab') as log:
                    tracer=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=log,stderr=log,
                        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
                until=time.monotonic()+90
                while True:
                    marker=root/'manager.json'
                    if marker.exists():
                        value=json.loads(marker.read_text())
                        if value['ready'] and value['process']['pid']!=manager.process.pid:
                            fields=authenticate(value['process'],binary_sha)
                            assert int(fields[1])==tracer.pid
                            original_owner=value;break
                    assert tracer.poll() is None and time.monotonic()<until,'traced manager readiness deadline'
                    time.sleep(.03)
                request=create_request();id=request['sandbox']['id'];operation=launch(request)
                record_path=root/'records'/(id+'.json')
                if kind in ['partial_delete','replacement']:
                    stdout,stderr=operation.communicate(timeout=180);answer=json.loads(stdout)
                    assert operation.returncode==0 and answer['ok'],(answer,stderr.decode(errors='replace')[-2000:])
                    handle=answer['data'];record=json.loads(record_path.read_text())
                    assert record['ever_ready'] and record['process'] and record['vm_root']
                    observed['before_stop_record']=record
                    operation=launch({'operation':'remove','handle':handle})
                until=time.monotonic()+25
                while True:
                    if record_path.exists():
                        current=json.loads(record_path.read_text());path,group,_=paths(current)
                        if current.get('supervisor') and path.exists():
                            header=None
                            try:header=json.loads(os.getxattr(path,ATTRIBUTE))
                            except OSError as error:
                                if error.errno!=61:raise
                            found=False
                            if kind=='pre_ack':
                                found=not current.get('vm_root') and header is None and not list(path.iterdir())
                            elif kind=='pending_receipt':
                                for pending in (root/'records').glob('.gh-meta-*.pending'):
                                    value=json.loads(pending.read_bytes())
                                    if value.get('owner',{}).get('sandbox_id')==id and value.get('vm_root')==header and header:
                                        receipt=json.loads(os.getxattr(pending,'user.goldenhoop.metadata.v1'))
                                        metadata=pending.lstat();raw=pending.read_bytes()
                                        assert receipt['content']=={'inode':{'device':metadata.st_dev,'inode':metadata.st_ino},'length':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
                                        observed['actual_pending_journal']={'path':str(pending),'receipt':receipt,'contents':value}
                                        found=not (path/'intent.json').exists();break
                            else:
                                found=current.get('root_collection_started') and not group.exists() and ((path/'intent.json').exists() is (kind=='replacement'))
                            if found:
                                record=current;value=path.lstat();pvalue=path.parent.lstat()
                                witness={'inode':{'device':value.st_dev,'inode':value.st_ino},'parent':{'device':pvalue.st_dev,'inode':pvalue.st_ino},'header':header}
                                fields=authenticate(record['supervisor'],binary_sha)
                                assert int(fields[1])==original_owner['process']['pid']
                                if header:
                                    assert header['producer']==record['supervisor'] and header['inode']==witness['inode'] and header['parent']==witness['parent']
                                    assert header['path']==str(path) and header['generation']==record['owner']['generation']
                                observed['actual_cut']={'record':record,'witness':witness};break
                    assert tracer.poll() is None and time.monotonic()<until,'actual root cut not reached'
                    time.sleep(.02)
                if kind in ['partial_delete','replacement']:
                    wait_original_absent(observed['before_stop_record']['process'])
                    assert record['process']==observed['before_stop_record']['process']
                kill_original(record['supervisor'],binary_sha)
                kill_original(original_owner['process'],binary_sha)
                tracer.kill();assert tracer.wait(timeout=15)==-signal.SIGKILL
                wait_original_absent(record['supervisor']);wait_original_absent(original_owner['process'])
                stdout,stderr=operation.communicate(timeout=20)
                observed['interrupted_request']={'exit_code':operation.returncode,'stdout_tail':stdout.decode(errors='replace')[-3000:],'stderr_tail':stderr.decode(errors='replace')[-3000:]}
                manager.maintenance_restart=True;new_owner=manager.start()
                handle=next(value for value in call({'operation':'discover'}) if value['sandbox_id']==id)
                if kind=='pre_ack':
                    refused=call({'operation':'remove','handle':handle},expect=False)
                    observed['production_unacknowledged_refusal']=refused
                    assert paths(record)[0].lstat().st_ino==witness['inode']['inode'] and not list(paths(record)[0].iterdir())
                    observed['same_intent_create_refused_without_replay']=call(request,expect=False)
                    assert paths(record)[0].lstat().st_ino==witness['inode']['inode'] and not paths(record)[1].exists()
                    # This reservation must continue to count, while an
                    # independent generation within capacity can still progress.
                    second=call(create_request())
                    observed['third_reservation_refused']=call(create_request(),expect=False)
                    assert observed['third_reservation_refused']['code']=='quota_exceeded'
                    remove(second);fixture_empty_rollback();remove(handle)
                    report['cases'].append('actual_unacknowledged_root_refusal_retains_reservation_allows_independent_progress_and_scoped_fixture_rollback')
                elif kind=='replacement':
                    path=paths(record)[0];held=path.with_name(path.name+'-held')
                    os.rename(path,held);path.mkdir(mode=0o700)
                    shutil.copyfile(held/'intent.json',path/'intent.json');(path/'intent.json').chmod(0o600)
                    os.setxattr(path,ATTRIBUTE,os.getxattr(held,ATTRIBUTE))
                    replaced=path.lstat().st_ino;assert replaced!=witness['inode']['inode']
                    before=digest(path/'intent.json');observed['replacement_refusal']=call({'operation':'remove','handle':handle},expect=False)
                    assert path.lstat().st_ino==replaced and digest(path/'intent.json')==before
                    assert held.lstat().st_ino==witness['inode']['inode'] and (held/'intent.json').exists()
                    (path/'intent.json').unlink();path.rmdir();os.rename(held,path);held=None;replaced=None
                    final=remove(handle);assert final['process']==record['process']
                    report['cases'].append('actual_same_marker_and_copied_receipt_replacement_refused_then_original_root_collected')
                else:
                    path=paths(record)[0];assert path.lstat().st_ino==witness['inode']['inode']
                    loaded=json.loads(record_path.read_text());assert loaded['vm_root']==witness['header']
                    if kind=='pending_receipt':
                        value=record_path.lstat()
                        assert {'device':value.st_dev,'inode':value.st_ino}==observed['actual_pending_journal']['receipt']['content']['inode']
                        assert 'records/'+record_path.name in new_owner['metadata_recovery']['completed']
                    final=remove(handle)
                    if record.get('process'):assert final['process']==record['process']
                    observed['original_inode_recovered_before_collection']=True
                    report['cases'].append('actual_release_'+kind+'_recovers_original_root_without_replaying_create')
                observed['recovered_owner']=new_owner
                assert manager.close() is None
            finally:
                # Only owned tracer and already authenticated original identities
                # may be stopped here. Never infer process absence from EOF.
                try:
                    if tracer and tracer.poll() is None:tracer.kill();tracer.wait(timeout=15)
                    for identity in [record.get('supervisor') if record else None,original_owner['process'] if original_owner else None]:
                        if identity:wait_original_absent(identity)
                    if operation and operation.poll() is None:operation.communicate(timeout=20)
                    if held:
                        path=paths(record)[0]
                        assert replaced and path.lstat().st_ino==replaced and held.lstat().st_ino==witness['inode']['inode']
                        assert set(p.name for p in path.iterdir())=={'intent.json'}
                        (path/'intent.json').unlink();path.rmdir();os.rename(held,path);held=None
                    if witness and kind=='pre_ack' and paths(record)[0].exists():fixture_empty_rollback()
                    if manager.process is None or manager.process.poll() is not None:
                        manager.maintenance_restart=True;manager.start()
                    assert manager.close() is None
                    assert not (root/'manager.json').exists() and not (root/'manager.sock').exists()
                    for saved in (root/'records').glob('*.json'):
                        value=json.loads(saved.read_text());assert value['phase']=='collected'
                        assert not any(path.exists() for path in paths(value))
                        for identity in [value.get('process'),value.get('supervisor')]:
                            if identity:wait_original_absent(identity)
                    observed['final_collection']='complete'
                except Exception as error:
                    cleanup_errors.append(f'{kind}: {type(error).__name__}: {error}')
                observed['trace_files']={path.name:{'sha256':digest(path),'tail':path.read_text(errors='replace')[-4096:]}
                    for path in fixture.glob(trace_prefix.name+'.*')}
        report['result']='passed'
    except Exception as error:
        report['error']=f'{type(error).__name__}: {error}'
        report['failure_site']=[{'file':Path(f.filename).name,'line':f.lineno,'function':f.name} for f in traceback.extract_tb(error.__traceback__)]
    report['cleanup']='unknown' if cleanup_errors else 'complete'
    if cleanup_errors:report['cleanup_errors']=cleanup_errors;report['result']='failed'
    return report
