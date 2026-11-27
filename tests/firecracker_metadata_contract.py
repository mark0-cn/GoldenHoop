"""Kill the actual release manager during real metadata syscalls, then recover.

strace delays a syscall; it does not fabricate success/error returns or write
the metadata under test. Rust performs all publication, recovery and drainage.
"""
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import time
import traceback
import uuid

from firecracker_manager_fixture import Manager

ATTRIBUTE = 'user.goldenhoop.metadata.v1'


def suite(binary, boot, fixture):
    report = {'result':'failed','cleanup':'unknown','cases':[], 'observations':[],
              'scope':'actual release-manager metadata publication/recovery; no VMM or snapshot capability claim'}
    binary_sha = hashlib.file_digest(binary.open('rb'),'sha256').hexdigest()
    report['strace_version'] = subprocess.check_output(['strace','--version']).decode().splitlines()[0]
    cleanup_errors = []
    try:
        # Assert the actual target/receipt at each ordinal rather than trusting
        # syscall ordering alone. The last two cuts cover the control receipts.
        for ordinal, target in [(1,'installation.lock'),(2,'installation.json'),(3,'config.json'),
                                (5,'manager.json'),(6,'manager.json')]:
            installation = str(uuid.uuid4())
            root = fixture/f'm{ordinal}'
            cfg = {'installation_id':installation,'data_root':str(root),'artifacts':boot,
                   'supervisor':{'path':str(binary),'size':binary.stat().st_size,'sha256':binary_sha},
                   'image':'sha256:'+boot['rootfs']['sha256'],
                   'max_resources':{'cpu_millis':2000,'memory_bytes':512*1024**2,'pids':256},
                   'capacity':{'cpu_millis':2000,'memory_bytes':2*1024**3,'max_vms':2},'max_ttl_seconds':300}
            config = fixture/f'metadata-{ordinal}.json'; config.write_text(json.dumps(cfg)); config.chmod(0o600)
            manager = Manager(binary,config,cfg)
            trace_prefix = fixture/f'metadata-trace-{ordinal}'
            command = ['strace','--kill-on-exit','-ff','-o',str(trace_prefix),'-s','512',
                       '-e','trace=renameat2','-e',f'inject=renameat2:delay_enter=30s:when={ordinal}',
                       str(binary),'manage','--config',str(config)]
            observed = {'ordinal':ordinal,'target':target,'command':command}
            report['observations'].append(observed)
            tracer = None; tracee = None; pidfd = None
            try:
                with (fixture/f'metadata-tracer-{ordinal}.log').open('ab') as log:
                    tracer = subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=log,stderr=log,
                        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
                until = time.monotonic()+25
                while True:
                    assert tracer.poll() is None and time.monotonic()<until, 'metadata syscall barrier not reached'
                    if tracee is None:
                        children = Path('/proc')/str(tracer.pid)/'task'/str(tracer.pid)/'children'
                        try:
                            candidates = children.read_text().split()
                        except FileNotFoundError:
                            candidates = []
                        for candidate in candidates:
                            proc = Path('/proc')/candidate
                            try:
                                parts=(proc/'stat').read_text().rsplit(')',1)[1].split()
                                executable=hashlib.file_digest((proc/'exe').open('rb'),'sha256').hexdigest()
                            except (FileNotFoundError,ProcessLookupError):
                                continue
                            if executable==binary_sha and int(parts[1])==tracer.pid:
                                tracee={'pid':int(candidate),'start_ticks':int(parts[19])}
                                observed['owned_tracee_before_barrier']=tracee
                    found = []
                    if root.exists():
                        for path in root.glob('.gh-meta-*.pending'):
                            try:
                                value = path.lstat(); raw = path.read_bytes()
                                header = json.loads(os.getxattr(path,ATTRIBUTE))
                            except FileNotFoundError:
                                continue
                            if header['binding']['target']!=target:
                                continue
                            assert stat.S_ISREG(value.st_mode) and value.st_uid==0 and value.st_mode&0o777==0o600
                            assert value.st_nlink==1 and header['binding']['directory']==str(root)
                            assert header['content']=={'inode':{'device':value.st_dev,'inode':value.st_ino},
                                                      'length':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
                            found.append((path,header,json.loads(raw)))
                    if found:
                        assert len(found)==1
                        pending, receipt, contents = found[0]
                        break
                    time.sleep(.02)
                producer = receipt['actor']['process']
                if tracee:
                    assert producer['pid']==tracee['pid'] and producer['start_ticks']==tracee['start_ticks']
                tracee = producer; pid = tracee['pid']
                proc = Path('/proc')/str(pid)
                parts = (proc/'stat').read_text().rsplit(')',1)[1].split()
                assert int(parts[1])==tracer.pid and int(parts[19])==tracee['start_ticks']
                assert tracee['uid']==0 and tracee['executable_sha256']==binary_sha
                assert hashlib.file_digest((proc/'exe').open('rb'),'sha256').hexdigest()==binary_sha
                if target=='manager.json':
                    assert contents['process']==tracee and contents['cgroup_identity']
                    assert contents['ready'] is (ordinal==6)
                    if ordinal==6:
                        assert contents['socket_identity'] and (root/'manager.sock').is_socket()
                observed['before_kill']={'receipt':receipt,'contents':contents,'pending':str(pending)}
                pidfd = os.pidfd_open(pid)
                assert int((proc/'stat').read_text().rsplit(')',1)[1].split()[19])==tracee['start_ticks']
                signal.pidfd_send_signal(pidfd,signal.SIGKILL)
                observed['tracer_exit_status'] = tracer.wait(timeout=15)
                assert observed['tracer_exit_status']==-signal.SIGKILL and not proc.exists()
                assert not (Path('/proc')/str(tracer.pid)).exists()
                assert pending.exists() and pending.stat().st_ino==receipt['content']['inode']['inode']
                observed['original_writer_absent']=True
                owner = manager.start()
                assert not list(root.glob('.gh-meta-*.pending'))
                assert json.loads((root/'config.json').read_text())==cfg
                if target in ['installation.lock','installation.json']:
                    current = (root/target).lstat()
                    assert {'device':current.st_dev,'inode':current.st_ino}==receipt['content']['inode']
                    observed['original_pending_inode_retained']=True
                else:
                    assert target in owner['metadata_recovery']['completed'],owner
                if target=='manager.json':
                    assert owner['epoch']!=contents['epoch']
                    assert owner['recovery']['previous_process']==tracee
                    assert not Path(contents['cgroup']).exists()
                observed['recovered_owner']=owner
                assert not list((root/'records').glob('*.json')) and not list((root/'vm').iterdir())
                assert manager.close() is None
                observed['manager_collected']=manager.diagnostics()['process_collected']
                assert observed['manager_collected']
                report['cases'].append(f'actual_release_manager_SIGKILL_at_rename_{ordinal}_recovers_{target}_and_drains_scoped_control')
            finally:
                if pidfd is not None:
                    os.close(pidfd)
                if tracer and tracer.poll() is None:
                    # The fixture owns this Popen; PTRACE_O_EXITKILL fences only
                    # its tracees if the observer itself fails before the cut.
                    tracer.kill(); tracer.wait(timeout=15)
                if tracee:
                    proc = Path('/proc')/str(tracee['pid']); until=time.monotonic()+15
                    while proc.exists():
                        try:
                            parts=(proc/'stat').read_text().rsplit(')',1)[1].split()
                        except FileNotFoundError:
                            break
                        if int(parts[19])!=tracee['start_ticks']:
                            break
                        assert time.monotonic()<until, 'original metadata writer collection unconfirmed'
                        time.sleep(.05)
                try:
                    if manager.process is None and root.exists():
                        manager.maintenance_restart=True; manager.start()
                    error=manager.close()
                    assert not error,error
                    observed['final_control_collected']=manager.diagnostics()['process_collected']
                    assert observed['final_control_collected']
                    assert not list(root.glob('.gh-meta-*.pending'))
                    assert not (root/'manager.json').exists() and not (root/'manager.sock').exists()
                except Exception as error:
                    cleanup_errors.append(f'{ordinal}: {type(error).__name__}: {error}')
                observed['trace_files']={path.name:{'sha256':hashlib.file_digest(path.open('rb'),'sha256').hexdigest(),
                    'tail':path.read_text(errors='replace')[-4096:]} for path in fixture.glob(trace_prefix.name+'.*')}
        report['result']='passed'
    except Exception as error:
        report['error']=f'{type(error).__name__}: {error}'
        report['failure_site']=[{'file':Path(f.filename).name,'line':f.lineno,'function':f.name}
                                for f in traceback.extract_tb(error.__traceback__)]
    report['cleanup']='unknown' if cleanup_errors else 'complete'
    if cleanup_errors:
        report['cleanup_errors']=cleanup_errors;report['result']='failed'
    return report
