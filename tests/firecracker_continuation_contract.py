"""Observe Rust's private fresh-VMM continuation; never replay the captured job."""
import json
import os
from pathlib import Path
import subprocess
import stat
import tempfile
import time
import uuid


def exercise(binary, boot, fixture, checkpoint, reference, capture, source_generation):
    generation = str(uuid.uuid4())
    source = capture['reference']
    cfg = {'artifacts':boot, 'checkpoint':checkpoint, 'reference':reference,
           'restoration':str(uuid.uuid4()), 'target_sandbox':str(uuid.uuid4()),
           'target_generation':generation, 'marker_execution':capture['marker_execution'],
           'marker_hex':capture['memory_marker_hex'], 'disk_marker_base64':capture['disk_marker_base64']}
    assert source == reference and cfg['marker_execution']
    path = fixture/'continuation.json'
    report = {'result':'failed','cleanup':'unknown','cases':[],'observations':{},
              'scope':'private same-host fresh-VMM continuation only; no native-manager/public restore or crash-reconnect acceptance'}

    def run(value):
        path.write_text(json.dumps(value),encoding='utf-8');path.chmod(0o400)
        samples=[]
        with tempfile.TemporaryFile() as output,tempfile.TemporaryFile() as errors:
            process = subprocess.Popen([str(binary),'probe-restore','--config',str(path)],stdout=output,stderr=errors)
            until=time.monotonic()+240
            jail=Path('/var/lib')/('ghv-'+uuid.UUID(value['target_generation']).hex[:8])/'j/firecracker'/value['target_generation']/'root'
            try:
                while process.poll() is None:
                    try:
                        parent=jail.lstat();folder=(jail/'restore').lstat();memory=(jail/'restore/memory').lstat()
                        protected=(parent.st_uid==0 and stat.S_IMODE(parent.st_mode)==0o755
                            and stat.S_ISDIR(folder.st_mode) and folder.st_uid==0 and stat.S_IMODE(folder.st_mode)==0o555
                            and stat.S_ISREG(memory.st_mode) and memory.st_uid==0 and stat.S_IMODE(memory.st_mode)==0o444 and memory.st_nlink==1)
                        if protected and not samples:
                            samples.append({'jail_uid':parent.st_uid,'jail_mode':stat.S_IMODE(parent.st_mode),
                                            'memory_uid':memory.st_uid,'memory_mode':stat.S_IMODE(memory.st_mode),
                                            'memory_device':memory.st_dev,'memory_inode':memory.st_ino,'memory_length':memory.st_size})
                    except FileNotFoundError:
                        pass
                    if time.monotonic()>=until:
                        process.terminate();process.wait(timeout=60);break
                    time.sleep(.05)
            finally:
                if process.poll() is None:
                    process.terminate();process.wait(timeout=60)
            process.wait(timeout=5);output.seek(0);errors.seek(0)
            stdout,stderr=output.read(),errors.read()
        assert not stderr, stderr.decode(errors='replace')[-3000:]
        answer = json.loads(stdout)
        assert process.returncode == (0 if answer['result'] in ['passed','existing'] else 2), (process.returncode,answer)
        return answer,samples

    try:
        first,samples = run(cfg); report['observations']['first'] = first
        report['observations']['protected_backing'] = samples
        assert first['result']=='passed' and first['cleanup']=='complete', first.get('error')
        target = first['target']
        assert target['generation']==generation and target['passed'] and target['guest_started']
        assert target['cleanup']=='complete' and all(target[key] for key in ['root_absent','cgroup_absent','vmm_reaped'])
        assert first['source_absence_confirmed'] and first['content_verified_after_target_collection']
        authority,thaw = first['frozen_authority'],first['thawed_barrier']
        transfer = authority['transfer']
        assert transfer['target_generation']==generation and transfer['restoration']==cfg['restoration']
        assert transfer['source_generation']==source_generation
        assert authority['protocol']==thaw['protocol']==3 and authority['phase']=='quiesced' and authority['workload_frozen']
        assert transfer['barrier']==thaw['barrier'] and samples, 'actual frozen receipt or protected backing was not observed'
        assert thaw['generation']==generation and thaw['phase']=='resumed' and thaw['workload_frozen'] is False
        suffix='ghv-'+uuid.UUID(generation).hex[:8]
        assert not os.path.lexists(Path('/var/lib')/suffix)
        assert not os.path.lexists(Path('/sys/fs/cgroup')/suffix)
        process = target['process']
        assert process['uid']==10000 and process['no_new_privileges'] and process['effective_capabilities']=='0000000000000000'
        assert process['seccomp_mode']==2 and process['namespace_isolated'] and process['network_namespace_isolated']
        for case in first['checks']:
            report['cases'].append(case)
        collection = first['restoration_collection']
        assert collection['target_absent'] and collection['target_reserved_bytes']==0
        assert collection['restoration']['outcome']=='activated' and collection['restoration']['phase']=='closed'
        report['cases'].append('actual_fresh_target_VMM_jail_and_cgroup_collection_closes_only_the_original_continuation_reservation')

        retry,_ = run(cfg); report['observations']['exact_retry'] = retry
        assert retry['result']=='existing' and retry['target'] is None and retry['checks']==[]
        original = retry['original_restoration']
        assert original['intent']['generation']==generation and original['intent']['restoration']==cfg['restoration']
        assert original['phase']=='closed' and original['outcome']=='activated'
        changed = dict(cfg,restoration=str(uuid.uuid4()),target_generation=str(uuid.uuid4()),target_sandbox=str(uuid.uuid4()))
        refused,_ = run(changed); report['observations']['changed_intent_refusal'] = refused
        assert refused['result']=='failed' and refused['target'] is None
        assert 'different immutable target' in refused['error'], refused
        refused_suffix='ghv-'+uuid.UUID(changed['target_generation']).hex[:8]
        assert not os.path.lexists(Path('/var/lib')/refused_suffix)
        assert not os.path.lexists(Path('/sys/fs/cgroup')/refused_suffix)
        report['cases'].append('actual_completed_continuation_retry_returns_original_target_without_relaunch_and_changed_target_is_refused')
        report['result']='passed';report['cleanup']='complete'
    except Exception as error:
        report['error']=f'{type(error).__name__}: {error}'
    return report
