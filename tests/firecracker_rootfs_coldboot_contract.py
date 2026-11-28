"""Python submits and observes; production Rust owns every disk copy and boot."""
import base64
import copy
import datetime
import json
import os
from pathlib import Path
import time
import uuid


def exercise(source, capture, counter, captured_value, source_execution, cfg, call, rpc, record, report):
    root=Path(cfg['data_root'])
    seen=report['observations']['rootfs_coldboot']={}
    original=record(source['sandbox_id'])
    status=call(dict(operation='rootfs_inspect',handle=source,capture=capture))
    assert status['phase']=='ready' and status['inspection_verified']
    reference=status['reference']
    def request():
        now=datetime.datetime.now(datetime.timezone.utc);sid=str(uuid.uuid4());resources=original['resources']
        create=dict(profile='local-firecracker',image=cfg['image'],resources=resources,ttl_seconds=120,
                    required_capabilities=['commands','files','pause','network_isolation'])
        sandbox=dict(id=sid,profile=create['profile'],image=create['image'],resources=resources,
                     state='pending',desired_state='running',cleanup='pending',created_at=now.isoformat(),
                     expires_at=(now+datetime.timedelta(seconds=120)).isoformat(),observed_at=None,metadata={},reason=None)
        return dict(operation='rootfs_boot',boot=dict(sandbox=sandbox,request=create,reference=reference,
                                                    operation=str(uuid.uuid4()),expected_source=source))
    def read(handle):
        result=rpc(handle,dict(method='read_file',path=counter,max_bytes=128),'file')
        return int(base64.b64decode(result['data_base64'],validate=True))
    requests=[request(),request()]
    bad=copy.deepcopy(requests[0]);bad['boot']['reference']['manifest_sha256']='f'*64
    call(bad,expect=False)
    assert not (root/'records'/f'{bad["boot"]["sandbox"]["id"]}.json').exists()
    targets=[]
    for value in requests:
        target=call(value);targets.append(target)
        native=record(target['sandbox_id']);binding=native['rootfs_boot']
        job=json.loads((root/'rootfs'/f'boot-{target["sandbox_id"]}.json').read_bytes())
        seen.setdefault('targets',[]).append(dict(request=value,handle=target,native=native,reference_job=job))
        assert native['phase']=='running' and native['ever_ready'] and native.get('restore') is None
        assert native.get('selected_image') is None and binding['target']['reference']==reference
        assert job['dispatched'] and job['copy'] and job['collection'] is None
        assert job['copy']['content']==binding['manifest']['disk']
        assert read(target)==captured_value
        time.sleep(.12)
        assert read(target)==captured_value, 'a disk-only boot adopted the original writer process'
        missing=rpc(target,dict(method='inspect',id=source_execution))
        assert missing['status']=='error' and missing['data']['code']=='not_found',missing
        assert call(value)==target
        assert record(target['sandbox_id'])['owner']==native['owner']
    assert len({record(t['sandbox_id'])['owner']['generation'] for t in targets})==2
    paths=[Path(record(t['sandbox_id'])['artifacts']['rootfs']['path']) for t in targets]
    identities=[(path.stat().st_dev,path.stat().st_ino) for path in paths]
    source_disk=root/'rootfs'/f'capture-{capture}.disk'
    identities.append((source_disk.stat().st_dev,source_disk.stat().st_ino))
    assert len(set(identities))==3
    assert read(source)>captured_value
    changed=copy.deepcopy(requests[0]);changed['boot']['operation']=str(uuid.uuid4())
    assert call(changed,expect=False)['code']=='conflict'
    changed=copy.deepcopy(requests[0]);changed['operation']='create';changed=changed['boot']
    assert call(dict(operation='create',sandbox=changed['sandbox'],request=changed['request']),expect=False)['code']=='conflict'
    report['cases'].append('one_Rust_captured_and_runsc_inspected_disk_starts_two_fresh_KVM_targets_with_distinct_disks_and_no_retained_execution_or_writer')
    report['cases'].append('rootfs_boot_exact_retry_reuses_original_target_and_refuses_changed_reference_operation_or_ordinary_boot_kind')
    call(dict(operation='rootfs_collect',handle=source,capture=capture))
    assert not os.path.lexists(source_disk)
    assert call(dict(operation='rootfs_inspect',handle=source,capture=capture))['reserved_bytes']==0
    for value,target in zip(requests,targets):
        assert call(value)==target
        assert call(dict(operation='inspect',handle=target))['state']=='running'
    rpc(targets[0],dict(method='write_file',path=counter,data_base64=base64.b64encode(b'8000001').decode()),'ok')
    assert read(targets[0])==8000001 and read(targets[1])==captured_value
    rpc(targets[1],dict(method='write_file',path=counter,data_base64=base64.b64encode(b'8000002').decode()),'ok')
    assert read(targets[0])==8000001 and read(targets[1])==8000002
    assert read(source)>captured_value and read(source)<8000001
    assert record(source['sandbox_id'])['owner']==original['owner']
    assert record(source['sandbox_id'])['process']==original['process']
    seen.update(source_disk_collected=True,distinct_disk_identities=identities,source_continues=True,
                target_values_after_source_gc=[read(target) for target in targets])
    report['cases'].append('materialized_rootfs_targets_write_independently_and_continue_after_source_content_GC_while_original_source_continues')
    for value,target in zip(requests,targets):
        call(dict(operation='remove',handle=target))
        assert record(target['sandbox_id'])['phase']=='collected'
        assert call(value)==target
        assert record(target['sandbox_id'])['phase']=='collected'
    seen['targets_collected_without_recreation']=True
    report['cases'].append('rootfs_target_collection_closes_original_durable_references_and_spent_targets_cannot_be_recreated')


def collect_observed(cfg):
    jobs=[]
    for path in sorted((Path(cfg['data_root'])/'rootfs').glob('boot-*.json')):
        job=json.loads(path.read_bytes())
        assert job['target']['reference']['installation']==cfg['installation_id']
        assert job['collection'] and job['collection']['target']==job['target']
        target=json.loads((Path(cfg['data_root'])/'records'/f'{job["target"]["sandbox"]}.json').read_bytes())
        assert target['phase']=='collected' and target['owner']['generation']==job['target']['generation']
        assert not os.path.lexists(job['target']['path'])
        suffix=uuid.UUID(cfg['installation_id']).hex+'-'+uuid.UUID(job['target']['generation']).hex
        assert all(not os.path.lexists(Path('/sys/fs/cgroup')/(prefix+'-'+suffix)) for prefix in ['ghv','ghs'])
        jobs.append(job)
    return dict(result='passed',references=jobs,all_original_target_references_closed=True)
