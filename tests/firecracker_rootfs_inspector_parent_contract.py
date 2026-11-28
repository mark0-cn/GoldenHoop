"""Exercise the production Rust parent; Python only submits and observes."""
import json
import os
from pathlib import Path
import signal
import time
import uuid

from image_builder_contract import docker


def exercise(handle, primary, cfg, manager, call, rpc, record, report):
    root = Path(cfg['data_root'])/'rootfs'
    seen = report['observations']['rootfs_inspector_parent'] = {}

    def meta(capture):
        return json.loads((root/f'capture-{capture}.json').read_bytes())

    def accept(value):
        deadline = time.monotonic()+20
        while True:
            answer = call(value, expect=None)
            if answer['ok']:
                return answer['data']
            assert answer['error']['code'] in ['backend_unavailable', 'quota_exceeded'], answer
            assert time.monotonic() < deadline, answer
            time.sleep(.05)

    def status(capture):
        return call(dict(operation='rootfs_inspect', handle=handle, capture=capture))

    def finish(capture):
        deadline = time.monotonic()+100
        while True:
            value = status(capture)
            job = meta(capture).get('inspection_job')
            if job and job['phase'] == 'collected' and value['producer_settled']:
                # I/O settlement precedes the final Ready acknowledgement.
                # An acknowledged result must finish that publication too.
                if job['result'] is None or value['phase'] == 'ready' and value['inspection_verified']:
                    return value, job
            assert not job or job['phase'] != 'unconfirmed', job
            assert time.monotonic() < deadline, (value, job)
            time.sleep(.025)

    def resources_absent(job):
        containers = docker('ps', '-aq', '--no-trunc').decode().splitlines()
        assert all(not job[key] or job[key] not in containers for key in ['seeder_id', 'inspector_id'])
        base = 'ghri-'+uuid.UUID(job['intent']['installation_id']).hex+'-'+uuid.UUID(job['intent']['request']['generation']).hex
        volumes = docker('volume', 'ls', '-q').decode().splitlines()
        assert base+'-input' not in volumes and base+'-output' not in volumes
        host = job['host']
        assert host and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == host['boot_id']
        try:
            raw = Path(f'/proc/{host["pid"]}/stat').read_text().rsplit(')', 1)[1].split()
            assert int(raw[19]) != host['start_ticks'], host
        except FileNotFoundError:
            pass
        assert host['owned_cgroup'].startswith('/') and '..' not in Path(host['owned_cgroup']).parts
        assert not os.path.lexists(Path('/sys/fs/cgroup')/host['owned_cgroup'].lstrip('/'))
        return dict(immutable_container_ids_absent=True, owned_volumes_absent=True,
                    original_host_process_and_cgroup_absent=True)

    original_source = record(handle['sandbox_id'])
    accept(dict(operation='rootfs_validate', handle=handle, capture=primary))
    ready, first = finish(primary)
    seen['ready_attempt'] = dict(status=ready, journal=first)
    assert ready['phase'] == 'ready' and ready['inspection_verified']
    assert first['result']['passed'] and first['pending'] is None and first['error'] is None
    assert first['intent']['image'] == cfg['rootfs']['inspector_image']
    assert first['result']['inspection']['disk'] == meta(primary)['manifest']['disk']
    assert first['result']['inspection']['inventory'] == cfg['rootfs']['inventory']
    assert first['result']['inspection']['guest_config']['content'] == cfg['rootfs']['guest_config']
    seen['ready'] = dict(status=ready, journal=first, collection=resources_absent(first))
    assert call(dict(operation='rootfs_validate', handle=handle, capture=primary)) == ready
    assert meta(primary)['inspection_job'] == first
    report['cases'].append('actual_Rust_parent_streams_original_disk_and_authorizes_pinned_runsc_only_after_host_enforcement_then_collects_before_Ready')
    report['cases'].append('rootfs_ready_inspector_exact_retry_preserves_original_journal_and_never_reauthorizes_or_recreates_resources')

    interrupted = str(uuid.uuid4())
    accept(dict(operation='rootfs_capture', handle=handle, capture=interrupted))
    deadline = time.monotonic()+90
    while True:
        value = status(interrupted)
        assert value['phase'] != 'failed', value
        if value['phase'] == 'captured' and value['source_resumed'] and value['producer_settled']:
            break
        assert time.monotonic() < deadline, value
        time.sleep(.025)
    accept(dict(operation='rootfs_validate', handle=handle, capture=interrupted))
    deadline = time.monotonic()+100
    while True:
        job = meta(interrupted).get('inspection_job')
        if job and job['phase'] in ['authorization_dispatched', 'result_observed'] and job['host']:
            break
        assert not job or job['phase'] not in ['collected', 'unconfirmed'], job
        assert time.monotonic() < deadline, job
        time.sleep(.002)
    before_death = job
    death = manager.hard_kill()
    assert death['actual_process_absent'] and death['exit_status'] == -signal.SIGKILL
    # The committed result at the actual cut, rather than the earlier poll,
    # determines whether output may be accepted after original-provider GC.
    stopped = meta(interrupted)['inspection_job']
    assert stopped['phase'] in ['authorization_dispatched', 'result_observed', 'collecting'], stopped
    manager.start()
    accept(dict(operation='rootfs_validate', handle=handle, capture=interrupted))
    recovered, second = finish(interrupted)
    for key in ['intent', 'engine_id', 'host_boot_id', 'nonce', 'actor', 'seeder_id', 'inspector_id', 'host']:
        assert second[key] == stopped[key], key
    assert second['result'] == stopped['result']
    if stopped['result'] is None:
        assert recovered['phase'] == 'captured' and not recovered['inspection_verified'] and second['error']
    else:
        assert recovered['phase'] == 'ready' and recovered['inspection_verified']
    seen['producer_kill'] = dict(death=death, observed_cut=before_death['phase'], durable_cut=stopped['phase'],
        stopped_journal=stopped, recovered_journal=second, status=recovered, collection=resources_absent(second))
    after_source = record(handle['sandbox_id'])
    assert after_source['owner'] == original_source['owner'] and after_source['process'] == original_source['process']
    assert after_source['supervisor'] == original_source['supervisor'] and not after_source.get('rootfs_hold')
    assert rpc(handle, dict(method='ping'))['status'] == 'success'
    call(dict(operation='rootfs_collect', handle=handle, capture=interrupted))
    assert status(interrupted)['reserved_bytes'] == 0
    seen['interrupted_disk_absent'] = not os.path.lexists(root/f'capture-{interrupted}.disk')
    assert seen['interrupted_disk_absent']
    report['cases'].append('SIGKILL_actual_inspector_producer_reconciles_original_daemon_objects_and_host_receipt_without_replaying_authorization_or_adopting_unacknowledged_output')
    report['cases'].append('original_live_source_and_independent_ready_content_survive_inspector_producer_death_and_exact_secondary_disk_collection')


def collect_owned(cfg, manager, call, record):
    """Failure-path collection uses the Rust original-operation reconciler."""
    root = Path(cfg['data_root'])/'rootfs'
    paths = sorted(root.glob('capture-*.json')) if root.exists() else []
    originals = [json.loads(path.read_bytes()) for path in paths]
    for value in originals:
        assert value['intent']['source']['installation'] == cfg['installation_id']
    unfinished = any(not value['producer_settled'] or value.get('inspection_job') and value['inspection_job']['phase'] != 'collected' for value in originals)
    if unfinished:
        manager.ensure_collection_owner()
        death = manager.hard_kill()
        assert death['actual_process_absent'] and death['exit_status'] == -signal.SIGKILL
        manager.start()
    results = []
    for value in originals:
        source = value['intent']['source']
        original = record(source['sandbox'])
        assert original['owner']['generation'] == source['source_generation']
        handle = dict(sandbox_id=source['sandbox'], profile='local-firecracker',
                      backend_ref='fc1:'+cfg['installation_id']+':'+source['source_generation'])
        capture = source['capture']
        job = value.get('inspection_job')
        if job and job['phase'] != 'collected':
            call(dict(operation='rootfs_validate', handle=handle, capture=capture))
            deadline = time.monotonic()+25
            while True:
                current = call(dict(operation='rootfs_inspect', handle=handle, capture=capture))
                assert current['inspector']['phase'] != 'unconfirmed', current
                if current['inspector']['phase'] == 'collected' and current['producer_settled']:
                    break
                assert time.monotonic() < deadline, current
                time.sleep(.05)
        collected = call(dict(operation='rootfs_collect', handle=handle, capture=capture))
        assert collected['disk_absent'] and collected['reserved_bytes'] == 0
        assert not os.path.lexists(root/f'capture-{capture}.disk')
        results.append(dict(capture=capture, original_inspector_journal=value.get('inspection_job'), result=collected, disk_absent=True))
    installation = cfg['installation_id']
    labels = ['--filter', 'label=dev.goldenhoop.installation='+installation,
              '--filter', 'label=dev.goldenhoop.role=rootfs-inspection']
    assert not docker('ps', '-aq', *labels).strip()
    assert not docker('volume', 'ls', '-q', *labels).strip()
    return dict(result='passed', disks=results, original_provider_containers_and_volumes_absent=True)
