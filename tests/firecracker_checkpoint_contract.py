"""Actual Rust capture/inspect/collect on owned KVM guests, never a restore test."""
import base64
import json
from pathlib import Path
import stat
import subprocess
import uuid


def suite(binary, boot, fixture, continuation=False):
    report = {'result': 'failed', 'cleanup': 'unknown', 'cases': [], 'observations': {},
              'scope': 'actual private full capture and retained content; no target load or public snapshot capability'}
    configs, children = [], []
    sources_collected = True

    def config(name, budget):
        value = {'root': str(fixture/name), 'installation': str(uuid.uuid4()),
                 'capture': str(uuid.uuid4()), 'policy': {'max_bytes': budget, 'max_checkpoints': 1}}
        path = fixture/(name+'.json'); path.write_text(json.dumps(value), encoding='utf-8'); path.chmod(0o400)
        configs.append((path, value)); return path, value

    def command(operation, path, expect=True):
        process = subprocess.run([str(binary), operation, '--config', str(path)], capture_output=True, timeout=120)
        if expect:
            assert process.returncode == 0 and not process.stderr, process.stderr.decode(errors='replace')[-2500:]
            return json.loads(process.stdout)
        assert process.returncode != 0, 'corrupt Ready content was accepted'
        return process.stderr.decode(errors='replace')[-2500:]

    boot_path = fixture/'checkpoint-boot.json'
    boot_path.write_text(json.dumps(boot), encoding='utf-8'); boot_path.chmod(0o400)

    def probe(path, expect):
        nonlocal sources_collected
        sources_collected = False
        process = subprocess.Popen([str(binary), 'probe-guest', '--config', str(boot_path),
                                    '--checkpoint-config', str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        children.append(process)
        try:
            stdout, stderr = process.communicate(timeout=300)
        except subprocess.TimeoutExpired:
            process.terminate(); stdout, stderr = process.communicate(timeout=45)
        value = json.loads(stdout)
        collected = value['cleanup'] == 'complete' and all(value[k] for k in ['root_absent', 'vmm_reaped', 'cgroup_absent'])
        sources_collected = collected
        assert collected, 'capture source VMM/jail/cgroup collection is unconfirmed'
        assert not stderr and process.returncode == (0 if expect else 2), (process.returncode, value.get('error'), stderr.decode(errors='replace'))
        assert value['passed'] is expect and value['guest_started'] and value['runtime_profile_published'] is False
        return value

    try:
        path, cfg = config('checkpoint-store', 4*1024**3)
        captured = probe(path, True); report['observations']['captured_source'] = captured
        capture = captured['checkpoint']; assert capture['phase'] == 'ready'
        assert capture['memory_marker_found'] and capture['verified_after_source_collection']
        reference = capture['reference']; assert reference['installation'] == cfg['installation'] and reference['capture'] == cfg['capture']
        ready = command('checkpoint-inspect', path); report['observations']['ready_after_source_absence'] = ready
        assert ready['phase'] == ready['capture_outcome'] == 'ready' and ready['content_verified']
        assert ready['reference'] == reference and ready['reserved_bytes'] == capture['reserved_bytes'] > 0
        manifest = ready['manifest']; assert manifest['source']['source_generation'] == captured['generation']
        assert manifest['barrier']['phase'] == 'quiesced' and manifest['barrier']['workload_frozen'] and manifest['barrier']['rootfs_synced']
        assert manifest['memory']['size_bytes'] == manifest['resources']['memory_bytes'] == 256*1024**2
        objects = {role: Path(cfg['root'])/f"capture-{cfg['capture']}-{role}.bin" for role in ['state', 'memory', 'disk']}
        for role, target in objects.items():
            metadata = target.lstat()
            assert stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0 and stat.S_IMODE(metadata.st_mode) == 0o400
            assert metadata.st_nlink == 1 and metadata.st_size == manifest[role]['size_bytes']
        report['cases'].append('actual_quiesced_paused_full_snapshot_publishes_three_verified_objects_outside_source_jail')
        marker = bytes.fromhex(capture['memory_marker_hex']); assert len(marker) == 32
        found, tail = False, b''
        with objects['memory'].open('rb') as stream:
            for block in iter(lambda: stream.read(65536), b''):
                data = tail+block; found |= marker in data; tail = data[-31:]
        assert found, 'independent reader did not find the actual guest-only RAM cookie'
        disk = subprocess.run(['debugfs', '-R', 'cat /workspace/checkpoint-payload', str(objects['disk'])],
                              capture_output=True, timeout=30, check=True)
        assert 'File not found' not in disk.stderr.decode(errors='replace')
        assert disk.stdout == base64.b64decode(capture['disk_marker_base64'], validate=True)
        report['observations']['independent_ram_cookie_and_drive_payload'] = {'ram_cookie_found': True,
            'disk_payload_base64': capture['disk_marker_base64'], 'source_already_collected': True}
        report['cases'].append('actual_guest_RAM_cookie_and_synced_copied_drive_nonce_survive_source_VMM_root_and_cgroup_collection')

        if continuation:
            from firecracker_continuation_contract import exercise
            restored = exercise(binary,boot,fixture,cfg,reference,capture,captured['generation'],manifest)
            report['observations']['continuation']=restored
            if restored['cleanup']!='complete':
                sources_collected=False
            assert restored['result']=='passed' and restored['cleanup']=='complete',restored.get('error')
            report['cases']+=['continuation:'+case for case in restored['cases']]

        quota_path, _ = config('checkpoint-quota', 256*1024**2)
        refused = probe(quota_path, False); report['observations']['quota_refusal'] = refused
        assert refused['checkpoint']['phase'] == 'admission'
        assert refused['checkpoint']['source_running_after_admission_refusal'] is True
        assert refused['checkpoint']['store_reserved_bytes_after_admission_refusal'] == 0
        report['cases'].append('actual_capture_quota_refusal_precedes_guest_quiescence_and_preserves_source_health')

        # A deliberate corruption in a precise task-created object. The Rust
        # collector must still use ownership receipts rather than repair bytes.
        with objects['state'].open('r+b') as stream:
            first = stream.read(1); assert first
            stream.seek(0); stream.write(bytes([first[0] ^ 1])); stream.flush()
            import os
            os.fsync(stream.fileno())
        error = command('checkpoint-inspect', path, False)
        assert 'corrupt' in error or 'content' in error, error
        report['observations']['corruption_refusal'] = error
        report['cases'].append('altered_owned_state_file_is_rejected_by_Rust_reference_inspection')
        report['result'] = 'passed'
    except Exception as error:
        report['error'] = f'{type(error).__name__}: {error}'
    finally:
        errors = []
        for process in children:
            if process.poll() is None:
                try:
                    process.terminate(); process.communicate(timeout=45)
                except Exception as error:
                    errors.append(f'capture caller still unconfirmed: {error}')
                    sources_collected = False
        collections = report['observations']['collections'] = []
        if sources_collected:
            for path, cfg in configs:
                store = Path(cfg['root']); record = store/f"capture-{cfg['capture']}.json"
                try:
                    if record.exists() or path.name == 'checkpoint-store.json':
                        # Rust also reconciles an inode-bound pending record
                        # after the original producer has actually exited.
                        value = command('checkpoint-collect', path)
                        assert value['phase'] == 'collected' and value['objects_absent'] is True and value['reserved_bytes'] == 0
                        collections.append(value)
                    else:
                        # Only the positively observed quota refusal has no
                        # capture record. It never dispatched any guest effect.
                        assert path.name == 'checkpoint-quota.json' and report['observations']['quota_refusal']['checkpoint']['store_reserved_bytes_after_admission_refusal'] == 0
                    for role in ['state', 'memory', 'disk']:
                        target = store/f"capture-{cfg['capture']}-{role}.bin"
                        try: target.lstat()
                        except FileNotFoundError: pass
                        else: raise AssertionError(f'exact checkpoint object still present: {target.name}')
                except Exception as error:
                    errors.append(str(error))
        else:
            errors.append('source absence unconfirmed; checkpoint reservation and fixtures retained')
        report['cleanup'] = 'complete' if not errors and sources_collected else 'unknown'
        if errors:
            report['cleanup_errors'] = errors; report['result'] = 'failed'
        elif report['result'] == 'passed':
            report['cases'].append('Rust_exact_source_fenced_capture_collection_observes_all_owned_object_absence_and_releases_reservation')
    return report
