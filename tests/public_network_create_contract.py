"""Actual public protected creation, availability, five-level lineage and cleanup."""
import argparse
import base64
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import time
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from api_contract import Contract as ApiContract, ApiFailure, docker
from guarded_bootstrap_samples import UPSTREAM

DENY = {'default_action': 'deny', 'rules': []}
ALLOW = {'default_action': 'allow', 'rules': []}
LIMITED = {'default_action': 'deny', 'rules': [
    {'destination': '93.184.216.34', 'ports': [443], 'action': 'allow'}]}
LIMITS = {'cpu_millis': 500, 'memory_bytes': 268435456, 'pids': 64}


class Contract(ApiContract):
    def __init__(self, args):
        super().__init__(args)
        self.report = {'suite': 'public-protected-network-creation', 'runtime': args.runtime,
            'mode': args.mode, 'timestamp': datetime.now(timezone.utc).isoformat(),
            'temporary_directory': str(self.root), 'result': 'failed', 'cleanup': 'unknown', 'cases': []}
        self.controller = None
        self.spy = None
        self.maintenance = False
        self.members = []
        self.physical = {}
        self.config = self.root / 'network.json'
        self.profile = 'local-gvisor' if args.runtime == 'runsc' else 'local-runc-dev'

    def save(self):
        path = Path(self.args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.report, indent=2) + '\n', encoding='utf-8', newline='\n')

    def check(self, name):
        self.report['cases'].append({'name': name, 'result': 'passed'})
        self.save()
        print('passed: ' + name, flush=True)

    def request(self, *args, **kwargs):
        value = super().request(*args, **kwargs)
        self.report.setdefault('api_responses', []).append({'method': args[0], 'path': args[1], 'body': value})
        self.save()
        return value

    def launch(self, role):
        path = self.root / f'{role}-{len(self.logs)}.log'
        handle = path.open('wb')
        self.logs.append(path)
        self.log_handles.append(handle)
        command = [self.args.binary, '--database', str(self.database), role]
        environment = {k: v for k, v in os.environ.items()
            if not k.startswith('GOLDENHOOP_ARTIFACT_') and k not in
            ('GOLDENHOOP_KERNEL_PROBE_IMAGE', 'GOLDENHOOP_API_TOKEN', 'GOLDENHOOP_EGRESS_CONTROLLER_IMAGE')}
        if role == 'api':
            environment['GOLDENHOOP_API_TOKEN'] = self.token
            command += ['--bind', '127.0.0.1:0']
        else:
            command += ['--agent-image', self.args.image, '--egress-controller-image', self.controller]
            if not self.maintenance:
                command += ['--network-config', str(self.config)]
            if self.args.runtime == 'runc':
                command += ['--allow-runc-development']
        process = subprocess.Popen(command, env=environment, stdin=subprocess.DEVNULL,
            stdout=handle, stderr=subprocess.STDOUT, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        self.processes[role] = process
        observations = None
        previous = None
        if role == 'worker':
            observations = {'log': path.name, 'scope': 'read-only metadata; no native lease or absence receipt',
                'samples': [], 'dropped_samples': 0}
            self.report.setdefault('startup_state_observations', []).append(observations)
        # Includes a new actual native root/child deployment probe; existing
        # generic API startup and command deadlines are not changed.
        deadline = time.monotonic() + (240 if role == 'worker' else 15)
        while time.monotonic() < deadline:
            assert process.poll() is None, path.read_text(encoding='utf-8', errors='replace')[-8192:]
            if observations is not None:
                try:
                    with closing(sqlite3.connect(self.database.as_uri() + '?mode=ro', uri=True, timeout=0.1)) as connection:
                        rows = connection.execute("SELECT b.id,s.parent_id,b.state,b.desired,b.cleanup,json_extract(b.payload,'$.reason'),json_extract(p.payload,'$.phase') FROM sandboxes b JOIN sandbox_scopes s ON s.sandbox_id=b.id LEFT JOIN network_policies p ON p.sandbox_id=b.id ORDER BY b.id").fetchall()
                    if rows != previous:
                        previous = rows
                        observations['samples'].append({'at': datetime.now(timezone.utc).isoformat(),
                            'nodes': [dict(zip(('id', 'parent_id', 'state', 'desired', 'cleanup', 'reason', 'policy_phase'), row)) for row in rows]})
                        if len(observations['samples']) > 256:
                            del observations['samples'][0]
                            observations['dropped_samples'] += 1
                        self.save()
                except sqlite3.Error as error:
                    errors = observations.setdefault('read_errors', [])
                    if len(errors) < 4:
                        errors.append(repr(error))
                observer = getattr(self, 'observe_startup', None)
                if observer is not None:
                    observer()
            for line in path.read_text(encoding='utf-8', errors='replace').splitlines():
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if event.get('event') == role + '_started':
                    if role == 'api':
                        self.base = 'http://' + event['address']
                        assert not self.installation or self.installation == event['installation_id']
                        self.installation = event['installation_id']
                        self.report['installation_id'] = self.installation
                    return
            time.sleep(0.1)
        raise RuntimeError('protected worker startup observation timed out')

    def rows(self, table):
        assert table in ('sandboxes', 'network_allocations', 'network_controllers', 'network_policies',
            'network_create_dispatches', 'network_policy_events', 'executions', 'events', 'operations')
        with closing(sqlite3.connect(self.database.as_uri() + '?mode=ro', uri=True, timeout=2)) as connection:
            return [json.loads(row[0]) for row in connection.execute('SELECT payload FROM ' + table)]

    def wait(self, operation, expected='succeeded'):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            current = self.request('GET', '/v1/operations/' + operation['id'])
            if current['state'] not in ('pending', 'running'):
                assert current['state'] == expected, current
                return current
            time.sleep(0.2)
        raise RuntimeError('public protected operation did not settle')

    def cli(self, *arguments):
        environment = os.environ.copy()
        environment['GOLDENHOOP_API_TOKEN'] = self.token
        result = subprocess.run([self.args.cli, '--endpoint', self.base, *arguments], env=environment,
            capture_output=True, text=True, encoding='utf-8', timeout=90)
        assert self.token not in result.stdout + result.stderr
        self.report.setdefault('cli_calls', []).append({'arguments': arguments,
            'exit_code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr[-4096:]})
        self.save()
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    def ready(self, ids):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            observations = []
            try:
                for identity in ids:
                    diagnostics = self.request('GET', f'/v1/sandboxes/{identity}/diagnostics')
                    sample = diagnostics['runtime']
                    if diagnostics['sandbox']['state'] != 'running' or sample is None or not sample['running'] or sample['paused']:
                        break
                    assert diagnostics['sandbox']['id'] == sample['sandbox_id'] == identity
                    observations.append(diagnostics)
                if len(observations) == len(ids):
                    self.report.setdefault('live_diagnostics', []).append(observations)
                    self.save()
                    return
            except ApiFailure as error:
                assert error.error['code'] in ('backend_unavailable', 'invalid_state'), error
            time.sleep(0.2)
        raise RuntimeError('actual private lease-gated diagnostics did not become ready')

    def snapshot(self, name):
        self.ready(self.members)
        controls = {row['sandbox_id']: row for row in self.rows('network_policies')}
        dispatches = self.rows('network_create_dispatches')
        for depth, identity in enumerate(self.members):
            control = controls[identity]
            assert control['phase'] == 'active' and control['observation']['config_sha256'] == control['config_sha256']
            assert [s['sandbox_id'] for s in control['public_inputs']['lineage']] == self.members[:depth + 1]
            assert len(control['config']['policies']) == depth + 1
            creates = [r for r in dispatches if r['sandbox_id'] == identity]
            assert {r['kind'] for r in creates} == {'bridge', 'workload'}
            assert all(r['settled_at'] is not None and r['allocation_generation'] == control['allocation_generation'] for r in creates)
            runtime_ids = docker('ps', '-aq', '--no-trunc', '--filter', 'label=dev.goldenhoop.installation=' + self.installation,
                '--filter', 'label=dev.goldenhoop.sandbox=' + identity, '--filter', 'label=dev.goldenhoop.role=sandbox').split()
            assert len(runtime_ids) == 1
            actual = json.loads(docker('inspect', runtime_ids[0]))[0]
            value = {k: actual['State'][k] for k in ('Pid', 'StartedAt')}
            value['Id'] = actual['Id']
            if identity in self.physical:
                assert self.physical[identity] == value
            else:
                self.physical[identity] = value
        self.report.setdefault('policy_snapshots', []).append({'name': name,
            'controls': [controls[i] for i in self.members], 'dispatches': dispatches, 'physical': dict(self.physical)})
        self.save()

    def command(self, identity, marker):
        execution = self.request('POST', f'/v1/sandboxes/{identity}/commands',
            {'argv': ['/bin/sh', '-c', 'printf ' + marker], 'timeout_seconds': 10}, str(uuid.uuid4()))
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            current = self.request('GET', '/v1/executions/' + execution['id'])
            if current['state'] in ('succeeded', 'failed', 'cancelled', 'timed_out'):
                assert current['state'] == 'succeeded' and current['exit_code'] == 0, current
                with closing(sqlite3.connect(self.database.as_uri() + '?mode=ro', uri=True, timeout=2)) as connection:
                    events = [json.loads(row[0]) for row in connection.execute(
                        'SELECT payload FROM events WHERE execution_id=? ORDER BY sequence', (execution['id'],))]
                stdout = b''.join(base64.b64decode(e['data']['data']) for e in events if e['kind'] == 'stdout')
                assert stdout == marker.encode() and len([e for e in events if e['kind'] == 'completed']) == 1
                self.report.setdefault('command_events', []).append({'execution': current, 'events': events})
                self.save()
                return
            time.sleep(0.1)
        raise RuntimeError('explicit command exit was not collected')

    def start_spy(self):
        self.spy = docker('run', '--detach', '--label', 'dev.goldenhoop.installation=' + self.installation,
            '--label', 'dev.goldenhoop.role=network-provider-audit', '--network', 'host', '--runtime', 'runc',
            '--user', '1000:1000', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--read-only',
            '--memory', '64m', '--memory-swap', '64m', '--cpus', '0.25', '--pids-limit', '16',
            '--entrypoint', 'python3', self.args.image, '-B', '-u', '-c', getattr(self, 'dns_upstream_source', UPSTREAM))
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            rows = [json.loads(line) for line in docker('logs', self.spy).splitlines()]
            ready = next((row for row in rows if row.get('ready')), None)
            if ready:
                self.config.write_text(json.dumps({'upstream': ready['endpoint']}), encoding='utf-8')
                self.report['owned_upstream'] = {'container_id': self.spy, 'endpoint': ready['endpoint']}
                return
            time.sleep(0.05)
        raise RuntimeError('owned DNS upstream did not publish its bound port')

    def exercise(self):
        profiles = self.request('GET', '/v1/profiles')
        self.report['profiles'] = profiles
        target = next(p for p in profiles if p['id'] == self.profile)
        if self.args.mode == 'unavailable':
            assert target['availability'] == 'unavailable' and 'network_policy' not in target['capabilities']
            count = len(self.rows('sandboxes'))
            # validate_create reports an unavailable deployment as 503,
            # independently of the requested capability's implementation.
            self.reject('POST', '/v1/sandboxes', 503, 'backend_unavailable', body={
                'profile': self.profile, 'image': self.args.image, 'required_capabilities': ['network_policy']}, key=str(uuid.uuid4()))
            assert len(self.rows('sandboxes')) == count
            assert all(s['cleanup'] == 'complete' for s in self.rows('sandboxes'))
            self.check('missing_bridge_support_refuses_public_admission_after_actual_probe_collection_without_fallback')
            return
        assert target['availability'] == 'available' and {'network_policy', 'isolated_sessions'} <= set(target['capabilities'])
        assert self.request('GET', '/v1/sandboxes')['items'] == []
        assert self.rows('sandboxes') and all(s['cleanup'] == 'complete' for s in self.rows('sandboxes'))
        self.check('NetworkPolicy_is_advertised_only_after_real_root_child_application_and_positive_probe_collection')
        limited = self.root / 'limited.json'
        limited.write_text(json.dumps(LIMITED), encoding='utf-8')
        broad = self.root / 'broad.json'
        broad.write_text(json.dumps(ALLOW), encoding='utf-8')
        common = ['--cpu-millis', '500', '--memory-bytes', '268435456', '--pids', '64']
        created = self.cli('create', '--profile', self.profile, '--image', self.args.image, '--ttl', '900',
            *common, '--child-cpu-millis', '2000', '--child-memory-bytes', '1073741824',
            '--child-pids', '256', '--network-policy', str(limited))
        assert created['operation']['state'] == 'succeeded'
        self.members.append(created['sandbox']['id'])
        original_expiry = created['sandbox']['expires_at']
        for depth in range(1, 5):
            parent = self.members[-1]
            remaining = 4 - depth
            if depth == 1:
                child = self.cli('isolated-create', parent, *common, '--network-policy', str(broad),
                    '--child-cpu-millis', str(remaining * 500), '--child-memory-bytes', str(remaining * 268435456),
                    '--child-pids', str(remaining * 64))
            else:
                body = {'resources': LIMITS, 'network': ALLOW, 'required_capabilities': ['network_policy']}
                if remaining:
                    body['child_budget'] = {k: v * remaining for k, v in LIMITS.items()}
                child = self.request('POST', f'/v1/sandboxes/{parent}/isolated-sessions', body, str(uuid.uuid4()))
                self.wait(child['operation'])
            self.members.append(child['sandbox']['id'])
            scope = self.request('GET', f'/v1/sandboxes/{self.members[-1]}/scope')
            assert scope['root_id'] == self.members[0] and scope['parent_id'] == parent and scope['depth'] == depth
            assert child['sandbox']['expires_at'] == original_expiry
        self.snapshot('five_layers_initial')
        assert {s['id'] for s in self.request('GET', '/v1/sandboxes')['items']} == set(self.members)
        for identity in self.members:
            self.command(identity, 'goldenhoop_public_initial')
        self.check('public_API_and_CLI_create_five_distinct_protected_levels_with_intersected_current_lineage')
        root = self.members[0]
        path = f'/v1/sandboxes/{root}/network-policy'
        for revision, policy in [(0, DENY), (1, LIMITED)]:
            changed = self.request('PUT', path, {'expected_revision': revision, 'policy': policy}, str(uuid.uuid4()))
            self.wait(changed['operation'])
            self.snapshot('ancestor_revision_' + str(revision + 1))
        self.check('root_policy_changes_wait_for_all_five_native_source_acknowledgements_without_recreation')
        self.wait(self.request('POST', f'/v1/sandboxes/{root}/pause', key=str(uuid.uuid4())))
        for identity in self.members:
            assert self.request('GET', f'/v1/sandboxes/{identity}')['state'] == 'paused'
        pending_body = {'expected_revision': 2, 'policy': LIMITED}
        key = str(uuid.uuid4())
        pending = self.request('PUT', path, pending_body, key)
        time.sleep(2)
        assert self.request('GET', '/v1/operations/' + pending['operation']['id'])['state'] == 'pending'
        self.stop('api')
        self.launch('api')
        replay = self.request('PUT', path, pending_body, key)
        assert replay['operation']['id'] == pending['operation']['id'] and replay['operation']['state'] == 'pending'
        self.wait(self.request('POST', f'/v1/sandboxes/{root}/resume', key=str(uuid.uuid4())))
        self.wait(pending['operation'])
        self.snapshot('same_config_fresh_source_after_tree_resume')
        self.check('paused_source_intent_survives_API_restart_and_resume_requires_fresh_acknowledgements_for_the_tree')
        self.stop('worker')
        try:
            self.request('GET', f'/v1/sandboxes/{root}/diagnostics')
        except ApiFailure as error:
            assert error.error['code'] == 'backend_unavailable'
        else:
            raise AssertionError('dead worker replied through the private lease gate')
        uncertain = self.request('POST', '/v1/sandboxes', {'profile': self.profile,
            'image': self.args.image, 'ttl_seconds': 900, 'resources': LIMITS}, str(uuid.uuid4()))
        # Explicit owned-journal crash injection, while no worker is running.
        # It represents an error before allocation, never a fabricated receipt.
        with closing(sqlite3.connect(self.database)) as connection:
            row = connection.execute('SELECT payload,ever_running,handle FROM sandboxes WHERE id=?', (uncertain['sandbox']['id'],)).fetchone()
            assert not row[1] and row[2] is None
            value = json.loads(row[0])
            value.update(state='unknown', cleanup='unknown')
            connection.execute("UPDATE sandboxes SET state='unknown',cleanup='unknown',payload=? WHERE id=?", (json.dumps(value), uncertain['sandbox']['id']))
            connection.commit()
        self.launch('worker')
        self.snapshot('after_actual_worker_restart')
        self.command(self.members[-1], 'goldenhoop_deep_recovery')
        self.check('a_replacement_worker_reprobes_its_environment_then_recovers_existing_protected_identities_without_replay')
        self.wait(uncertain['operation'], 'failed')
        assert self.request('GET', '/v1/sandboxes/' + uncertain['sandbox']['id'])['cleanup'] == 'complete'
        assert not docker('ps', '-aq', '--filter', 'label=dev.goldenhoop.installation=' + self.installation,
            '--filter', 'label=dev.goldenhoop.sandbox=' + uncertain['sandbox']['id'])
        assert all(r['sandbox_id'] != uncertain['sandbox']['id'] for r in self.rows('network_allocations'))
        self.check('uncertainty_before_allocation_never_falls_through_to_none_network_creation')
        broken = self.request('POST', '/v1/sandboxes', {'profile': self.profile,
            'image': 'goldenhoop-missing-' + uuid.uuid4().hex, 'ttl_seconds': 120,
            'required_capabilities': ['network_policy']}, str(uuid.uuid4()))
        self.wait(broken['operation'], 'failed')
        assert self.request('GET', '/v1/sandboxes/' + broken['sandbox']['id'])['cleanup'] == 'complete'
        self.check('failed_workload_preparation_confirms_native_collection_before_reporting_cleanup_complete')
        self.wait(self.request('DELETE', '/v1/sandboxes/' + root, key=str(uuid.uuid4())))
        assert all(self.request('GET', f'/v1/sandboxes/{i}')['cleanup'] == 'complete' for i in self.members)
        self.check('root_termination_collects_every_descendant_runtime_controller_and_native_allocation')

    def cleanup(self):
        if not self.installation and self.database.exists():
            with closing(sqlite3.connect(self.database.as_uri() + '?mode=ro', uri=True)) as connection:
                row = connection.execute("SELECT value FROM meta WHERE key='installation_id'").fetchone()
                if row:
                    self.installation = row[0]
        if self.installation and ('api' not in self.processes or self.processes['api'].poll() is not None):
            self.stop('api')
            self.launch('api')
        if self.database.exists() and self.installation:
            with closing(sqlite3.connect(self.database.as_uri() + '?mode=ro', uri=True)) as connection:
                roots = [r[0] for r in connection.execute('SELECT b.id FROM sandboxes b JOIN sandbox_scopes s ON s.sandbox_id=b.id WHERE s.parent_id IS NULL AND b.cleanup<>\'complete\'')]
            for identity in roots:
                self.request('DELETE', '/v1/sandboxes/' + identity, key=str(uuid.uuid4()))
            if roots:
                self.stop('worker')
                self.maintenance = True
                self.launch('worker')
                deadline = time.monotonic() + 100
                while any(r['cleanup'] != 'complete' for r in self.rows('sandboxes')):
                    if time.monotonic() >= deadline:
                        raise RuntimeError('owned native recovery remains unknown; retain private journal')
                    time.sleep(0.2)
            assert all(r['phase'] == 'collected' for r in self.rows('network_allocations'))
            assert all(r['phase'] == 'collected' for r in self.rows('network_controllers'))
            allocations = self.rows('network_allocations')
            bridges, tables = [], set()
            for allocation in allocations:
                generation = uuid.UUID(allocation['generation']).hex
                assert allocation['bridge'] == 'ghn' + generation[:12]
                bridges.append(allocation['bridge'])
                tables.update(part + generation for part in ('gh_e_', 'gh_l_', 'gh_s_', 'gh_d_', 'gh_c_'))
            for role in list(self.processes):
                self.stop(role)
            name = 'goldenhoop-public-create-audit-' + uuid.uuid4().hex[:12]
            command = ['run', '--rm', '--name', name, '--label', 'dev.goldenhoop.installation=' + self.installation,
                '--label', 'dev.goldenhoop.role=network-provider-audit', '--network', 'host', '--runtime', 'runc',
                '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN', '--security-opt', 'no-new-privileges:true',
                '--read-only', '--memory', '128m', '--pids-limit', '32', '--entrypoint', '/bin/sh', self.controller,
                '-c', 'for bridge in "$@"; do test ! -e "/sys/class/net/$bridge" || exit 19; done; exec /usr/sbin/nft --json list tables',
                'goldenhoop-owned-check', *bridges]
            native = docker(*command)
            matching = [r['table'] for r in json.loads(native)['nftables'] if 'table' in r and r['table']['name'] in tables]
            assert not matching
            self.report['native_absence'] = {'bridges': bridges, 'table_scopes': sorted(tables),
                'inventory_sha256': hashlib.sha256(native.encode()).hexdigest(), 'matching': matching}
            for row in self.rows('network_controllers'):
                if row['container_id']:
                    self.report.setdefault('collected_controller_ids', []).append(row['container_id'])
            if self.spy:
                logs = [json.loads(line) for line in docker('logs', self.spy).splitlines()]
                assert not any(row.get('unexpected_query') for row in logs)
                self.report['upstream_logs'] = logs
                labels = json.loads(docker('inspect', self.spy))[0]['Config']['Labels']
                assert labels['dev.goldenhoop.installation'] == self.installation and labels['dev.goldenhoop.role'] == 'network-provider-audit'
                docker('rm', '--force', self.spy)
                self.spy = None
            assert not docker('ps', '-aq', '--filter', 'label=dev.goldenhoop.installation=' + self.installation)
            assert not docker('network', 'ls', '-q', '--filter', 'label=dev.goldenhoop.installation=' + self.installation)
            for volume in docker('volume', 'ls', '-q', '--filter', 'label=dev.goldenhoop.installation=' + self.installation).split():
                labels = json.loads(docker('volume', 'inspect', volume))[0]['Labels']
                assert labels['dev.goldenhoop.role'] == 'agent-bundle' and labels['dev.goldenhoop.installation'] == self.installation
                docker('volume', 'rm', volume)
            assert not docker('volume', 'ls', '-q', '--filter', 'label=dev.goldenhoop.installation=' + self.installation)
            self.report['owned_inventories_empty'] = True
        for role in list(self.processes):
            self.stop(role)
        for handle in self.log_handles:
            handle.close()
        self.report['process_logs'] = [p.read_text(encoding='utf-8', errors='replace')[-16384:] for p in self.logs]
        assert self.token not in json.dumps(self.report)
        assert self.root.resolve().is_relative_to(self.work) and self.root.name.startswith('goldenhoop-api-')
        self.temporary.cleanup()
        assert not self.root.exists()
        self.report['temporary_directory_absent'] = True

    def run(self):
        failure = None
        try:
            repository = Path(__file__).resolve().parents[1]
            paths = [repository / 'Cargo.toml', repository / 'Cargo.lock', Path(__file__).resolve(),
                repository / 'tests/api_contract.py', repository / 'tests/guarded_bootstrap_samples.py',
                repository / '.github/workflows/network-contract.yml']
            paths.extend((repository / 'crates').rglob('*.rs'))
            paths.extend((repository / 'crates').rglob('*.sql'))
            paths.extend((repository / 'crates').rglob('Cargo.toml'))
            self.report['source_files_sha256'] = {p.relative_to(repository).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
            self.report['binaries_sha256'] = {n: hashlib.sha256(Path(p).read_bytes()).hexdigest() for n, p in [('server', self.args.binary), ('cli', self.args.cli)]}
            image = json.loads(docker('image', 'inspect', self.args.controller_image))[0]
            assert image['Config']['Labels']['dev.goldenhoop.egress'] == 'host-netfilter'
            self.controller = image['Id']
            self.report['controller_image_id'] = self.controller
            self.report['agent_image_id'] = json.loads(docker('image', 'inspect', self.args.image))[0]['Id']
            self.launch('api')
            self.start_spy()
            self.launch('worker')
            self.exercise()
            self.report['result'] = 'passed'
        except BaseException as error:
            failure = error
            self.report['error'] = repr(error)
        finally:
            # Preserve actual private probe history before collection/removing
            # the test database. Separate read-only snapshots are diagnostics;
            # they do not grant a live lease or attest native absence.
            if self.database.exists():
                try:
                    self.report['pre_cleanup_journal'] = {
                        'captured_at': datetime.now(timezone.utc).isoformat(),
                        'separate_read_only_snapshots': True,
                        'tables': {table: self.rows(table) for table in (
                            'sandboxes', 'network_allocations', 'network_controllers', 'network_policies',
                            'network_create_dispatches', 'network_policy_events', 'executions', 'events', 'operations')}}
                    self.save()
                except BaseException as error:
                    self.report['journal_observation_error'] = repr(error)
            try:
                self.cleanup()
                self.report['cleanup'] = 'complete'
            except BaseException as error:
                failure = failure or error
                self.report.update(result='failed', cleanup='unknown', cleanup_error=repr(error))
                for role in list(self.processes):
                    self.stop(role)
                # Preserve the journal and evidence if actual absence is unknown.
                self.temporary._finalizer.detach()
            self.save()
            print(json.dumps({k: self.report.get(k) for k in ('result', 'cleanup', 'error', 'cleanup_error')}), flush=True)
        if failure:
            raise failure


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--cli', required=True)
    parser.add_argument('--image', default='goldenhoop-agent:test')
    parser.add_argument('--controller-image', default='goldenhoop-egress:test')
    parser.add_argument('--runtime', choices=['runc', 'runsc'], default='runc')
    parser.add_argument('--mode', choices=['full', 'unavailable'], default='full')
    parser.add_argument('--work-dir', required=True)
    parser.add_argument('--output', required=True)
    parser.set_defaults(kernel_image=None, code_languages=['python'])
    Contract(parser.parse_args()).run()
