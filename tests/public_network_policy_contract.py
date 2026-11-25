"""Real public policy changes on a trusted, already protected allocation.

This does not test public initial provisioning or publish NetworkPolicy.
"""
import argparse
import copy
import hashlib
import json
import os
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from worker_network_policy_contract import Contract as WorkerContract, NoRedirect


DENY = {'default_action': 'deny', 'rules': []}
ALLOW = {'default_action': 'deny', 'rules': [
    {'destination': '93.184.216.34', 'ports': [443], 'action': 'allow'}]}


class Contract(WorkerContract):
    def __init__(self, args):
        super().__init__(args)
        self.api_process = None
        self.api_log = self.state / 'api.log'
        self.api_log_handle = None
        self.api_token = uuid.uuid4().hex
        self.endpoint = None
        self.report['suite'] = 'public-source-network-policy-api'
        self.report['scope'] = ('Real API, Rust SDK/CLI and production worker on a trusted '
            'already protected allocation; versioned intent, actual native acknowledgement, '
            'pause/restart/replay and cleanup. Public initial provisioning, hierarchy runtime '
            'and NetworkPolicy capability publication remain unverified.')
        self.report['cli_binary_sha256'] = hashlib.sha256(Path(args.cli_binary).read_bytes()).hexdigest()
        sources = [Path(__file__).resolve()]
        for crate in ('client', 'cli'):
            sources.extend((self.root / 'crates' / crate).rglob('*.rs'))
            sources.append(self.root / 'crates' / crate / 'Cargo.toml')
        for path in sources:
            self.report['source_files_sha256'][path.relative_to(self.root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()

    def start_api(self):
        assert self.api_process is None
        # Token stays in the host process environment, never a command, report,
        # image, mount, or workload environment.
        environment = os.environ.copy()
        environment['GOLDENHOOP_API_TOKEN'] = self.api_token
        self.api_log_handle = self.api_log.open('wb')
        command = [self.args.worker_binary, '--database', str(self.database), 'api', '--bind', '127.0.0.1:0']
        self.api_process = subprocess.Popen(command, env=environment, stdout=self.api_log_handle,
            stderr=subprocess.STDOUT, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            assert self.api_process.poll() is None, 'API process exited'
            for line in self.api_log.read_text(encoding='utf-8', errors='replace').splitlines():
                try:
                    frame = json.loads(line)
                except ValueError:
                    continue
                if frame.get('event') == 'api_started':
                    assert frame['installation_id'] == self.installation
                    assert frame['address'].startswith('127.0.0.1:')
                    self.endpoint = 'http://' + frame['address']
                    self.report.setdefault('api_starts', []).append(frame)
                    self.save()
                    return
            time.sleep(0.05)
        raise RuntimeError('API did not publish its actual bound address')

    def stop_api(self):
        if self.api_process is not None:
            if self.api_process.poll() is None:
                self.api_process.terminate()
            self.api_process.wait(timeout=15)
            assert self.api_process.poll() is not None
            self.api_process = None
            self.report['api_process_stopped'] = True
        if self.api_log_handle:
            self.api_log_handle.close()
            self.api_log_handle = None
        if self.api_log.exists():
            tail = self.api_log.read_text(encoding='utf-8', errors='replace')[-8192:]
            assert self.api_token not in tail
            self.report['api_log_tail'] = tail

    def stop_worker(self):
        try:
            self.stop_api()
        finally:
            super().stop_worker()

    def api(self, method, path, body=None, key=None, status=200, authenticated=True):
        headers = {'Content-Type': 'application/json'}
        if authenticated:
            headers['Authorization'] = 'Bearer ' + self.api_token
        if key:
            headers['Idempotency-Key'] = key
        request = urllib.request.Request(self.endpoint + path,
            data=json.dumps(body).encode() if body is not None else None, headers=headers, method=method)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        try:
            response = opener.open(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            actual = response.code
            value = json.load(response)
        self.report.setdefault('api_responses', []).append({'method': method, 'path': path,
            'status': actual, 'body': value})
        self.save()
        assert actual == status, (method, path, actual, value)
        return value

    def wait_operation(self, operation):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            current = self.api('GET', '/v1/operations/' + operation['id'])
            assert current['id'] == operation['id'] and current['resource_id'] == self.sandbox
            if current['state'] not in ('pending', 'running'):
                assert current['state'] == 'succeeded' and current['error'] is None, current
                return current
            time.sleep(0.25)
        raise RuntimeError('policy operation never obtained actual native acknowledgement')

    def cli(self, *arguments):
        environment = os.environ.copy()
        environment['GOLDENHOOP_API_TOKEN'] = self.api_token
        result = subprocess.run([self.args.cli_binary, '--endpoint', self.endpoint, *arguments],
            env=environment, capture_output=True, text=True, encoding='utf-8', timeout=90)
        assert self.api_token not in result.stdout + result.stderr
        self.report.setdefault('cli_calls', []).append({'arguments': arguments,
            'exit_code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr[-4096:]})
        self.save()
        assert result.returncode == 0, (result.returncode, result.stderr)
        return json.loads(result.stdout)

    def after_startup(self):
        frozen = self.report['bootstrap_result']['protected_binding']
        original = self.target_runtime()
        self.report['initial_owned_dns_spy'] = copy.deepcopy(self.report['owned_dns_spy'])
        self.start_upstream()
        staged = self.policy('stage-public', '--checkpoint-json', json.dumps(frozen), '--upstream', self.upstream)
        assert staged['phase'] == 'pending' and staged['owner'] is None and staged['observation'] is None
        assert staged['config']['policies'] == [DENY]
        lineage = staged['public_inputs']['lineage']
        assert len(lineage) == 1 and lineage[0]['sandbox_id'] == self.sandbox and lineage[0]['revision'] == 0
        assert len(lineage[0]['policy_sha256']) == 64
        self.check('public_source_binding_is_derived_from_stored_intent_and_never_reconstructs_a_lease')
        self.start_live_worker()
        _, active = self.wait_state('running', 0)
        self.command('goldenhoop_public_initial_deny')
        self.start_api()
        path = '/v1/sandboxes/' + self.sandbox + '/network-policy'
        self.api('GET', path, status=401, authenticated=False)
        initial = self.api('GET', path)
        assert initial == {'sandbox_id': self.sandbox, 'revision': 0, 'policy': DENY}
        assert self.cli('network-policy', self.sandbox) == initial
        self.check('authenticated_API_and_Rust_SDK_return_only_versioned_user_intent')
        request = {'expected_revision': 0, 'policy': ALLOW}
        key = uuid.uuid4().hex
        changed = self.api('PUT', path, request, key, status=202)
        assert changed['policy'] == {'sandbox_id': self.sandbox, 'revision': 1, 'policy': ALLOW}
        assert changed['operation']['state'] == 'pending'
        self.wait_operation(changed['operation'])
        _, allowed = self.wait_state('running', 1)
        assert allowed['owner'] == active['owner']
        assert allowed['public_inputs']['lineage'][0]['revision'] == 1
        assert allowed['config']['policies'] == [ALLOW]
        assert allowed['observation']['binding']['expires_at'] == frozen['expires_at']
        self.report['independent_public_allow_native'] = self.source_audit(
            allowed['observation']['binding'], self.report['bootstrap_native_alias']['alias'])
        self.command('goldenhoop_public_allow_confirmed')
        self.same_runtime(original)
        self.check('a_public_change_succeeds_only_after_actual_protected_native_readback_in_the_same_held_session')
        assert self.api('PUT', path, {'expected_revision': 0, 'policy': DENY}, uuid.uuid4().hex, status=409)['code'] == 'conflict'
        assert self.api('PUT', path, {'expected_revision': 1, 'policy': DENY}, key, status=409)['code'] == 'conflict'
        self.api('PUT', path, {'expected_revision': 1, 'policy': DENY, 'allow_always': []}, uuid.uuid4().hex, status=400)
        assert self.api('GET', path) == changed['policy']
        replay = self.api('PUT', path, request, key, status=202)
        assert replay['policy'] == changed['policy'] and replay['operation']['id'] == changed['operation']['id']
        assert replay['operation']['state'] == 'succeeded'
        self.check('stale_revisions_key_reuse_and_privileged_fields_refuse_without_mutating_intent')
        policy_file = self.state / 'desired-policy.json'
        policy_file.write_text(json.dumps(DENY), encoding='utf-8')
        tightened = self.cli('network-policy-set', self.sandbox, '--policy', str(policy_file),
            '--expected-revision', '1', '--idempotency-key', uuid.uuid4().hex)
        assert tightened['operation']['state'] == 'succeeded' and tightened['policy']['revision'] == 2
        _, denied = self.wait_state('running', 2)
        assert denied['owner'] == active['owner'] and denied['config']['policies'] == [DENY]
        assert denied['config_sha256'] != allowed['config_sha256']
        self.command('goldenhoop_Rust_SDK_tightening_confirmed')
        self.same_runtime(original)
        self.check('CLI_and_Rust_SDK_wait_for_a_real_tightened_policy_without_recreating_the_workload')
        lifecycle = '/v1/sandboxes/' + self.sandbox
        pause = self.api('POST', lifecycle + '/pause', key=uuid.uuid4().hex, status=202)
        self.wait_operation(pause)
        self.wait_state('paused')
        assert self.target_runtime()['State']['Paused'] and self.control()['phase'] == 'fenced'
        pending_request = {'expected_revision': 2, 'policy': DENY}
        pending_key = uuid.uuid4().hex
        pending = self.api('PUT', path, pending_request, pending_key, status=202)
        assert pending['policy']['revision'] == 3 and pending['operation']['state'] == 'pending'
        time.sleep(2)
        assert self.api('GET', '/v1/operations/' + pending['operation']['id'])['state'] == 'pending'
        self.stop_api()
        self.start_api()
        assert self.api('GET', path) == pending['policy']
        replay = self.api('PUT', path, pending_request, pending_key, status=202)
        assert replay['operation']['id'] == pending['operation']['id'] and replay['operation']['state'] == 'pending'
        self.check('paused_policy_intent_and_idempotency_survive_API_restart_without_an_application_claim')
        resume = self.api('POST', lifecycle + '/resume', key=uuid.uuid4().hex, status=202)
        self.wait_operation(resume)
        self.wait_operation(pending['operation'])
        _, resumed = self.wait_state('running', 3)
        assert resumed['owner']['controller_generation'] != active['owner']['controller_generation']
        assert resumed['public_inputs']['lineage'][0]['revision'] == 3
        assert resumed['config_sha256'] == denied['config_sha256']
        self.command('goldenhoop_same_config_new_source_acknowledged')
        self.same_runtime(original)
        self.check('equal_effective_config_still_requires_the_new_source_revision_and_a_fresh_epoch_after_resume')
        logs = [json.loads(line) for line in self.docker('logs', self.upstream_id).stdout.splitlines()]
        assert not any(row.get('unexpected_query') for row in logs)
        self.report['owned_dns_spy']['logs'] = logs
        self.owned(json.loads(self.docker('inspect', self.upstream_id).stdout)[0])
        self.docker('rm', '--force', '--volumes', self.upstream_id)
        self.api('DELETE', lifecycle, key=uuid.uuid4().hex, status=202)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'worker-binary', 'policy-binary', 'cli-binary', 'work-dir', 'output'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--runtime', choices=['runc', 'runsc'], default='runc')
    parser.add_argument('--mode', choices=['full'], default='full')
    parser.add_argument('--image', default='goldenhoop-network-fixture:test')
    parser.add_argument('--agent-image', default='goldenhoop-agent:test')
    parser.add_argument('--controller-image', default='goldenhoop-egress:test')
    parser.add_argument('--remove-image', action='store_true')
    Contract(parser.parse_args()).run()
