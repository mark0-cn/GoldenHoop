"""Actual journal checkpoint, Rust alias binding and independent owned collection."""
import argparse
import copy
import hashlib
import json
import queue
import subprocess
import threading
import uuid
from pathlib import Path

from network_provider_contract import Contract as ProviderContract


class Contract(ProviderContract):
    def __init__(self, args):
        super().__init__(args)
        self.report['suite'] = 'rust-native-bridge-binding'
        self.report['scope'] = 'Actual persisted native checkpoint and host alias only; no endpoint, packet, DNS, lease or workload publication'
        self.report['source_files_sha256']['tests/native_bridge_contract.py'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        self.report['alias_controls'] = []

    def command(self, name, entrypoint, capabilities=('NET_ADMIN',)):
        cmd = ['docker', 'run', '--rm', '--name', name, '--interactive',
               '--label', 'dev.goldenhoop.installation='+self.installation,
               '--label', 'dev.goldenhoop.role=network-provider-audit',
               '--label', 'dev.goldenhoop.test=network-provider',
               '--label', 'dev.goldenhoop.attempt='+self.attempt,
               '--runtime', 'runc', '--network', 'host', '--user', '0:0',
               '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
               '--memory', '128m', '--memory-swap', '128m', '--cpus', '0.25', '--pids-limit', '32']
        for capability in capabilities:
            cmd += ['--cap-add', capability]
        return cmd + ['--entrypoint', entrypoint, self.args.image]

    def collect_controller(self, name):
        ids = self.docker('ps', '-a', '--no-trunc', '--filter', 'name=^/'+name+'$', '--format', '{{.ID}}').stdout.split()
        for identity in ids:
            value = json.loads(self.docker('inspect', identity).stdout)[0]
            self.owned(value)
            assert value['Name'] == '/'+name
            self.docker('rm', '--force', identity)
        assert not self.docker('ps', '-a', '--filter', 'name=^/'+name+'$', '--format', '{{.ID}}').stdout.strip()

    def rpc_once(self, plan, expected=None, capabilities=('NET_ADMIN',)):
        name = 'goldenhoop-native-bind-'+uuid.uuid4().hex[:12]
        cmd = self.command(name, '/usr/local/libexec/goldenhoop-egress', capabilities)
        frame = {'id': 1, 'command': {'operation': 'bind_native', 'plan': plan}}
        try:
            result = subprocess.run(cmd, input=json.dumps(frame)+'\n', capture_output=True,
                                    text=True, encoding='utf-8', timeout=15,
                                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            assert result.returncode == 0, result.stderr
            lines = result.stdout.splitlines(); assert len(lines) == 1, result.stdout
            reply = json.loads(lines[0]); assert reply['id'] == 1
            self.report['alias_controls'].append({'request': frame, 'capabilities': list(capabilities), 'reply': reply})
            self.save()
            if expected:
                assert reply.get('error', {}).get('code') == expected, reply
                return reply
            assert set(reply) == {'id', 'result'}, reply
            return reply['result']
        finally:
            self.collect_controller(name)

    def link(self):
        name = 'goldenhoop-native-read-'+uuid.uuid4().hex[:12]
        try:
            result = subprocess.run(self.command(name, 'ip')+['--json', '--details', 'link', 'show', 'dev', self.bridge],
                                    capture_output=True, text=True, encoding='utf-8', timeout=15)
            assert result.returncode == 0, result.stderr
            links = json.loads(result.stdout); assert len(links) == 1
            return links[0]
        finally:
            self.collect_controller(name)

    def fixture_alias(self, alias):
        name = 'goldenhoop-native-fixture-'+uuid.uuid4().hex[:12]
        try:
            result = subprocess.run(self.command(name, 'ip')+['link', 'set', 'dev', self.bridge, 'alias', alias],
                                    capture_output=True, text=True, encoding='utf-8', timeout=15)
            assert result.returncode == 0, result.stderr
        finally:
            self.collect_controller(name)

    def binding_checks(self):
        checkpoint = self.report['native_checkpoint_recovered_from_file_database']
        assert checkpoint['phase'] == 'provisioning' and checkpoint['binding'] is None
        plan = {'identity': self.plan['identity'], 'allocation': checkpoint['native']['allocation'],
                'provisioning_token': self.plan['provisioning_token'], 'expires_at': self.plan['expires_at']}
        self.bridge = plan['allocation']['bridge']
        before = self.link(); assert not before.get('ifalias')
        assert before['ifindex'] == plan['allocation']['ifindex'] and before['linkinfo']['info_kind'] == 'bridge'
        for capabilities in ((), ('NET_ADMIN', 'NET_RAW')):
            self.rpc_once(plan, 'forbidden', capabilities)
        expired = copy.deepcopy(plan); expired['expires_at'] = '1970-01-01T00:00:00Z'
        self.rpc_once(expired, 'deadline_exceeded')
        wrong = copy.deepcopy(plan); wrong['allocation']['ifindex'] += 1
        self.rpc_once(wrong, 'conflict')
        foreign = copy.deepcopy(plan); foreign['allocation']['sandbox_id'] = str(uuid.uuid4())
        self.rpc_once(foreign, 'invalid_request')
        assert not self.link().get('ifalias')
        self.check('missing_extra_capabilities_expiry_and_foreign_native_identity_refuse_before_alias_mutation')
        for alias in ('foreign-fixture:'+self.attempt, '\n'):
            try:
                self.fixture_alias(alias)
                self.rpc_once(plan, 'conflict')
                assert self.link()['ifalias'] == alias
            finally:
                self.fixture_alias('')
        self.check('foreign_and_newline_aliases_remain_unchanged_after_rust_binding_refusal')
        bound = self.rpc_once(plan)
        assert bound['changed'] and bound['allocation'] == plan['allocation'] and bound['provisioning_token'] == plan['provisioning_token']
        observed = self.link(); assert observed['ifalias'] == bound['alias'] and observed['ifindex'] == before['ifindex']
        self.report['actual_alias_binding'] = {'plan': plan, 'reply': bound, 'independent_link': observed}
        self.check('rust_netlink_alias_ack_is_followed_by_matching_independent_native_identity')
        replay = self.rpc_once(plan); assert not replay['changed'] and replay['alias'] == bound['alias']
        self.check('an_identical_native_binding_replay_observes_without_replacing_the_alias')
        name = 'goldenhoop-native-manager-'+uuid.uuid4().hex[:12]
        child = None; reader = None
        try:
            child = subprocess.Popen(self.command(name, '/usr/local/libexec/goldenhoop-egress'),
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True, encoding='utf-8', creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            lines = queue.Queue()
            reader = threading.Thread(target=lambda: [lines.put(line) for line in child.stdout], daemon=True)
            reader.start()
            def rpc(identity, command):
                child.stdin.write(json.dumps({'id': identity, 'command': command})+'\n'); child.stdin.flush()
                reply = json.loads(lines.get(timeout=12)); assert reply['id'] == identity; return reply
            opened = rpc(1, {'operation': 'open', 'allocation': plan['allocation']})
            assert not opened['result']['installed'] and opened['result']['revision'] is None
            self.rpc_once(plan, 'conflict')
            refused = rpc(2, {'operation': 'bind_native', 'plan': plan})
            assert refused['error']['code'] == 'conflict'
            child.stdin.close(); child.stdin = None
            assert child.wait(timeout=12) == 0
            reader.join(timeout=2); assert not reader.is_alive()
        finally:
            self.collect_controller(name)
            if child:
                if child.poll() is None: child.kill()
                child.wait(timeout=10)
                if child.stdin: child.stdin.close()
                if reader: reader.join(timeout=2)
                child.stdout.close(); child.stderr.close()
        assert not self.rpc_once(plan)['changed']
        self.check('an_active_manager_blocks_same_process_and_separate_controller_binding_until_confirmed_exit')
        assert self.link()['ifalias'] == bound['alias'] and not self.audit()['owned_tables']
        self.report['alias_binding_created_no_packet_tables'] = True
        self.save()

    def check(self, name):
        super().check(name)
        if name == 'actual_exit_after_native_checkpoint_keeps_the_original_provider_and_index_without_source_or_packet_confirmation':
            self.binding_checks()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--image', default='goldenhoop-network-fixture:test')
    parser.add_argument('--agent-image', default='goldenhoop-agent:test')
    parser.add_argument('--work-dir', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--remove-image', action='store_true')
    parser.add_argument('--fail-after-create', action='store_true')
    Contract(parser.parse_args()).run()
