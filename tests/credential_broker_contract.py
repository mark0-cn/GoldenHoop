"""Actual production credential ingress, private storage and native convergence."""
import argparse
import asyncio
import base64
import hashlib
import ipaddress
import json
import os
import sqlite3
import subprocess
import sys
import time
import urllib.parse
import uuid
from contextlib import closing
from pathlib import Path

from api_contract import ApiFailure, Contract as ApiContract, docker
from public_network_create_contract import Contract as NetworkContract, LIMITS

CLIENT = r'''import http.client,json,os,ssl,urllib.parse
assert os.geteuid()==1000
u=urllib.parse.urlsplit(os.environ['GH_URL'])
context=ssl.create_default_context(cadata=os.environ['GH_PUBLIC_CA'])
c=(http.client.HTTPSConnection(u.hostname,u.port,context=context,timeout=8) if u.scheme=='https' else http.client.HTTPConnection(u.hostname,u.port,timeout=8))
headers=json.loads(os.environ.get('GH_HEADERS','{}'))
c.request(os.environ.get('GH_METHOD','GET'),u.path+('?' + u.query if u.query else ''),body=os.environ.get('GH_BODY'),headers=headers)
r=c.getresponse();assert r.status==200,r.status
assert r.getheader('X-Reflected-Credential') is None
assert r.read(129).decode()==os.environ['GH_EXPECTED_BODY']
c.close();print('credential_client_accepted',end='')
'''

DENIED_CLIENT = r'''import http.client,json,os,socket,ssl,urllib.parse
assert os.geteuid()==1000
u=urllib.parse.urlsplit(os.environ['GH_URL'])
context=ssl.create_default_context(cadata=os.environ['GH_PUBLIC_CA'])
c=(http.client.HTTPSConnection(u.hostname,u.port,context=context,timeout=5) if u.scheme=='https' else http.client.HTTPConnection(u.hostname,u.port,timeout=5))
try:
 c.request('GET',u.path,headers=json.loads(os.environ.get('GH_HEADERS','{}')))
 r=c.getresponse();assert r.status>=400,r.status
except (OSError,http.client.HTTPException):pass
finally:c.close()
print('credential_client_refused',end='')
'''

STREAM_CLIENT = r'''import http.client,json,os,ssl,urllib.parse
assert os.geteuid()==1000
u=urllib.parse.urlsplit(os.environ['GH_URL'])
c=http.client.HTTPSConnection(u.hostname,u.port,context=ssl.create_default_context(cadata=os.environ['GH_PUBLIC_CA']),timeout=8)
c.request('GET',u.path,headers=json.loads(os.environ['GH_HEADERS']))
r=c.getresponse();assert r.status==200,r.status
ticks=0
try:
 while True:
  line=r.readline(128)
  if not line:break
  if line.startswith(b'data: '):
   ticks+=1;print('credential_tick',ticks,flush=True)
except (OSError,http.client.HTTPException):pass
finally:c.close()
assert ticks>=13,ticks
print('credential_stream_collected',end='',flush=True)
'''


class Contract(NetworkContract):
    def __init__(self, args):
        super().__init__(args)
        self.report['suite'] = 'production-native-credential-broker'
        self.report['scope'] = 'Actual public API, untrusted UID HTTP/TLS traffic, owned upstream, durable audit and physical controller convergence'
        self.attempt = uuid.uuid4().hex
        self.receiver = self.receiver_network = None
        self.receiver_pending = self.network_pending = False
        self.control = None
        self.private_values = []
        self.key_file = self.root / 'credential-master.key'
        self.credential_config = self.root / 'credentials.json'
        self.packet_probe_observations = {}

    def observe_startup(self):
        # Read-only diagnostics during the private ordinary-UID probe. These
        # counters never attest policy authority or replace receiver evidence.
        try:
            with closing(sqlite3.connect(self.database.as_uri() + '?mode=ro', uri=True, timeout=0.1)) as database:
                rows = database.execute("SELECT id,sandbox_id,spec FROM executions WHERE state='running'").fetchall()
            for identity, sandbox, raw in rows:
                if 'goldenhoop_credential_profile_probe' not in raw:
                    continue
                progress = self.packet_probe_observations.setdefault(identity, dict(start=time.monotonic(), count=0))
                if progress['count'] >= 2 or time.monotonic() - progress['start'] < 0.5 + progress['count']:
                    continue
                progress['count'] += 1
                owner = self.controller_owner(sandbox)
                observed = json.loads(docker('inspect', owner['container_id']))[0]
                labels = observed['Config']['Labels']
                assert (labels['dev.goldenhoop.installation'] == self.installation
                        and labels['dev.goldenhoop.sandbox'] == sandbox
                        and labels['dev.goldenhoop.role'] == 'egress-controller')
                with closing(sqlite3.connect(self.database.as_uri() + '?mode=ro', uri=True, timeout=0.1)) as database:
                    allocation = json.loads(database.execute('SELECT payload FROM network_allocations WHERE sandbox_id=?', (sandbox,)).fetchone()[0])
                suffix = uuid.UUID(allocation['generation']).hex
                tables = {prefix + suffix for prefix in ('gh_e_', 'gh_l_', 'gh_s_', 'gh_d_', 'gh_c_')}
                native = json.loads(docker('exec', owner['container_id'], '/usr/sbin/nft', '--json', 'list', 'ruleset'))
                scoped = [row for row in native['nftables'] if any(
                    value.get('name' if kind == 'table' else 'table') in tables for kind, value in row.items())]
                self.report.setdefault('probe_packet_counter_observations', []).append(dict(
                    execution_id=identity, sandbox_id=sandbox, controller_id=owner['container_id'],
                    diagnostic_only=True, owned_tables=sorted(tables), native=scoped))
                self.save()
        except (sqlite3.Error, OSError, ValueError, AssertionError, KeyError, TypeError, IndexError, RuntimeError) as error:
            errors = self.report.setdefault('probe_packet_counter_observation_errors', [])
            if len(errors) < 3:
                errors.append(type(error).__name__)

    def launch(self, role):
        if not self.key_file.exists():
            result = subprocess.run([self.args.binary, 'vault-init', str(self.key_file)], capture_output=True, timeout=15)
            assert result.returncode == 0
            assert self.key_file.stat().st_size == 32
        previous = {k: os.environ.get(k) for k in ('GOLDENHOOP_CREDENTIAL_KEY_FILE', 'GOLDENHOOP_CREDENTIAL_CONFIG')}
        try:
            for key in previous:
                os.environ.pop(key, None)
            if role == 'api' or not self.maintenance:
                os.environ['GOLDENHOOP_CREDENTIAL_KEY_FILE'] = str(self.key_file)
            if role == 'worker' and not self.maintenance:
                os.environ['GOLDENHOOP_CREDENTIAL_CONFIG'] = str(self.credential_config)
            return super().launch(role)
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def start_spy(self):
        fixture = json.loads(docker('image', 'inspect', self.args.fixture_image))[0]
        assert fixture['Config']['Labels']['dev.goldenhoop.fixture'] == 'network-interop'
        network_name = 'goldenhoop-credential-receiver-' + self.attempt[:12]
        subnet = f'fd{self.attempt[:2]}:{self.attempt[2:6]}:{self.attempt[6:10]}::/64'
        self.network_pending = True
        self.report['receiver_network_intent'] = dict(name=network_name, subnet=subnet, attempt=self.attempt)
        self.save()
        self.receiver_network = docker('network', 'create', '--driver', 'bridge', '--ipv6', '--subnet', subnet,
            '--label', 'dev.goldenhoop.test=credential-broker-fixture', '--label', 'dev.goldenhoop.attempt=' + self.attempt, network_name)
        assert len(self.receiver_network) == 64
        self.network_pending = False
        source = Path('tests/fixtures/credential_receiver.py').read_text(encoding='utf-8')
        self.receiver_pending = True
        self.report['receiver_create_intent'] = dict(name=network_name, image_id=fixture['Id'])
        self.save()
        self.receiver = docker('create', '--name', network_name, '--network', self.receiver_network, '--runtime', 'runc',
            '--user', '1000:1000', '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,size=4m,uid=1000,gid=1000',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--cpus', '0.5', '--memory', '128m',
            '--memory-swap', '128m', '--pids-limit', '64', '--label', 'dev.goldenhoop.test=credential-broker-fixture',
            '--label', 'dev.goldenhoop.attempt=' + self.attempt, '--entrypoint', 'python3', fixture['Id'], '-B', '-u', '-c', source)
        assert len(self.receiver) == 64
        self.receiver_pending = False
        docker('start', self.receiver)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            logs = [json.loads(line) for line in docker('logs', self.receiver).splitlines() if line.startswith('{')]
            if any(row.get('ready') for row in logs):
                break
            state = json.loads(docker('inspect', self.receiver))[0]['State']
            assert state['Running'], state
            time.sleep(0.1)
        else:
            raise RuntimeError('owned credential receiver did not become ready')
        self.control = json.loads(docker('exec', self.receiver, 'cat', '/tmp/credential-fixture/control.json'))
        self.private_values.extend(self.control['tokens'].values())
        endpoint = json.loads(docker('inspect', self.receiver))[0]['NetworkSettings']['Networks'][network_name]
        assert endpoint['IPAddress'] == self.control['ipv4']
        assert ipaddress.ip_address(endpoint['GlobalIPv6Address']) == ipaddress.ip_address(self.control['ipv6'])
        dns_fixture = Path('tests/fixtures/credential_dns.py')
        self.dns_upstream_source = dns_fixture.read_text(encoding='utf-8').replace('MAPPING = {}',
            'MAPPING = ' + repr({key: self.control[key] for key in ('ipv4', 'ipv6')}), 1)
        super().start_spy()
        configuration = json.loads(self.config.read_text())
        configuration['private_exceptions'] = [self.control['ipv4'] + '/32', self.control['ipv6'] + '/128']
        self.config.write_text(json.dumps(configuration), encoding='utf-8')
        secure = self.url('https', '/exchange')
        options = dict(upstream_ca_pem=[self.control['public_ca']], exchanges={
            'fixture': dict(endpoint=secure, headers={'x-exchange-auth': self.control['tokens']['exchange-auth']}),
            'delayed': dict(endpoint=self.url('https', '/exchange-delayed'), headers={'x-exchange-auth': self.control['tokens']['exchange-auth']})},
            probe=dict(http_url=self.url('http', '/v1/probe'), https_url=self.url('https', '/v1/probe'),
                       credential=self.control['tokens']['alpha'], expected_body=self.control['expected_body']))
        self.credential_config.write_text(json.dumps(options), encoding='utf-8')
        self.credential_config.chmod(0o600)
        self.report['owned_receiver'] = dict(container_id=self.receiver, network_id=self.receiver_network,
            ipv4=self.control['ipv4'], ipv6=self.control['ipv6'], public_ca_sha256=hashlib.sha256(self.control['public_ca'].encode()).hexdigest())
        self.report['source_files_sha256']['tests/credential_broker_contract.py'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        self.report['source_files_sha256']['tests/fixtures/credential_receiver.py'] = hashlib.sha256(source.encode()).hexdigest()
        self.report['source_files_sha256']['tests/fixtures/credential_dns.py'] = hashlib.sha256(dns_fixture.read_bytes()).hexdigest()
        self.save()

    def url(self, scheme, path, ipv6=False):
        host = '[' + self.control['ipv6'] + ']' if ipv6 else self.control['ipv4']
        return f'{scheme}://{host}:{18443 if scheme == "https" else 18080}{path}'

    def controller_owner(self, sandbox):
        with closing(sqlite3.connect(self.database.as_uri() + '?mode=ro', uri=True)) as database:
            policy = json.loads(database.execute('SELECT payload FROM network_policies WHERE sandbox_id=?', (sandbox,)).fetchone()[0])
        return policy['owner']

    def workload_identity(self, sandbox):
        ids = docker('ps', '-aq', '--no-trunc', '--filter', 'label=dev.goldenhoop.installation=' + self.installation,
                     '--filter', 'label=dev.goldenhoop.sandbox=' + sandbox, '--filter', 'label=dev.goldenhoop.role=sandbox').split()
        assert len(ids) == 1
        observed = json.loads(docker('inspect', ids[0]))[0]
        return dict(Id=observed['Id'], Pid=observed['State']['Pid'], StartedAt=observed['State']['StartedAt'])

    def wait_credential(self, sandbox, binding, state='active', revision=None):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            record = self.request('GET', f'/v1/sandboxes/{sandbox}/credentials/{binding}')
            if record['state'] == state and record['applied_revision'] == record['revision'] and (revision is None or record['revision'] == revision):
                return record
            time.sleep(0.1)
        raise RuntimeError('credential intent did not converge through native ownership')

    def put(self, sandbox, binding, *, scheme='http', host=None, revision=0, injection=None, substitutions=None, source=None, prefix='/v1/'):
        return self.request('PUT', f'/v1/sandboxes/{sandbox}/credentials/{binding}', {
            'expected_revision': revision, 'binding': dict(scheme=scheme, host=host or self.control['ipv4'],
                port=18443 if scheme == 'https' else 18080, methods=['GET', 'POST'], path_prefix=prefix,
                injection=injection or {'kind': 'bearer'}, substitutions=substitutions or []),
            'secret': source or dict(kind='literal', value=self.control['tokens']['alpha'])})

    def start_client(self, sandbox, url, *, method='GET', headers=None, body=None, script=CLIENT, timeout=20):
        public = self.request('GET', f'/v1/sandboxes/{sandbox}/credential-ca')['certificate_pem']
        environment = dict(GH_URL=url, GH_PUBLIC_CA=public, GH_EXPECTED_BODY=self.control['expected_body'], GH_METHOD=method)
        if headers:
            environment['GH_HEADERS'] = json.dumps(headers)
        if body is not None:
            environment['GH_BODY'] = body
        return self.request('POST', f'/v1/sandboxes/{sandbox}/commands',
            dict(argv=['python3', '-c', script], env=environment, timeout_seconds=timeout, max_output_bytes=4096), key=str(uuid.uuid4()))

    def command_events(self, execution):
        with closing(sqlite3.connect(self.database.as_uri() + '?mode=ro', uri=True)) as database:
            events = [json.loads(row[0]) for row in database.execute('SELECT payload FROM events WHERE execution_id=? ORDER BY sequence', (execution['id'],))]
        return events

    def finish_client(self, execution, marker=b'credential_client_accepted', exact=True):
        result = self.wait_execution(execution['id'], limit=35)
        events = self.command_events(execution)
        stdout = b''.join(base64.b64decode(event['data']['data']) for event in events if event['kind'] == 'stdout')
        assert result['state'] == 'succeeded' and result['exit_code'] == 0, (result, events)
        assert (stdout == marker if exact else stdout.endswith(marker)) and sum(event['kind'] == 'completed' for event in events) == 1
        self.report.setdefault('credential_command_events', []).append(dict(execution=result, events=events))

    def command(self, sandbox, url, **kwargs):
        self.finish_client(self.start_client(sandbox, url, **kwargs))

    def receiver_logs(self):
        return [json.loads(line) for line in docker('logs', self.receiver).splitlines() if line.startswith('{')]

    def wait_receiver(self, predicate, limit=15):
        deadline = time.monotonic() + limit
        while time.monotonic() < deadline:
            selected = [row for row in self.receiver_logs() if predicate(row)]
            if selected:
                return selected
            time.sleep(0.1)
        raise AssertionError('owned receiver did not observe the required boundary')

    def assert_collected(self, owner):
        assert not docker('ps', '-aq', '--filter', 'id=' + owner['container_id'])
        self.report.setdefault('independently_collected_controller_ids', []).append(owner['container_id'])

    def policy(self, root, deny=False):
        path = f'/v1/sandboxes/{root}/network-policy'
        current = self.request('GET', path)
        rules = [] if deny else self.allowed_rules()
        operation = self.request('PUT', path, dict(expected_revision=current['revision'], policy=dict(default_action='deny', rules=rules)), key=str(uuid.uuid4()))
        self.wait(operation['operation'])
        self.ready([root])

    def create_source(self):
        rules = self.allowed_rules()
        created = self.request('POST', '/v1/sandboxes', dict(profile=self.profile, image=self.args.image, resources=LIMITS,
            ttl_seconds=900, network=dict(default_action='deny', rules=rules), required_capabilities=['network_policy', 'secret_injection']), key=str(uuid.uuid4()))
        identity = created['sandbox']['id']
        self.members.append(identity)
        self.wait(created['operation'])
        self.ready([identity])
        self.physical[identity] = self.workload_identity(identity)
        return identity

    def allowed_rules(self):
        return [dict(destination=host, ports=[18080, 18443], action='allow')
                for host in (self.control['ipv4'], self.control['ipv6'], 'api.credential.test', 'other.credential.test')]

    def named_origin(self, root):
        binding = str(uuid.uuid4())
        self.put(root, binding, scheme='https', host='api.credential.test',
                 source=dict(kind='literal', value=self.control['tokens']['rotated']))
        self.wait_credential(root, binding)
        marker = uuid.uuid4().hex
        self.command(root, 'https://api.credential.test:18443/v1/named', headers={'X-Fixture-Request': marker})
        rows = self.wait_receiver(lambda row: row.get('request_id') == marker)
        assert len(rows) == 1 and rows[0]['secret_sha256'] == hashlib.sha256(self.control['tokens']['rotated'].encode()).hexdigest()
        marker = uuid.uuid4().hex
        execution = self.start_client(root, 'https://other.credential.test:18443/v1/named',
            headers={'X-Fixture-Request': marker}, script=DENIED_CLIENT)
        self.finish_client(execution, b'credential_client_refused')
        assert not any(row.get('request_id') == marker for row in self.receiver_logs())
        queries = [json.loads(line) for line in docker('logs', self.spy).splitlines()]
        assert {'api.credential.test', 'other.credential.test'} <= {row.get('query') for row in queries}
        self.check('actual_owned_DNS_and_TLS_name_grants_cannot_select_another_binding_on_the_shared_receiver_IP')

    def client_input(self, prefix):
        return dict(expected_revision=0, binding=dict(scheme='http', host=self.control['ipv4'], port=18080,
            methods=['GET'], path_prefix=prefix, injection={'kind': 'bearer'}, substitutions=[]),
            secret=dict(kind='literal', value=self.control['tokens']['alpha']))

    def sdk_contracts(self, root):
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'sdk/python/src'))
        from goldenhoop import Client, AsyncClient
        sync_id = str(uuid.uuid4())
        with Client(self.base, self.token) as client:
            created = client.put_credential(root, sync_id, self.client_input('/sdk-sync/'))
            assert created['state'] == 'pending' and created['applied_revision'] is None
            assert client.credential(root, sync_id)['id'] == sync_id
            assert any(row['id'] == sync_id for row in client.credentials(root))
            assert client.credential_ca(root)['sandbox_id'] == root
        self.wait_credential(root, sync_id)
        self.command(root, self.url('http', '/sdk-sync/accepted'))
        with Client(self.base, self.token) as client:
            assert client.revoke_credential(root, sync_id)['state'] == 'revoking'
        self.wait_credential(root, sync_id, 'revoked', 2)
        self.check('Python_sync_SDK_credential_CA_and_revoke_methods_preserve_actual_native_intent')

        async_id = str(uuid.uuid4())
        async def create_async():
            async with AsyncClient(self.base, self.token) as client:
                assert (await client.put_credential(root, async_id, self.client_input('/sdk-async/')))['state'] == 'pending'
                assert (await client.credential(root, async_id))['id'] == async_id
                assert any(row['id'] == async_id for row in await client.credentials(root))
                assert (await client.credential_ca(root))['sandbox_id'] == root
        asyncio.run(create_async())
        self.wait_credential(root, async_id)
        self.command(root, self.url('http', '/sdk-async/accepted'))
        async def revoke_async():
            async with AsyncClient(self.base, self.token) as client:
                assert (await client.revoke_credential(root, async_id))['state'] == 'revoking'
        asyncio.run(revoke_async())
        self.wait_credential(root, async_id, 'revoked', 2)
        self.check('Python_async_SDK_preserves_the_same_actual_credential_convergence')

        cli_id = str(uuid.uuid4())
        request_file = self.root / 'credential-cli-request.json'
        request_file.write_text(json.dumps(self.client_input('/sdk-cli/')), encoding='utf-8')
        request_file.chmod(0o600)
        assert self.cli('credentials', 'put', root, cli_id, str(request_file))['state'] == 'pending'
        assert self.cli('credentials', 'get', root, cli_id)['id'] == cli_id
        assert any(row['id'] == cli_id for row in self.cli('credentials', 'list', root))
        assert self.cli('credentials', 'ca', root)['sandbox_id'] == root
        self.wait_credential(root, cli_id)
        self.command(root, self.url('http', '/sdk-cli/accepted'))
        assert self.cli('credentials', 'revoke', root, cli_id)['state'] == 'revoking'
        self.wait_credential(root, cli_id, 'revoked', 2)
        self.check('actual_CLI_private_file_metadata_CA_and_native_revoke_contract')

        rust_id = str(uuid.uuid4())
        request_file = self.root / 'credential-rust-request.json'
        request_file.write_text(json.dumps(self.client_input('/sdk-rust/')), encoding='utf-8')
        request_file.chmod(0o600)
        environment = dict(os.environ, GOLDENHOOP_ENDPOINT=self.base, GOLDENHOOP_API_TOKEN=self.token)
        result = subprocess.run([self.args.sdk_binary, root, rust_id, str(request_file)], env=environment,
                                capture_output=True, text=True, encoding='utf-8', timeout=30)
        assert result.returncode == 0, result.stderr
        value = json.loads(result.stdout)
        assert value['binding']['id'] == rust_id and value['binding']['state'] == 'pending'
        self.wait_credential(root, rust_id)
        self.command(root, self.url('http', '/sdk-rust/accepted'))
        self.request('DELETE', f'/v1/sandboxes/{root}/credentials/{rust_id}')
        self.wait_credential(root, rust_id, 'revoked', 2)
        self.report['rust_sdk_result'] = value
        self.check('actual_Rust_SDK_credential_intent_metadata_and_public_CA_contract')

    def cross_sandbox(self, root):
        peer = self.create_source()
        binding = str(uuid.uuid4())
        self.put(peer, binding, source=dict(kind='literal', value=self.control['tokens']['beta']))
        self.wait_credential(peer, binding)
        assert self.request('GET', f'/v1/sandboxes/{peer}/credential-ca')['certificate_pem'] != self.request('GET', f'/v1/sandboxes/{root}/credential-ca')['certificate_pem']
        for source, target, secret in ((root, peer, 'exchange'), (peer, root, 'beta')):
            marker = uuid.uuid4().hex
            self.command(source, self.url('http', '/v1/identity'), headers={
                'X-Fixture-Request': marker, 'X-GoldenHoop-Sandbox': target, 'X-Sandbox-ID': target})
            rows = self.wait_receiver(lambda row: row.get('request_id') == marker)
            assert len(rows) == 1 and rows[0]['event'] == 'accepted'
            assert rows[0]['secret_sha256'] == hashlib.sha256(self.control['tokens'][secret].encode()).hexdigest()
        self.check('distinct_owned_network_sources_and_CAs_resist_cross_sandbox_header_selection')
        return peer

    def stream_revocation(self, root, binding):
        marker = uuid.uuid4().hex
        owner = self.controller_owner(root)
        start = time.monotonic()
        execution = self.start_client(root, self.url('https', '/v1/stream'),
            headers={'X-Fixture-Request': marker}, script=STREAM_CLIENT, timeout=60)
        deadline = start + 30
        while time.monotonic() < deadline:
            events = self.command_events(execution)
            stdout = b''.join(base64.b64decode(event['data']['data']) for event in events if event['kind'] == 'stdout')
            assert not any(event['kind'] == 'completed' for event in events), events
            if b'credential_tick 13\n' in stdout:
                assert time.monotonic() - start >= 12
                break
            time.sleep(0.2)
        else:
            raise AssertionError('actual TLS stream did not survive more than one native lease')
        self.request('DELETE', f'/v1/sandboxes/{root}/credentials/{binding}')
        self.wait_credential(root, binding, 'revoked', 2)
        self.assert_collected(owner)
        self.finish_client(execution, b'credential_stream_collected', exact=False)
        self.wait_receiver(lambda row: row.get('event') == 'stream_collected' and row.get('request_id') == marker)
        self.check('actual_TLS_stream_survives_native_renewal_then_revocation_collects_the_old_process_and_receiver_socket')

    def deny_and_late_exchange(self, root, binding):
        self.put(root, binding, revision=5, source=dict(kind='exchange', resolver='delayed'))
        self.wait_credential(root, binding, revision=6)
        self.policy(root, deny=True)
        self.wait_credential(root, binding, revision=6)
        baseline = len([row for row in self.receiver_logs() if row.get('event') == 'exchange_received'])
        marker = uuid.uuid4().hex
        execution = self.start_client(root, self.url('http', '/v1/denied'),
            headers={'X-Fixture-Request': marker}, script=DENIED_CLIENT)
        self.finish_client(execution, b'credential_client_refused')
        rows = self.receiver_logs()
        assert len([row for row in rows if row.get('event') == 'exchange_received']) == baseline
        assert not any(row.get('request_id') == marker for row in rows)
        self.check('applied_packet_deny_prevents_both_private_exchange_and_upstream_arrival')
        self.policy(root)
        self.wait_credential(root, binding, revision=6)
        marker = uuid.uuid4().hex
        owner = self.controller_owner(root)
        execution = self.start_client(root, self.url('http', '/v1/delayed'),
            headers={'X-Fixture-Request': marker}, script=DENIED_CLIENT)
        self.wait_receiver(lambda row: row.get('event') == 'exchange_received' and row.get('delayed'))
        self.request('DELETE', f'/v1/sandboxes/{root}/credentials/{binding}')
        self.wait_credential(root, binding, 'revoked', 7)
        self.assert_collected(owner)
        docker('exec', self.receiver, 'python3', '-c', "from pathlib import Path;Path('/tmp/credential-fixture/release-delayed').touch()")
        self.finish_client(execution, b'credential_client_refused')
        self.wait_receiver(lambda row: row.get('event') == 'exchange_connection_collected' and row.get('delayed'))
        assert not any(row.get('request_id') == marker for row in self.receiver_logs())
        delayed = hashlib.sha256(self.control['tokens']['delayed'].encode()).hexdigest()
        assert not any(row.get('event') == 'accepted' and row.get('secret_sha256') == delayed for row in self.receiver_logs())
        self.check('exchange_released_after_applied_revocation_cannot_dispatch_a_late_private_value')

    def exercise(self):
        profiles = self.request('GET', '/v1/profiles')
        self.report['profiles'] = profiles
        profile = next(row for row in profiles if row['id'] == self.profile)
        assert profile['availability'] == 'available' and {'network_policy', 'secret_injection'} <= set(profile['capabilities'])
        assert all(row['cleanup'] == 'complete' for row in self.rows('sandboxes'))
        startup = [json.loads(line) for line in docker('logs', self.receiver).splitlines() if line.startswith('{')]
        accepted = [row for row in startup if row.get('event') == 'accepted']
        assert {row['tls'] for row in accepted} == {False, True}
        assert all(row['secret_sha256'] == hashlib.sha256(self.control['tokens']['alpha'].encode()).hexdigest() for row in accepted)
        self.check('SecretInjection_requires_actual_untrusted_UID_HTTP_TLS_receiver_and_collected_private_probe')
        root = self.create_source()
        plain, secure = str(uuid.uuid4()), str(uuid.uuid4())
        self.put(root, plain)
        self.put(root, secure, scheme='https')
        self.wait_credential(root, plain)
        self.wait_credential(root, secure)
        self.command(root, self.url('http', '/v1/bearer'))
        self.command(root, self.url('https', '/v1/bearer'))
        self.check('actual_transparent_HTTP_TLS_injection_redacts_reflected_headers_without_proxy_environment')
        v6 = str(uuid.uuid4())
        self.put(root, v6, scheme='https', host=self.control['ipv6'])
        self.wait_credential(root, v6)
        self.command(root, self.url('https', '/v1/bearer', ipv6=True))
        self.check('IPv6_original_destination_and_owned_source_reach_the_same_credential_boundary')
        old = self.controller_owner(root)
        self.put(root, plain, revision=1, injection=dict(kind='basic', username='goldenhoop'))
        self.wait_credential(root, plain, revision=2)
        fresh = self.controller_owner(root)
        assert fresh['controller_generation'] != old['controller_generation']
        remaining = docker('ps', '-a', '--filter', 'id=' + old['container_id'], '--format', '{{.ID}}')
        assert not remaining
        self.command(root, self.url('http', '/v1/basic'))
        self.check('rotation_collects_the_exact_previous_controller_before_applying_basic_credentials')
        self.put(root, plain, revision=2, injection=dict(kind='header', name='X-Provider-Key'))
        self.wait_credential(root, plain, revision=3)
        self.command(root, self.url('http', '/v1/header'), headers={'X-Provider-Key': 'untrusted-client-value'})
        self.check('custom_header_mode_replaces_untrusted_client_values_at_the_approved_receiver')
        substitutions = [dict(placeholder='GH_TOKEN', at=dict(kind='path')), dict(placeholder='GH_TOKEN', at=dict(kind='query', name='key')),
                         dict(placeholder='GH_TOKEN', at=dict(kind='header', name='X-Placeholder')), dict(placeholder='GH_TOKEN', at=dict(kind='body'))]
        self.put(root, plain, revision=3, injection=dict(kind='placeholders'), substitutions=substitutions)
        self.wait_credential(root, plain, revision=4)
        self.command(root, self.url('http', '/v1/substitute/GH_TOKEN?key=GH_TOKEN'), method='POST', headers={'X-Placeholder': 'GH_TOKEN'}, body='GH_TOKEN')
        self.check('actual_native_path_query_header_and_body_substitution_uses_private_values_only_upstream')
        self.put(root, plain, revision=4, source=dict(kind='exchange', resolver='fixture'))
        self.wait_credential(root, plain, revision=5)
        self.command(root, self.url('http', '/v1/exchange'))
        logs = [json.loads(line) for line in docker('logs', self.receiver).splitlines() if line.startswith('{')]
        assert any(row.get('event') == 'exchange_received' and row.get('authenticated') for row in logs)
        assert any(row.get('secret_sha256') == hashlib.sha256(self.control['tokens']['exchange'].encode()).hexdigest() for row in logs)
        self.check('named_HTTPS_exchange_is_operator_authenticated_and_the_value_reaches_only_the_receiver')
        public = self.request('GET', f'/v1/sandboxes/{root}/credential-ca')
        self.stop('api')
        self.launch('api')
        assert self.request('GET', f'/v1/sandboxes/{root}/credential-ca') == public
        self.command(root, self.url('https', '/v1/restarted-api'))
        self.check('API_restart_preserves_encrypted_CA_identity_and_existing_native_traffic')
        self.sdk_contracts(root)
        self.named_origin(root)
        peer = self.cross_sandbox(root)
        owners = [self.controller_owner(identity) for identity in (root, peer)]
        self.stop('worker')
        self.launch('worker')
        for binding in (plain, secure, v6):
            self.wait_credential(root, binding)
        assert self.request('GET', f'/v1/sandboxes/{root}/credential-ca') == public
        for owner in owners:
            self.assert_collected(owner)
        self.command(root, self.url('https', '/v1/restarted-worker'))
        self.check('worker_restart_reuses_the_encrypted_CA_and_workload_but_collects_old_controller_epochs')
        self.stream_revocation(root, secure)
        self.deny_and_late_exchange(root, plain)
        assert self.workload_identity(root) == self.physical[root]
        assert self.workload_identity(peer) == self.physical[peer]
        self.check('revocation_requires_native_collection_while_preserving_the_workload_identity')
        with closing(sqlite3.connect(self.database.as_uri() + '?mode=ro', uri=True)) as database:
            material = '\n'.join(str(row) for table in ('credential_bindings', 'credential_cas', 'audit') for row in database.execute('SELECT * FROM ' + table))
        assert not any(value in material for value in self.private_values)
        self.check('provider_values_are_absent_from_durable_binding_metadata_CA_rows_and_audit')

    def cleanup(self):
        failure = None
        try:
            if self.receiver:
                self.report['receiver_logs'] = [json.loads(line) for line in docker('logs', self.receiver).splitlines() if line.startswith('{')]
            super().cleanup()
        except BaseException as error:
            failure = error
        finally:
            if self.receiver:
                row = json.loads(docker('inspect', self.receiver))[0]
                assert row['Config']['Labels']['dev.goldenhoop.attempt'] == self.attempt
                docker('rm', '--force', self.receiver)
                assert not docker('ps', '-aq', '--filter', 'id=' + self.receiver)
                self.receiver = None
            if self.receiver_network:
                row = json.loads(docker('network', 'inspect', self.receiver_network))[0]
                assert row['Labels']['dev.goldenhoop.attempt'] == self.attempt and not row['Containers']
                docker('network', 'rm', self.receiver_network)
                assert not docker('network', 'ls', '-q', '--filter', 'id=' + self.receiver_network)
                self.receiver_network = None
            assert not self.receiver_pending and not self.network_pending
            assert not docker('ps', '-aq', '--filter', 'label=dev.goldenhoop.attempt=' + self.attempt)
            assert not docker('network', 'ls', '-q', '--filter', 'label=dev.goldenhoop.attempt=' + self.attempt)
            assert not any(value in json.dumps(self.report) for value in self.private_values)
            self.report['credential_fixture_cleanup'] = 'complete'
        if failure:
            raise failure


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--cli', required=True)
    parser.add_argument('--sdk-binary', required=True)
    parser.add_argument('--image', default='goldenhoop-agent:test')
    parser.add_argument('--controller-image', default='goldenhoop-egress:test')
    parser.add_argument('--fixture-image', default='goldenhoop-network-fixture:test')
    parser.add_argument('--runtime', choices=['runc', 'runsc'], default='runc')
    parser.add_argument('--work-dir', required=True)
    parser.add_argument('--output', required=True)
    parser.set_defaults(mode='full', kernel_image=None, code_languages=['python'])
    Contract(parser.parse_args()).run()
