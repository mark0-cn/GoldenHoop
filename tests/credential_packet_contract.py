"""Actual private inet packet path and original destination; no runtime capability."""
import argparse
import hashlib
import ipaddress
import json
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

SERVER = r'''
import ipaddress,json,socket,struct,threading,time
from pathlib import Path
output=Path('/tmp/credential-packets.jsonl')
lock=threading.Lock()
ready=[]
def serve(family,port):
 s=socket.socket(family,socket.SOCK_STREAM)
 if family==socket.AF_INET6:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
 s.bind(('0.0.0.0' if family==socket.AF_INET else '::',port));s.listen(8)
 with lock:
  ready.append(family)
  if len(ready)==2:Path('/tmp/credential-packet-ready').touch()
 while True:
  c,peer=s.accept()
  with c:
   c.settimeout(3)
   raw=c.getsockopt(socket.SOL_IP if family==socket.AF_INET else socket.IPPROTO_IPV6,80,128)
   sockaddr_bytes=16 if family==socket.AF_INET else 28
   exact=c.getsockopt(socket.SOL_IP if family==socket.AF_INET else socket.IPPROTO_IPV6,80,sockaddr_bytes)
   assert len(exact)==sockaddr_bytes and exact==raw[:sockaddr_bytes]
   original=str(ipaddress.ip_address(raw[4:8] if family==socket.AF_INET else raw[8:24]))
   original_port=struct.unpack('!H',raw[2:4])[0]
   marker=c.recv(128).decode()
   with lock:
    with output.open('a') as f:f.write(json.dumps(dict(peer=peer,original=original,original_port=original_port,returned_buffer_length=len(raw),sockaddr_bytes=sockaddr_bytes,exact_buffer_length=len(exact),exact_family_read_matches=True,marker=marker))+'\n')
   c.sendall(b'credential_packet_observed')
for family,port in ((socket.AF_INET,44000),(socket.AF_INET6,44001)):
 threading.Thread(target=serve,args=(family,port),daemon=True).start()
threading.Event().wait()
'''

CLIENT = r'''
import json,os,socket,sys
assert os.geteuid()==1000
assert int(next(l.split()[1] for l in open('/proc/self/status') if l.startswith('CapEff:')),16)==0
family=socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET
try:
 with socket.socket(family,socket.SOCK_STREAM) as s:
  s.settimeout(2);s.connect((sys.argv[1],18080));s.sendall(sys.argv[2].encode())
  assert s.recv(128)==b'credential_packet_observed'
 print(json.dumps(dict(accepted=True)))
except (OSError,AssertionError) as e:print(json.dumps(dict(accepted=False,error=type(e).__name__)))
'''


def run(args):
    attempt = uuid.uuid4().hex
    report = dict(timestamp=datetime.now(timezone.utc).isoformat(), attempt=attempt,
        suite='credential-private-inet-packet-path', result='failed', cleanup='unknown',
        scope='Actual inet redirect, main policy and destination floor in private namespaces; bridge/source floors, production broker and runtime support are not attested',
        commands=[], cases=[])
    containers, network = [], None
    pending = set()
    failure = None

    def save():
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')

    def call(argv, data=None, check=True):
        result = subprocess.run(argv, input=data, capture_output=True, timeout=30)
        report['commands'].append(dict(argv=argv, exit_code=result.returncode,
            stdout=result.stdout.decode(errors='replace'), stderr=result.stderr.decode(errors='replace')))
        if check:
            assert result.returncode == 0, report['commands'][-1]
        return result

    def docker(*argv, **kwargs):
        return call(['docker', *argv], **kwargs)

    def compile(binary, value, text=False):
        output = call([binary], json.dumps(value).encode()).stdout.decode()
        return output if text else json.loads(output)['script']

    try:
        sources = [Path(__file__), Path('Cargo.toml'), Path('Cargo.lock'), Path('crates/egress/Cargo.toml'), *Path('crates/egress').rglob('*.rs')]
        report['source_files_sha256'] = {p.as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
        report['binaries_sha256'] = {key: hashlib.sha256(Path(value).read_bytes()).hexdigest()
            for key, value in vars(args).items() if key.endswith('_binary')}
        image = json.loads(docker('image', 'inspect', args.image).stdout)[0]
        assert image['Config']['Labels']['dev.goldenhoop.fixture'] == 'network-interop'
        labels = ['--label', 'dev.goldenhoop.test=credential-packet-path', '--label', 'dev.goldenhoop.attempt=' + attempt]
        pending.add('network')
        network = docker('network', 'create', '--ipv6', '--subnet', f'fd{attempt[:2]}:{attempt[2:6]}:{attempt[6:10]}::/64',
            *labels, 'goldenhoop-credential-packets-' + attempt[:12]).stdout.decode().strip()
        assert len(network) == 64
        pending.remove('network')
        for role in ('controller', 'sender'):
            pending.add(role)
            identity = docker('run', '--detach', '--network', network, '--runtime', 'runc',
                '--name', 'goldenhoop-credential-packets-' + attempt[:12] + '-' + role,
                '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,size=4m', '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN',
                '--security-opt', 'no-new-privileges:true', '--memory', '128m', '--cpus', '0.5', '--pids-limit', '32',
                *labels, '--entrypoint', '/bin/sleep', image['Id'], '300').stdout.decode().strip()
            assert len(identity) == 64
            containers.append(identity)
            pending.remove(role)
        controller, sender = containers
        endpoints = [next(iter(json.loads(docker('inspect', c).stdout)[0]['NetworkSettings']['Networks'].values())) for c in containers]
        addresses = {key: endpoints[0][key] for key in ('IPAddress', 'GlobalIPv6Address', 'IPPrefixLen', 'GlobalIPv6PrefixLen')}
        bridge = 'ghpacketprobe'
        def native(*argv, **kwargs):
            return docker('exec', controller, *argv, **kwargs)
        native('ip', 'link', 'add', bridge, 'type', 'bridge')
        native('ip', 'addr', 'del', addresses['IPAddress'] + '/' + str(addresses['IPPrefixLen']), 'dev', 'eth0')
        native('ip', '-6', 'addr', 'del', addresses['GlobalIPv6Address'] + '/' + str(addresses['GlobalIPv6PrefixLen']), 'dev', 'eth0')
        native('ip', 'link', 'set', 'eth0', 'master', bridge)
        native('ip', 'addr', 'add', addresses['IPAddress'] + '/' + str(addresses['IPPrefixLen']), 'dev', bridge)
        native('ip', '-6', 'addr', 'add', addresses['GlobalIPv6Address'] + '/' + str(addresses['GlobalIPv6PrefixLen']), 'dev', bridge, 'nodad')
        native('ip', 'link', 'set', bridge, 'up')
        native('ip', 'route', 'del', 'default', check=False)
        native('ip', '-6', 'route', 'del', 'default', check=False)
        original4, original6 = '10.222.0.99', 'fdff:222::99'
        docker('exec', sender, 'ip', 'route', 'add', original4 + '/32', 'via', addresses['IPAddress'])
        docker('exec', sender, 'ip', '-6', 'route', 'add', original6 + '/128', 'via', addresses['GlobalIPv6Address'])
        allocation = dict(installation_id=str(uuid.uuid4()), sandbox_id=str(uuid.uuid4()), generation=str(uuid.uuid4()),
                          bridge=bridge, ifindex=int(native('cat', '/sys/class/net/' + bridge + '/ifindex').stdout))
        listeners = [dict(address=addresses['IPAddress'], port=44000), dict(address=addresses['GlobalIPv6Address'], port=44001)]
        definition = dict(v4=listeners[0], v6=listeners[1], ports={'18080': 'http'})
        redirect = compile(args.redirect_binary, dict(allocation=allocation, definition=definition))
        docker('exec', '-i', controller, 'nft', '--file', '-', data=redirect.encode())
        docker('exec', '--detach', controller, 'python3', '-B', '-u', '-c', SERVER)
        deadline = time.monotonic() + 5
        while native('test', '-f', '/tmp/credential-packet-ready', check=False).returncode:
            assert time.monotonic() < deadline
            time.sleep(0.05)
        for phase in ('redirect', 'main', 'floor'):
            if phase == 'main':
                config = {'policies': [dict(default_action='deny', rules=[dict(destination=ip, ports=[18080], action='allow') for ip in (original4, original6)])]}
                script = compile(args.policy_binary, dict(allocation=allocation, revision=1, config=config, dns_enabled=True, dns=listeners))
                docker('exec', '-i', controller, 'nft', '--file', '-', data=script.encode())
            if phase == 'floor':
                floor = dict(scope=dict(host_addresses=[v['address'] for v in listeners], control_addresses=[],
                    private_exceptions=[original4 + '/32', original6 + '/128']), dns=listeners)
                script = compile(args.destination_binary, dict(allocation=allocation, definition=floor), text=True)
                docker('exec', '-i', controller, 'nft', '--file', '-', data=script.encode())
            for original in (original4, original6):
                marker = phase + '-' + ('v6' if ':' in original else 'v4')
                result = docker('exec', '--user', '1000:1000', sender, 'python3', '-B', '-c', CLIENT, original, marker)
                row = dict(phase=phase, original=original, result=json.loads(result.stdout))
                report['cases'].append(row)
            report.setdefault('ruleset_captures', []).append(dict(phase=phase,
                native=json.loads(native('nft', '--json', 'list', 'ruleset').stdout)))
            save()
        report['socket_observations'] = [json.loads(line) for line in native('cat', '/tmp/credential-packets.jsonl', check=False).stdout.decode().splitlines()]
        assert all(row['result']['accepted'] for row in report['cases']), 'actual private credential packet path refused'
        for row in report['socket_observations']:
            assert row['original_port'] == 18080 and ipaddress.ip_address(row['original']) in map(ipaddress.ip_address, (original4, original6))
            assert ipaddress.ip_address(row['peer'][0]) in map(ipaddress.ip_address, (endpoints[1]['IPAddress'], endpoints[1]['GlobalIPv6Address']))
        assert len(report['socket_observations']) == 6
        report['result'] = 'passed'
    except BaseException as error:
        failure = error
        report['error'] = repr(error)
    finally:
        try:
            for identity in containers:
                actual = json.loads(docker('inspect', identity).stdout)[0]
                assert actual['Config']['Labels']['dev.goldenhoop.attempt'] == attempt
                docker('rm', '--force', identity)
                assert not docker('ps', '-aq', '--filter', 'id=' + identity).stdout.strip()
            if network:
                actual = json.loads(docker('network', 'inspect', network).stdout)[0]
                assert actual['Labels']['dev.goldenhoop.attempt'] == attempt and not actual['Containers']
                docker('network', 'rm', network)
                assert not docker('network', 'ls', '-q', '--filter', 'id=' + network).stdout.strip()
            assert not docker('ps', '-aq', '--filter', 'label=dev.goldenhoop.attempt=' + attempt).stdout.strip()
            assert not docker('network', 'ls', '-q', '--filter', 'label=dev.goldenhoop.attempt=' + attempt).stdout.strip()
            assert not pending, 'unacknowledged fixture creation remains unknown'
            report['cleanup'] = 'complete'
        except BaseException as error:
            failure = failure or error
            report['cleanup_error'] = repr(error)
        save()
    print(json.dumps({key: report.get(key) for key in ('result', 'cleanup', 'error')}))
    if failure:
        raise failure


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for binary in ('redirect', 'policy', 'destination'):
        parser.add_argument('--' + binary + '-binary', required=True)
    parser.add_argument('--image', default='goldenhoop-network-fixture:test')
    parser.add_argument('--output', required=True)
    run(parser.parse_args())
