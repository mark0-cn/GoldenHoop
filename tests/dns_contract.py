"""Actual private-control DNS grants and packets; frontend/capability still pending."""
import argparse
import hashlib
import json
import os
import struct
import time
from pathlib import Path

from dns_samples import DNS
from egress_contract import RustContract
from network_contract import Stream, docker


def question(name, kind=1):
    return list(struct.pack('!HHHHHH',71,0x100,1,0,0,0)+b''.join(bytes([len(label)])+label.encode('ascii') for label in name.split('.'))+b'\0'+struct.pack('!HH',kind,1))


class DnsContract(RustContract):
    def __init__(self,args):
        super().__init__(args)
        self.evidence['suite']='rust-private-dns-grants'
        self.evidence['scope']='actual DNS resolution through trusted private control and kernel grants; workload DNS frontend/IPv6/L2/credentials not established'
        root=Path(__file__).resolve().parents[1]
        for path in [Path(__file__).resolve(),root/'tests/dns_samples.py']:
            self.evidence['source_files_sha256'][path.relative_to(root).as_posix()]=hashlib.sha256(path.read_bytes()).hexdigest()
        self.save()

    def kernel_policy_cases(self):
        super().kernel_policy_cases()
        network=next(row['network_id'] for row in self.evidence['resources'] if row['role']=='target-net')
        bind='0.0.0.0' if self.args.receiver_publication=='routed' else '127.0.0.1'
        server=self.container('dns-target',['--runtime','runc','--network',network,'--user','1000:1000',
            '--memory','128m','--memory-swap','128m','--cpus','0.25','--pids-limit','32',
            '--publish',f'{bind}::19004/udp','--publish',f'{bind}::19004/tcp'],DNS,self.target_ip)
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            if any(json.loads(line).get('ready') for line in docker('logs',server).stdout.splitlines()):break
            time.sleep(.05)
        else:raise RuntimeError('owned DNS upstream did not start')
        info=json.loads(docker('inspect',server).stdout)[0]
        endpoint=next(iter(info['NetworkSettings']['Networks'].values()))['IPAddress']+':19004'
        self.rpc('quarantine',expected_revision=self.revision)
        self.rpc('enable_dns',expected_revision=self.revision,upstream=endpoint,remaining_seconds=120)
        config={'policies':[{'default_action':'deny','rules':[{'destination':name,'ports':[],'action':'allow'} for name in ['short.test','long.test']]}]}
        self.apply_config(config)
        self.rpc('renew',expected_revision=self.revision)
        assert not self.probe(self.guest,'tcp',self.target_ip,19001)
        self.resolve('short.test')
        assert self.probe(self.guest,'tcp',self.target_ip,19001)
        assert self.probe(self.guest,'udp',self.target_ip,19002)
        self.check('private_dns_answer_follows_confirmed_kernel_tcp_and_udp_grants')
        queries=self.queries(server)
        reply=self.rpc('resolve',wire=question('denied.test'),error=True)
        assert reply['error']['code']=='forbidden'
        assert self.queries(server)==queries
        self.check('denied_domain_is_not_forwarded_to_the_owned_upstream')
        established=Stream(self.guest,self.target_ip,self.attempt)
        try:
            assert established.exchange()['ok']
            self.hold(4.5)
            denied=established.exchange()
            assert not denied['ok']
            self.evidence['dns_expired_existing_flow']=denied
        finally:established.close()
        assert not self.rpc('dns_source',name='short.test')['result']['source_live']
        before=self.packets()
        assert not self.probe(self.guest,'tcp',self.target_ip,19001)
        assert self.packets()>before
        self.control()
        self.check('source_expiry_denies_packets_while_controller_and_target_remain_live')
        self.resolve('short.test');self.resolve('long.test')
        self.hold(4.5)
        assert not self.rpc('dns_source',name='short.test')['result']['source_live']
        assert self.rpc('dns_source',name='long.test')['result']['source_live']
        assert self.probe(self.guest,'tcp',self.target_ip,19001)
        self.check('live_shared_ip_source_does_not_revive_the_expired_original_source')
        self.resolve('long.test',28)
        assert self.rpc('dns_source',name='long.test')['result']['source_live']
        assert not self.rpc('dns_source',name='long.test',aaaa=True)['result']['source_live']
        assert self.probe(self.guest,'tcp',self.target_ip,19001)
        self.check('negative_aaaa_preserves_the_same_names_live_a_permission')
        self.rpc('renew',expected_revision=self.revision)
        started=time.monotonic()
        while time.monotonic()-started<8:
            self.rpc('resolve',wire=question('long.test',28))
            time.sleep(min(1,max(0,started+8-time.monotonic())))
        time.sleep(max(0,started+10.4-time.monotonic()))
        self.rpc('resolve',wire=question('long.test'),error=True)
        assert not self.probe(self.guest,'tcp',self.target_ip,19001)
        rows=self.owned_table()
        assert any(element.get('elem',{}).get('val')==self.target_ip and element['elem'].get('expires',0)>0
            for row in rows if row.get('set',{}).get('type')=='ipv4_addr'
            for element in row['set'].get('elem',[])), 'long DNS source must remain live when the control lease expires'
        self.check('dns_queries_cannot_renew_the_trusted_controller_lease')
        self.rpc('quarantine',expected_revision=self.revision)
        self.apply_config(config);self.resolve('long.test')
        assert self.probe(self.guest,'tcp',self.target_ip,19001)
        self.apply_config({'policies':[{'default_action':'deny','rules':[]}]})
        assert not self.probe(self.guest,'tcp',self.target_ip,19001)
        self.rpc('resolve',wire=question('long.test'),error=True)
        self.control()
        self.check('policy_replacement_clears_prior_dns_permissions')
        operator={'policies':[{'default_action':'deny','rules':[{'destination':'*','ports':[],'action':'deny'}]}],
            'allow_always':[{'destination':'operator.test','ports':[],'action':'allow'}]}
        self.apply_config(operator);self.resolve('operator.test')
        assert self.probe(self.guest,'tcp',self.target_ip,19001)
        self.check('operator_domain_credit_precedes_user_address_denies')
        blocked=dict(operator,deny_always=[{'destination':self.target_ip,'ports':[],'action':'deny'}])
        self.apply_config(blocked)
        self.rpc('resolve',wire=question('operator.test'),error=True)
        assert not self.probe(self.guest,'tcp',self.target_ip,19001)
        self.control()
        self.check('operator_address_deny_refuses_a_dns_answer_and_packet_grant')
        self.apply_config(dict(operator,tcp_cap=[19003]));self.resolve('operator.test')
        assert not self.probe(self.guest,'tcp',self.target_ip,19001)
        assert self.probe(self.guest,'tcp',self.target_ip,19003)
        assert self.probe(self.guest,'udp',self.target_ip,19002)
        self.control()
        self.check('tcp_floor_precedes_dns_operator_permission')
        self.evidence['owned_dns_queries']=self.queries(server)
        self.save()

    def resolve(self,name,kind=1):
        self.rpc('renew',expected_revision=self.revision)
        response=self.rpc('resolve',wire=question(name,kind))['result']
        wire=bytes(response['wire'])
        assert len(wire)>=12 and int.from_bytes(wire[:2],'big')==71 and int.from_bytes(wire[2:4],'big')&15==0
        assert int.from_bytes(wire[6:8],'big')==(1 if kind==1 else 0)
        return wire

    def queries(self,server):
        return [json.loads(line) for line in docker('logs',server).stdout.splitlines() if 'query' in json.loads(line)]

    def hold(self,seconds):
        deadline=time.monotonic()+seconds
        while time.monotonic()<deadline:
            self.rpc('renew',expected_revision=self.revision)
            time.sleep(min(.5,max(0,deadline-time.monotonic())))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',default='goldenhoop-network-fixture:test')
    parser.add_argument('--runtime',choices=['runc','runsc'],default='runc')
    parser.add_argument('--output',required=True)
    parser.add_argument('--remove-image',action='store_true')
    parser.add_argument('--receiver-publication',choices=['loopback','routed'],default='loopback')
    parser.add_argument('--ci-host-diagnostics',action='store_true')
    args=parser.parse_args()
    if args.ci_host_diagnostics and os.environ.get('GITHUB_ACTIONS')!='true':parser.error('ephemeral CI only')
    DnsContract(args).run()
