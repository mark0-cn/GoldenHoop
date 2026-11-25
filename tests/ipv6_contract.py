"""Actual dual-stack packet/DNS contract; component-only is a separate dev gate."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path

from dns_contract import question
from ethernet_contract import EthernetContract
from frontend_contract import FrontendContract
from frontend_samples import CLIENT as DNS_CLIENT,SYSTEM_RESOLVER
from ipv6_samples import PRESSURE,TARGET
from network_contract import Stream,docker
from network_samples import CLIENT


class IPv6Cases:
    def __init__(self,args):
        super().__init__(args)
        self.binding6=None
        self.target6=None
        self.gateway6=None
        self.evidence['suite']='rust-ipv6-component' if args.component_only else 'rust-dualstack-ethernet'
        self.evidence['scope']='actual IPv6 routed packets and dual-stack DNS; component-only omits Ethernet; metadata/source integrity/credentials/API remain incomplete'
        root=Path(__file__).resolve().parents[1]
        for name in ('ipv6_contract.py','ipv6_samples.py'):
            p=root/'tests'/name;self.evidence['source_files_sha256'][p.relative_to(root).as_posix()]=hashlib.sha256(p.read_bytes()).hexdigest()
        self.save()

    def network(self,role,*options):
        if role in ('guest-net','target-net'):
            suffix=1 if role=='guest-net' else 2
            prefix=f'fd{self.attempt[:2]}:{self.attempt[2:6]}:{self.attempt[6:10]}:{suffix}::/64'
            options=(*options,'--ipv6','--subnet',prefix)
            if role=='target-net':options=(*options,'--opt','com.docker.network.bridge.gateway_mode_ipv6=routed')
        identity,observed=super().network(role,*options)
        if role in ('guest-net','target-net'):
            assert observed['EnableIPv6']
            gateway=next(c['Gateway'] for c in observed['IPAM']['Config'] if ipaddress.ip_network(c['Subnet']).version==6)
            if role=='guest-net':self.gateway6=str(ipaddress.IPv6Address(gateway))
            self.evidence.setdefault('ipv6_networks',{})[role]={'gateway':gateway,'ipam':observed['IPAM']}
            self.save()
        return identity,observed

    def container(self,role,options,script,*args):
        if role in ('target','ethernet-peer'):script=TARGET
        if role=='target':
            bind='::' if self.args.receiver_publication=='routed' else '::1'
            options=[*options,*sum((['--publish',f'[{bind}]::{port}/{transport}'] for port,transport in [(19001,'tcp'),(19003,'tcp'),(19002,'udp')]),[])]
        if role=='dns-target':args=(*args,self.target6)
        identity=super().container(role,options,script,*args)
        if role in ('target','guest'):
            endpoint=next(iter(json.loads(docker('inspect',identity).stdout)[0]['NetworkSettings']['Networks'].values()))
            address=str(ipaddress.IPv6Address(endpoint['GlobalIPv6Address']))
            if role=='target':self.target6=address
            self.evidence.setdefault('ipv6_endpoints',{})[role]={'address':address,'gateway':endpoint['IPv6Gateway']}
            self.save()
        return identity

    def rpc(self,operation,error=False,**fields):
        if operation=='enable_dns' and not error:fields['remaining_seconds']=getattr(self.args,'dns_lifetime',300)
        reply=super().rpc(operation,error=error,**fields)
        if operation=='enable_dns' and not error:
            self.binding6=self.evidence['owned_dns_listener']['ipv6_binding']
            assert self.binding6['address']==self.gateway6 and self.binding6['port']>=1024,self.binding6
        return reply

    def probe(self,container,mode,ip,port):
        if ipaddress.ip_address(ip).version==4:return super().probe(container,mode,ip,port)
        assert str(ipaddress.IPv6Address(ip))==ip
        result=json.loads(self.exec(container,'python3','-c',CLIENT,mode,ip,str(port),self.attempt).stdout)
        self.evidence['observations'].append({'origin':'workload' if container==self.guest else 'trusted-control','transport':mode,'address':ip,'port':port,**result})
        self.save()
        return result['ok']

    def control6(self):
        for mode,port in [('tcp',19001),('tcp',19003),('udp',19002)]:assert self.probe(self.helper,mode,self.target6,port),(mode,port)

    def dns6(self,container,mode,address,port,name,rcode=None):
        reply=json.loads(self.exec(container,'python3','-c',DNS_CLIENT,mode,address,str(port),json.dumps(question(name,28))).stdout)
        self.evidence.setdefault('ipv6_dns_observations',[]).append({'origin':'workload' if container==self.guest else 'other-bridge','mode':mode,'address':address,'port':port,'name':name,'reply':reply})
        self.save()
        if rcode is not None:
            assert reply['ok'] and reply['rcode']==rcode,reply
            if rcode==0:assert reply['addresses']==[self.target6],reply
            else:assert not reply['addresses'] and reply['answers']==0,reply
        return reply

    def kernel_policy_cases(self):
        super().kernel_policy_cases()
        self.control6()
        self.apply_config({'policies':[{'default_action':'deny','rules':[]}]})
        assert not self.probe(self.guest,'tcp',self.target6,19001)
        assert not self.probe(self.guest,'udp',self.target6,19002)
        self.control6()
        self.check('ipv6_raw_tcp_and_udp_are_denied_with_independent_live_controls')
        self.apply_config({'policies':[
            {'default_action':'deny','rules':[{'destination':self.target6+'/128','ports':[],'action':'allow'}]},
            {'default_action':'deny','rules':[{'destination':self.target6,'ports':[19001],'action':'allow'}]}]})
        assert self.probe(self.guest,'tcp',self.target6,19001)
        assert not self.probe(self.guest,'tcp',self.target6,19003)
        assert not self.probe(self.guest,'udp',self.target6,19002)
        self.control6()
        self.check('ipv6_cidr_hierarchy_and_tcp_port_scope_have_real_positive_and_negative_packets')
        config={'policies':[{'default_action':'deny','rules':[{'destination':name,'ports':[],'action':'allow'} for name in ('ipv6-short.test','ipv6-long.test')]}]}
        self.apply_config(config)
        assert not self.probe(self.guest,'tcp',self.target6,19001)
        self.rpc('renew',expected_revision=self.revision)
        self.dns6(self.guest,'udp','2001:db8::53',53,'ipv6-short.test',0)
        self.dns6(self.guest,'tcp','2001:db8::53',53,'ipv6-long.test',0)
        assert self.probe(self.guest,'tcp',self.target6,19001) and self.probe(self.guest,'udp',self.target6,19002)
        system=json.loads(self.exec(self.guest,'python3','-c',SYSTEM_RESOLVER,'ipv6-long.test','6').stdout)
        assert system['ok'] and system['addresses']==[self.target6] and system['resolver_readonly'],system
        self.evidence['ipv6_libc_resolver']=system;self.save()
        self.check('ipv6_udp_and_tcp_dns_interception_publishes_aaaa_only_with_real_kernel_grants')
        self.dns6(self.guest,'udp',self.gateway6,self.binding6['port'],'ipv6-long.test',0)
        before=self.queries(self.dns_target)
        self.dns6(self.guest,'udp','2001:db8::53',53,'denied.test',5)
        self.dns6(self.guest,'tcp','2001:db8::53',53,'denied.test',5)
        assert self.queries(self.dns_target)==before
        self.check('ipv6_denied_dns_returns_no_address_and_never_reaches_the_upstream')
        pressure=json.loads(self.exec(self.guest,'python3','-c',PRESSURE,self.gateway,str(self.binding['port']),self.gateway6,str(self.binding6['port']),json.dumps(question('ipv6-long.test',28))).stdout)
        assert pressure['connections']==16 and pressure['id']==71 and pressure['rcode']==2 and pressure['answers']==pressure['authority']==pressure['additional']==0,pressure
        self.evidence['dualstack_dns_pressure']=pressure;self.save()
        self.rpc('renew',expected_revision=self.revision)
        self.dns6(self.guest,'udp',self.gateway6,self.binding6['port'],'ipv6-long.test',0)
        self.check('ipv4_and_ipv6_share_the_allocation_dns_limit_and_release_it_after_connections_close')
        before=self.queries(self.dns_target)
        assert not self.dns6(self.dns_target,'udp',self.gateway6,self.binding6['port'],'ipv6-long.test')['ok']
        assert self.queries(self.dns_target)==before
        self.rpc('renew',expected_revision=self.revision)
        self.dns6(self.guest,'udp',self.gateway6,self.binding6['port'],'ipv6-long.test',0)
        self.check('another_ipv6_bridge_cannot_borrow_the_owned_resolver_identity')
        alias=str(ipaddress.IPv6Address(int(ipaddress.IPv6Address(self.gateway6))+65534))
        self.exec(self.helper,'ip','-6','addr','add',alias+'/128','dev',self.bridge,'nodad')
        try:
            refused=self.rpc('renew',expected_revision=self.revision,error=True)
            assert refused['error']['code']=='conflict',refused
            self.dns6(self.guest,'udp',self.gateway6,self.binding6['port'],'ipv6-long.test',2)
        finally:self.exec(self.helper,'ip','-6','addr','del',alias+'/128','dev',self.bridge)
        self.rpc('quarantine',expected_revision=self.revision)
        self.apply_config(config)
        self.dns6(self.guest,'udp',self.gateway6,self.binding6['port'],'ipv6-long.test',0)
        self.check('ambiguous_gateway_addresses_refuse_renewal_and_dns_addresses_then_recover_through_quarantine')
        self.apply_config(config)
        self.dns6(self.guest,'udp',self.gateway6,self.binding6['port'],'ipv6-short.test',0)
        stream=Stream(self.guest,self.target6,self.attempt)
        try:
            assert stream.exchange()['ok'];self.hold(4.5)
            assert not stream.exchange()['ok']
        finally:stream.close()
        assert not self.rpc('dns_source',name='ipv6-short.test',aaaa=True)['result']['source_live']
        assert not self.probe(self.guest,'tcp',self.target6,19001) and not self.probe(self.guest,'udp',self.target6,19002)
        self.control6()
        self.check('aaaa_source_expiry_denies_existing_and_new_ipv6_packets_while_the_controller_is_live')
        if not self.args.component_only:
            peer=next(r['container_id'] for r in self.evidence['resources'] if r['role']=='ethernet-peer')
            peer6=next(iter(json.loads(docker('inspect',peer).stdout)[0]['NetworkSettings']['Networks'].values()))['GlobalIPv6Address']
            assert self.probe(peer,'tcp',peer6,19001) and self.probe(peer,'udp',peer6,19002)
            self.apply_config({'policies':[{'default_action':'allow','rules':[]}]})
            assert self.probe(self.guest,'tcp',self.target6,19001)
            before=self.ethernet_packets('forward')
            assert not self.probe(self.guest,'tcp',peer6,19001) and not self.probe(self.guest,'udp',peer6,19002)
            assert self.ethernet_packets('forward')>before
            self.check('same_bridge_ipv6_is_denied_while_policy_allowed_routed_ipv6_remains_usable')


class IPv6Contract(IPv6Cases,EthernetContract):pass
class IPv6ComponentContract(IPv6Cases,FrontendContract):pass


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',default='goldenhoop-network-fixture:test')
    parser.add_argument('--runtime',choices=['runc','runsc'],default='runc')
    parser.add_argument('--output',required=True)
    parser.add_argument('--remove-image',action='store_true')
    parser.add_argument('--receiver-publication',choices=['loopback','routed'],default='loopback')
    parser.add_argument('--resolver-path',choices=['owned'],default='owned')
    parser.add_argument('--ci-host-diagnostics',action='store_true')
    parser.add_argument('--component-only',action='store_true')
    parser.set_defaults(expect_unavailable=False,raw_control=False)
    args=parser.parse_args()
    if args.ci_host_diagnostics and os.environ.get('GITHUB_ACTIONS')!='true':parser.error('ephemeral CI only')
    (IPv6ComponentContract if args.component_only else IPv6Contract)(args).run()
