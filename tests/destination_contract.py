"""Actual pre/post-NAT destination floor and address-free DNS refusal."""
import argparse
import hashlib
import ipaddress
import json
import os
import time
from pathlib import Path

from ipv6_samples import TARGET
from network_contract import Stream,docker
from source_contract import SourceContract,SourceProbeContract


class DestinationCases:
    def __init__(self,args):
        super().__init__(args)
        self.evidence['suite']='rust-destination-component' if args.component_only else 'rust-composed-destination-floor'
        self.evidence['scope']='actual protected/private targets, pre/post-DNAT, DNS grant refusal and immutable guard recovery; component-only omits bridge source/Ethernet; production journal/credentials remain incomplete'
        self.protected_bound=False;self.translation_attempted=False;self.private_stream=None
        self.extra_address=None;self.injected_rule=None
        path=Path(__file__).resolve();self.evidence['source_files_sha256'][path.relative_to(path.parents[1]).as_posix()]=hashlib.sha256(path.read_bytes()).hexdigest();self.save()

    def container(self,role,options,script,*args):
        if role=='dns-target':options=[*options,'--env','GOLDENHOOP_DNS_RECORDS='+json.dumps(self.dns_overrides)]
        return super().container(role,options,script,*args)

    def rpc(self,operation,error=False,**fields):
        try:reply=super().rpc(operation,error=error,**fields)
        finally:
            if operation=='protect_destinations':
                result=self.exec(self.helper,'nft','--json','list','table','inet','gh_d_'+self.attempt,check=False)
                self.evidence['destination_bind_kernel_observation']={'exit_code':result.returncode,'stderr':result.stderr,'json':json.loads(result.stdout) if result.returncode==0 else None};self.save()
        if operation=='remove' and not error:
            assert not reply['result']['destinations_guarded'] and reply['result']['destination_binding_sha256'] is None
            assert not any(e.get('table',{}).get('name')=='gh_d_'+self.attempt for e in self.tables())
            self.evidence['owned_destination_table_absent']=True;self.save()
        return reply

    def destination_dns_observation(self,started):
        if not self.protected_bound:return
        result=self.exec(self.helper,'nft','--json','list','table','inet','gh_d_'+self.attempt,check=False)
        self.evidence.setdefault('destination_dns_observations',[]).append({'elapsed_seconds':time.monotonic()-started,'exit_code':result.returncode,'stderr':result.stderr,'json':json.loads(result.stdout) if result.returncode==0 else None})
        self.save()

    def dns_probe(self,*args,**kwargs):
        started=time.monotonic()
        try:return super().dns_probe(*args,**kwargs)
        finally:self.destination_dns_observation(started)

    def dns6(self,*args,**kwargs):
        started=time.monotonic()
        try:return super().dns6(*args,**kwargs)
        finally:self.destination_dns_observation(started)

    def open(self):
        reply=super().open()
        if self.phase==3 and self.protected_bound:
            assert reply['result']['destinations_guarded'] and reply['result']['destination_binding_sha256']==self.destination_digest,reply
            self.check('restart_adopts_the_immutable_destination_descriptor_and_guard')
        return reply

    def collect_translation(self):
        if not self.translation_attempted:return
        name='gh_t_'+self.attempt
        if any(e.get('table',{}).get('name')==name and e['table']['family']=='inet' for e in self.tables()):
            value=json.loads(self.exec(self.helper,'nft','--json','list','table','inet',name).stdout)
            owners=[e['chain']['name'] for e in value['nftables'] if 'chain' in e and e['chain']['name'].startswith('goldenhoop_')]
            assert owners==[self.owner.replace(':','_')],owners
            self.exec(self.helper,'nft','delete','table','inet',name)
        assert not any(e.get('table',{}).get('name')==name for e in self.tables())
        self.translation_attempted=False;self.evidence['owned_translation_table_absent']=True;self.save()

    def restore_host_address(self):
        if self.extra_address is None:return
        bridge,address=self.extra_address
        self.exec(self.helper,'ip','addr','del',address+'/32','dev',bridge)
        values=json.loads(self.exec(self.helper,'ip','-json','addr','show','dev',bridge).stdout)
        assert not any(a.get('local')==address for link in values for a in link.get('addr_info',[]))
        self.extra_address=None

    def remove_injected_rule(self):
        if self.injected_rule is None:return
        self.exec(self.helper,'nft','delete','rule','inet','gh_d_'+self.attempt,'decision','handle',str(self.injected_rule))
        self.injected_rule=None

    def cleanup(self):
        try:
            if self.protected_bound:
                try:
                    result=self.exec(self.helper,'nft','--json','list','table','inet','gh_d_'+self.attempt,check=False)
                    self.evidence['destination_before_cleanup']={'exit_code':result.returncode,'stderr':result.stderr,'json':json.loads(result.stdout) if result.returncode==0 else None}
                except BaseException as error:self.evidence['destination_cleanup_diagnostic_error']=repr(error)
                self.save()
            try:
                if self.private_stream:self.private_stream.close();self.private_stream=None
            finally:
                try:self.restore_host_address()
                finally:
                    try:self.remove_injected_rule()
                    finally:self.collect_translation()
        finally:super().cleanup()

    def floor_drops(self):
        value=json.loads(self.exec(self.helper,'nft','--json','list','table','inet','gh_d_'+self.attempt).stdout)
        return sum(p['counter']['packets'] for e in value['nftables'] if 'rule' in e for p in e['rule']['expr'] if 'counter' in p and any('drop' in x for x in e['rule']['expr']))

    def blocked(self,address,transport='tcp',port=19001):
        before=self.floor_drops();assert not self.probe(self.guest,transport,address,port),(address,transport)
        after=self.floor_drops();assert after>before,(address,transport,before,after)
        self.evidence.setdefault('destination_drop_observations',[]).append({'address':address,'transport':transport,'before':before,'after':after});self.save()
        self.rpc('renew',expected_revision=self.revision)

    def prepare_protected_target(self):
        prefix=f'fd{self.attempt[:2]}:{self.attempt[2:6]}:{self.attempt[6:10]}:3::/64'
        network,net=self.network('protected-net','--ipv6','--subnet',prefix,'--opt','com.docker.network.bridge.name=ghpp'+self.attempt[:10],'--opt','com.docker.network.bridge.gateway_mode_ipv4=routed','--opt','com.docker.network.bridge.gateway_mode_ipv6=routed')
        self.protected_bridge=net['Options'].get('com.docker.network.bridge.name','br-'+network[:12])
        bind4='0.0.0.0' if self.args.receiver_publication=='routed' else '127.0.0.1'
        bind6='::' if self.args.receiver_publication=='routed' else '::1'
        options=['--runtime','runc','--network',network,'--user','1000:1000','--memory','128m','--memory-swap','128m','--cpus','0.25','--pids-limit','32']
        for bind in (bind4,'['+bind6+']'):
            for port,transport in ((19001,'tcp'),(19002,'udp')):options.extend(['--publish',f'{bind}::{port}/{transport}'])
        target=self.container('protected-target',options,TARGET,self.attempt);self.ready(target)
        obj=json.loads(docker('inspect',target).stdout)[0];endpoint=next(iter(obj['NetworkSettings']['Networks'].values()))
        self.private4=endpoint['IPAddress'];self.private6=endpoint['GlobalIPv6Address']
        ports=obj['NetworkSettings']['Ports'];assert all(not p['HostPort'] or p['HostIp'] in ('127.0.0.1','::1') for values in ports.values() for p in (values or [])),ports
        if self.args.receiver_publication=='routed':assert all(not p['HostPort'] for values in ports.values() for p in (values or [])),ports
        self.dns_overrides={'private-floor.test':{'A':self.private4,'AAAA':self.private6},'metadata-floor.test':{'A':'100.100.100.200','AAAA':'fd00:ec2::254'},'control-floor.test':{'A':'203.0.113.8','AAAA':'2001:db8::8'},'host-floor.test':{'A':self.gateway,'AAAA':self.gateway6}}
        self.evidence['controlled_private_target']={'container':target,'address4':self.private4,'address6':self.private6,'ports':ports};self.save()

    def prepare_translation(self):
        name='gh_t_'+self.attempt;assert not any(e.get('table',{}).get('name')==name for e in self.tables())
        self.translations=[('203.0.113.7',self.private4),('2001:db8::7',self.private6),('203.0.113.8',self.target_ip),('2001:db8::8',self.target6),('169.254.169.254',self.target_ip),('100.100.100.200',self.target_ip),('fd00:ec2::254',self.target6)]
        lines=[f'add table inet {name}',f'add chain inet {name} {self.owner.replace(":","_")}',f'add chain inet {name} prerouting {{ type nat hook prerouting priority -100; policy accept; }}']
        for source,dest in self.translations:
            family='ip' if ipaddress.ip_address(source).version==4 else 'ip6'
            for protocol,port in (('tcp',19001),('udp',19002)):
                target=f'{dest}:{port}' if family=='ip' else f'[{dest}]:{port}'
                lines.append(f'add rule inet {name} prerouting iifname "{self.bridge}" {family} daddr {source} {protocol} dport {port} dnat {family} to {target}')
        self.translation_attempted=True;self.exec(self.helper,'nft','--file','-',data='\n'.join(lines)+'\n')
        self.evidence['controlled_translation_table']=json.loads(self.exec(self.helper,'nft','--json','list','table','inet',name).stdout);self.save()

    def kernel_policy_cases(self):
        self.prepare_protected_target()
        super().kernel_policy_cases()
        self.apply_config({'policies':[{'default_action':'allow','rules':[]}]})
        self.prepare_translation()
        for source,_ in self.translations:
            assert self.probe(self.guest,'tcp',source,19001),source
            self.rpc('renew',expected_revision=self.revision)
        for address in (self.private4,self.private6):
            assert self.probe(self.guest,'tcp',address,19001);assert self.probe(self.helper,'tcp',address,19001)
        self.private_stream=Stream(self.guest,self.private4,self.attempt);assert self.private_stream.exchange()['ok']
        self.check('controlled_private_and_translated_metadata_control_targets_are_live_before_the_destination_floor')
        self.rpc('quarantine',expected_revision=self.revision)
        bad=self.rpc('protect_destinations',expected_revision=self.revision,private_exceptions=['0.0.0.0/0'],control_addresses=[],error=True)
        assert bad['error']['code']=='invalid_request',bad
        assert not self.rpc('inspect')['result']['destinations_guarded']
        self.check('invalid_private_exception_is_rejected_without_publication_or_unknown_state')
        target_net=next(r for r in self.evidence['resources'] if r['role']=='target-net')
        exceptions=[str(ipaddress.ip_network(c['Subnet'])) for c in target_net['ipam']['Config']]+['100.64.0.0/10','fd00:ec2::/64']
        observed=self.rpc('protect_destinations',expected_revision=self.revision,private_exceptions=exceptions,control_addresses=['203.0.113.8','2001:db8::8'])['result']
        assert observed['destinations_guarded'] and observed['destination_binding_sha256'],observed
        self.protected_bound=True;self.destination_digest=observed['destination_binding_sha256'];self.evidence['confirmed_destination_observation']=observed;self.save()
        repeated=self.rpc('protect_destinations',expected_revision=self.revision,private_exceptions=[],control_addresses=[],error=True)
        assert repeated['error']['code']=='invalid_state' and self.rpc('inspect')['result']['destination_binding_sha256']==self.destination_digest,repeated
        self.check('destination_scope_cannot_be_replaced_or_weakened_on_a_live_allocation')
        self.apply_config({'policies':[{'default_action':'allow','rules':[]}],'allow_always':[{'destination':'*','ports':[],'action':'allow'}]})
        for address in (self.target_ip,self.target6):
            assert self.probe(self.guest,'tcp',address,19001);assert self.probe(self.guest,'udp',address,19002);self.rpc('renew',expected_revision=self.revision)
        self.check('administrator_private_exception_keeps_real_dualstack_tcp_udp_admission')
        before=self.floor_drops();expired=self.private_stream.exchange();assert not expired['ok'] and self.floor_drops()>before,expired
        self.evidence['protected_existing_flow_denial']=expired;self.private_stream.close();self.private_stream=None
        for address in (self.private4,self.private6):self.blocked(address);self.blocked(address,'udp',19002)
        self.check('private_destinations_deny_new_and_existing_flows_even_under_operator_allow')
        for address in ('203.0.113.8','2001:db8::8'):self.blocked(address)
        self.check('protected_original_control_destinations_cannot_hide_behind_dnat_to_an_excepted_target')
        for address in ('203.0.113.7','2001:db8::7'):self.blocked(address)
        self.check('otherwise_unrestricted_original_addresses_cannot_dnat_into_private_denied_targets')
        for address in ('169.254.169.254','100.100.100.200','fd00:ec2::254'):self.blocked(address)
        self.check('synthetic_metadata_targets_remain_denied_even_inside_private_exceptions')
        for mode in ('udp','tcp'):
            self.dns_probe(self.guest,mode,self.gateway,53,'long.test',0);self.rpc('renew',expected_revision=self.revision)
            self.dns6(self.guest,mode,self.gateway6,53,'ipv6-long.test',0);self.rpc('renew',expected_revision=self.revision)
        self.check('exact_owned_dns_infrastructure_survives_the_host_and_private_destination_floor')
        assert self.probe(self.helper,'tcp',self.gateway,self.host_port)
        self.blocked(self.gateway,'tcp',self.host_port)
        self.check('the_dns_infrastructure_exception_does_not_open_other_host_ports')
        for name in self.dns_overrides:
            self.dns_probe(self.guest,'udp',self.gateway,53,name,5);self.rpc('renew',expected_revision=self.revision)
            self.dns6(self.guest,'tcp',self.gateway6,53,name,5);self.rpc('renew',expected_revision=self.revision)
            for aaaa in (False,True):assert not self.rpc('dns_source',name=name,aaaa=aaaa)['result']['source_live']
        queries=self.queries(self.dns_target)
        assert all(any(q['query']==name and q['kind']==kind for q in queries) for name in self.dns_overrides for kind in (1,28)),queries
        self.evidence['destination_dns_upstream_queries']=queries;self.save()
        self.check('protected_dns_addresses_return_no_answer_or_source_grant_after_actual_upstream_resolution')
        self.apply_config({'policies':[{'default_action':'deny','rules':[]}]})
        assert not self.probe(self.guest,'tcp',self.target_ip,19001);assert not self.probe(self.guest,'tcp',self.target6,19001)
        self.check('a_private_exception_does_not_override_user_default_deny')
        self.apply_config({'policies':[{'default_action':'allow','rules':[]}]})
        protected_net=next(r for r in self.evidence['resources'] if r['role']=='protected-net')
        subnet=next(ipaddress.ip_network(c['Subnet']) for c in protected_net['ipam']['Config'] if ipaddress.ip_network(c['Subnet']).version==4)
        extra=str(subnet[-2]);assert extra not in (self.private4,str(subnet[1]))
        current=json.loads(self.exec(self.helper,'ip','-json','addr','show','dev',self.protected_bridge).stdout)
        assert not any(a.get('local')==extra for link in current for a in link.get('addr_info',[]))
        self.exec(self.helper,'ip','addr','add',extra+'/32','dev',self.protected_bridge);self.extra_address=(self.protected_bridge,extra)
        try:
            denied=self.rpc('renew',expected_revision=self.revision,error=True)
            assert denied['error']['code']=='conflict' and denied['error']['message']=='protected host address inventory changed',denied
            self.dns_probe(self.guest,'udp',self.gateway,53,'changed-host-floor.test',2)
        finally:self.restore_host_address()
        self.rpc('quarantine',expected_revision=self.revision);self.apply_config({'policies':[{'default_action':'allow','rules':[]}]})
        self.check('unrelated_host_address_changes_refuse_renewal_and_dns_addresses_until_quarantine_recovery')
        self.exec(self.helper,'nft','insert','rule','inet','gh_d_'+self.attempt,'decision','counter','accept')
        value=json.loads(self.exec(self.helper,'nft','--json','list','table','inet','gh_d_'+self.attempt).stdout)
        injected=[e['rule'] for e in value['nftables'] if 'rule' in e and e['rule']['chain']=='decision' and any('accept' in p for p in e['rule']['expr'])];assert len(injected)==1
        self.injected_rule=injected[0]['handle']
        try:
            unknown=self.rpc('inspect',allow_uncertain=True)['result'];assert unknown['uncertain'] and not unknown['destinations_guarded'],unknown
            denied=self.rpc('renew',expected_revision=self.revision,error=True);assert denied['error']['code']=='conflict',denied
            self.evidence['destination_widening_injection_observation']=unknown;self.save()
        finally:self.remove_injected_rule()
        self.rpc('quarantine',expected_revision=self.revision);self.apply_config({'policies':[{'default_action':'allow','rules':[]}]})
        self.check('unexpected_widened_kernel_rules_cannot_confirm_a_guard_or_new_controller_lease')
        self.collect_translation()


class DestinationContract(DestinationCases,SourceContract):pass
class DestinationComponentContract(DestinationCases,SourceProbeContract):pass


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image',default='goldenhoop-network-fixture:test');p.add_argument('--runtime',choices=['runc','runsc'],default='runc');p.add_argument('--output',required=True)
    p.add_argument('--remove-image',action='store_true');p.add_argument('--receiver-publication',choices=['loopback','routed'],default='loopback');p.add_argument('--ci-host-diagnostics',action='store_true');p.add_argument('--component-only',action='store_true')
    p.set_defaults(resolver_path='owned',expect_unavailable=False,raw_control=False,dns_lifetime=600)
    args=p.parse_args();args.probe_only=args.component_only
    if args.ci_host_diagnostics and os.environ.get('GITHUB_ACTIONS')!='true':p.error('ephemeral CI only')
    (DestinationComponentContract if args.component_only else DestinationContract)(args).run()
