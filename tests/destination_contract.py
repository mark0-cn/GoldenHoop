"""Actual pre/post-NAT destination floor and address-free DNS refusal."""
import argparse
import hashlib
import ipaddress
import json
import os
import time
from pathlib import Path

from ipv6_samples import TARGET
from destination_samples import LOCAL_HOST
from network_contract import Stream,docker
from source_contract import SourceContract,SourceProbeContract


class DestinationCases:
    def __init__(self,args):
        super().__init__(args)
        self.evidence['suite']='rust-destination-component' if args.component_only else 'rust-composed-destination-floor'
        self.evidence['scope']='actual protected/private targets, pre/post-DNAT, DNS grant refusal and immutable guard recovery; component-only omits bridge source/Ethernet; production journal/credential acceptance belongs to its separate gates'
        self.protected_bound=False;self.translation_attempted=False;self.private_stream=None
        self.extra_addresses=[];self.injected_rule=None
        root=Path(__file__).resolve().parents[1]
        for name in ('destination_contract.py','destination_samples.py'):
            path=root/'tests'/name;self.evidence['source_files_sha256'][path.relative_to(root).as_posix()]=hashlib.sha256(path.read_bytes()).hexdigest()
        self.save()

    def container(self,role,options,script,*args):
        if role=='dns-target':options=[*options,'--env','GOLDENHOOP_DNS_RECORDS='+json.dumps(self.dns_overrides|self.dynamic_dns_overrides)]
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

    def stop_local_host_target(self):
        identities=docker('ps','-a','--filter','label=dev.goldenhoop.attempt='+self.attempt,'--filter','label=dev.goldenhoop.role=local-host-target','--format','{{.ID}}').stdout.split()
        for identity in identities:
            self.owned(json.loads(docker('inspect',identity).stdout)[0]);docker('rm','--force','--volumes',identity)
        assert not docker('ps','-a','--filter','label=dev.goldenhoop.attempt='+self.attempt,'--filter','label=dev.goldenhoop.role=local-host-target','--format','{{.ID}}').stdout.strip()

    def restore_host_addresses(self):
        failures=[]
        for item in list(self.extra_addresses):
            bridge,address,prefix=item
            try:
                values=json.loads(self.exec(self.helper,'ip','-json','addr','show','dev',bridge).stdout)
                if any(a.get('local')==address for link in values for a in link.get('addr_info',[])):
                    self.exec(self.helper,'ip','addr','del',address+'/'+str(prefix),'dev',bridge)
                values=json.loads(self.exec(self.helper,'ip','-json','addr','show','dev',bridge).stdout)
                assert not any(a.get('local')==address for link in values for a in link.get('addr_info',[]))
                self.extra_addresses.remove(item)
                self.evidence.setdefault('dynamic_host_addresses_collected',[]).append({'bridge':bridge,'address':address,'confirmed_absent':True});self.save()
            except BaseException as error:failures.append(repr(error))
        if failures:raise RuntimeError('owned host address collection failed: '+repr(failures))

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
                try:
                    try:self.stop_local_host_target()
                    finally:self.restore_host_addresses()
                finally:
                    try:self.remove_injected_rule()
                    finally:self.collect_translation()
        finally:super().cleanup()

    def floor_drops(self,local_only=False):
        value=json.loads(self.exec(self.helper,'nft','--json','list','table','inet','gh_d_'+self.attempt).stdout)
        return sum(p['counter']['packets'] for e in value['nftables'] if 'rule' in e and (not local_only or any(x.get('match',{}).get('left',{}).get('fib')=={'result':'type','flags':['daddr']} for x in e['rule']['expr'])) for p in e['rule']['expr'] if 'counter' in p and any('drop' in x for x in e['rule']['expr']))

    def blocked(self,address,transport='tcp',port=19001,local_only=False):
        before=self.floor_drops(local_only);assert not self.probe(self.guest,transport,address,port),(address,transport)
        after=self.floor_drops(local_only);assert after>before,(address,transport,before,after)
        self.evidence.setdefault('destination_drop_observations',[]).append({'address':address,'transport':transport,'port':port,'local_route_only':local_only,'before':before,'after':after});self.save()
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
        target_net=next(r for r in self.evidence['resources'] if r['role']=='target-net')
        native=json.loads(docker('network','inspect',target_net['network_id']).stdout)[0];self.owned(native)
        self.dynamic_bridge=native['Options'].get('com.docker.network.bridge.name','br-'+native['Id'][:12])
        subnets={ipaddress.ip_network(c['Subnet']).version:ipaddress.ip_network(c['Subnet']) for c in native['IPAM']['Config']}
        self.dynamic4=str(subnets[4][-2]);self.dynamic6=str(subnets[6][-2])
        endpoints={str(ipaddress.ip_interface(value[key]).ip) for value in native['Containers'].values() for key in ('IPv4Address','IPv6Address') if value.get(key)}
        assert not {self.dynamic4,self.dynamic6}&endpoints
        self.dynamic_dns_overrides={'new-host-floor.test':{'A':self.dynamic4,'AAAA':self.dynamic6}}
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

    def dynamic_host_cases(self):
        prefix=f'fd{self.attempt[:2]}:{self.attempt[2:6]}:{self.attempt[6:10]}:4::/64'
        bridge='ghpc'+self.attempt[:10]
        identity,native=self.network('concurrent-net','--internal','--ipv6','--subnet',prefix,'--opt','com.docker.network.bridge.name='+bridge)
        self.evidence['concurrent_allocation_network']=native;self.save()
        try:
            renewed=self.rpc('renew',expected_revision=self.revision)['result']
            assert renewed['destinations_guarded'] and renewed['destination_binding_sha256']==self.destination_digest,renewed
            for address in (self.target_ip,self.target6):assert self.probe(self.guest,'tcp',address,19001),address
            self.dns_probe(self.guest,'udp',self.gateway,53,'long.test',0);self.rpc('renew',expected_revision=self.revision)
            self.dns6(self.guest,'tcp',self.gateway6,53,'ipv6-long.test',0);self.rpc('renew',expected_revision=self.revision)
        finally:
            observed=json.loads(docker('network','inspect',identity).stdout)[0];self.owned(observed);assert not observed['Containers']
            docker('network','rm',identity)
            assert not docker('network','ls','--filter','id='+identity,'--format','{{.ID}}').stdout.strip()
            links=json.loads(self.exec(self.helper,'ip','-json','link','show').stdout);assert not any(link['ifname']==bridge for link in links)
            self.evidence['concurrent_allocation_bridge_and_network_absent']=True;self.save()
        self.check('another_owned_dualstack_bridge_allocation_keeps_existing_digest_lease_packets_and_dns_live')
        current=json.loads(self.exec(self.helper,'ip','-json','addr','show','dev',self.dynamic_bridge).stdout)
        assert not any(a.get('local') in (self.dynamic4,self.dynamic6) for link in current for a in link.get('addr_info',[]))
        try:
            for address,prefix in ((self.dynamic4,32),(self.dynamic6,128)):
                item=(self.dynamic_bridge,address,prefix);self.extra_addresses.append(item)
                self.evidence.setdefault('dynamic_host_address_intent',[]).append({'bridge':self.dynamic_bridge,'address':address,'prefix':prefix});self.save()
                self.exec(self.helper,'ip','addr','add',address+'/'+str(prefix),'dev',self.dynamic_bridge)
            local=self.container('local-host-target',['--runtime','runc','--network','host','--user','1000:1000','--memory','128m','--memory-swap','128m','--cpus','0.25','--pids-limit','32'],LOCAL_HOST,self.dynamic4,self.dynamic6,self.attempt)
            ready=self.ready(local)
            assert ready['address4']==self.dynamic4 and ready['address6']==self.dynamic6 and ready['uid']==ready['gid']==1000 and ready['cap_effective']==0 and ready['no_new_privileges'],ready
            self.evidence['dynamic_host_target']=ready;self.save()
            for address,port in ((self.dynamic4,ready['port4']),(self.dynamic6,ready['port6'])):
                assert self.probe(self.helper,'tcp',address,port),(address,port)
            renewed=self.rpc('renew',expected_revision=self.revision)['result']
            assert renewed['destinations_guarded'] and renewed['destination_binding_sha256']==self.destination_digest,renewed
            for address in (self.target_ip,self.target6):
                for mode,port in (('tcp',19001),('udp',19002)):assert self.probe(self.guest,mode,address,port),(address,mode)
                self.rpc('renew',expected_revision=self.revision)
            self.dns_probe(self.guest,'udp',self.gateway,53,'long.test',0);self.rpc('renew',expected_revision=self.revision)
            self.dns6(self.guest,'tcp',self.gateway6,53,'ipv6-long.test',0);self.rpc('renew',expected_revision=self.revision)
            self.check('unrelated_dualstack_host_addresses_keep_existing_revision_digest_lease_packets_and_dns_live')
            for address,port in ((self.dynamic4,ready['port4']),(self.dynamic6,ready['port6'])):self.blocked(address,port=port,local_only=True)
            self.check('new_host_addresses_inside_administrator_private_exceptions_hit_the_actual_local_route_drop')
            name='gh_t_'+self.attempt
            for alias,address,port in (('203.0.113.6',self.dynamic4,ready['port4']),('2001:db8::6',self.dynamic6,ready['port6'])):
                family='ip' if ipaddress.ip_address(alias).version==4 else 'ip6'
                target=f'{address}:{port}' if family=='ip' else f'[{address}]:{port}'
                self.exec(self.helper,'nft','--file','-',data=f'add rule inet {name} prerouting iifname "{self.bridge}" {family} daddr {alias} tcp dport {port} dnat {family} to {target}\n')
                self.blocked(alias,port=port,local_only=True)
            self.evidence['dynamic_host_translation_table']=json.loads(self.exec(self.helper,'nft','--json','list','table','inet',name).stdout);self.save()
            self.check('post_dnat_new_host_targets_hit_the_actual_local_route_drop_in_both_families')
            self.dns_probe(self.guest,'udp',self.gateway,53,'new-host-floor.test',5);self.rpc('renew',expected_revision=self.revision)
            self.dns6(self.guest,'tcp',self.gateway6,53,'new-host-floor.test',5);self.rpc('renew',expected_revision=self.revision)
            for aaaa in (False,True):assert not self.rpc('dns_source',name='new-host-floor.test',aaaa=aaaa)['result']['source_live']
            queries=self.queries(self.dns_target)
            assert all(any(q['query']=='new-host-floor.test' and q['kind']==kind for q in queries) for kind in (1,28)),queries
            self.evidence['dynamic_host_dns_upstream_queries']=queries;self.save()
            self.check('new_host_dns_answers_are_refused_without_source_credit_after_actual_dualstack_resolution')
        finally:
            try:self.stop_local_host_target()
            finally:self.restore_host_addresses()
        self.rpc('renew',expected_revision=self.revision)
        reply=self.dns_probe(self.guest,'udp',self.gateway,53,'new-host-floor.test')
        assert reply['ok'] and reply['rcode']==0 and reply['addresses']==[self.dynamic4],reply
        self.rpc('renew',expected_revision=self.revision)
        reply=self.dns6(self.guest,'tcp',self.gateway6,53,'new-host-floor.test')
        assert reply['ok'] and reply['rcode']==0 and reply['addresses']==[self.dynamic6],reply
        self.rpc('renew',expected_revision=self.revision)
        for aaaa in (False,True):assert self.rpc('dns_source',name='new-host-floor.test',aaaa=aaaa)['result']['source_live']
        self.check('collected_new_host_addresses_return_to_the_existing_private_exception_without_rebinding')

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
        if not self.args.component_only:
            renewed=self.rpc('renew',expected_revision=self.revision)['result']
            assert all(renewed[key] for key in ('ethernet_guarded','source_guarded','destinations_guarded')) and not renewed['uncertain'],renewed
            assert renewed['maximum_lease_seconds']==10 and 'binding' not in renewed and 'lease_remaining_milliseconds' not in renewed,renewed
            self.check('relative_DNS_lifetime_basic_renewal_preserves_every_native_guard_without_minting_a_binding_receipt')
            refused=self.rpc('renew_policy',expected_revision=self.revision,error=True)
            assert (refused['error']['code'],refused['error']['message'])==('invalid_state','bind original native lifetime before policy inspection'),refused
            after=self.rpc('renew',expected_revision=self.revision)['result']
            assert not after['uncertain'] and after['revision']==renewed['revision'] and after['maximum_lease_seconds']==10,after
            for key in ('ethernet_guarded','source_guarded','destinations_guarded'):
                assert after[key],after
            for key in ('ethernet_sha256','source_binding_sha256','destination_binding_sha256'):
                assert after[key]==renewed[key],(key,renewed,after)
            assert 'binding' not in after and 'lease_remaining_milliseconds' not in after,after
            self.check('relative_DNS_lifetime_cannot_mint_a_public_policy_receipt_or_mutate_the_verified_basic_lease')
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
        self.dynamic_host_cases()
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
