"""Actual trusted endpoint binding, source spoofing and ARP/ND host protection."""
import argparse
import hashlib
import ipaddress
import json
import os
import time
from pathlib import Path

from ipv6_contract import IPv6Contract,IPv6ComponentContract
from network_contract import docker
from source_samples import INSPECT,PACKET,RECEIVER


class SourceCases:
    def __init__(self,args):
        super().__init__(args)
        self.evidence['suite']='rust-endpoint-source-floor'
        self.evidence['scope']='actual owned endpoint MAC/IP and canonical ARP/ND binding; durable driver integration/metadata/credentials remain incomplete'
        if args.probe_only:
            self.evidence['suite']='source-fixture-prerequisite-probe'
            self.evidence['scope']='actual trusted endpoint/provider mapping and source-spoof diagnostic controls; source floor not installed; no capability granted'
        self.source_bound=False
        root=Path(__file__).resolve().parents[1]
        for name in ('source_contract.py','source_samples.py'):
            p=root/'tests'/name;self.evidence['source_files_sha256'][p.relative_to(root).as_posix()]=hashlib.sha256(p.read_bytes()).hexdigest()
        self.save()

    def allowed_capabilities(self,role):
        if role.startswith('source-packet-'):return {'NET_RAW'}
        return super().allowed_capabilities(role)

    def completed(self,identity):
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            state=json.loads(docker('inspect',identity).stdout)[0]['State']
            if not state['Running']:
                assert state['ExitCode']==0,(state,docker('logs',identity).stdout)
                return json.loads(docker('logs',identity).stdout)
            time.sleep(.05)
        raise RuntimeError('owned source diagnostic did not complete')

    def ready(self,identity):
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            for line in docker('logs',identity).stdout.splitlines():
                observed=json.loads(line)
                if observed.get('ready'):return observed
            time.sleep(.05)
        raise RuntimeError('owned source receiver did not become ready')

    def packet(self,phase,mode,expect_delivery=None):
        nonce=self.attempt+':'+phase+':'+mode
        role='source-packet-'+phase+'-'+mode
        identity=self.container(role,['--runtime','runc','--network','container:'+self.guest,'--user','0:0','--cap-add','NET_RAW','--memory','128m','--memory-swap','128m','--cpus','0.25','--pids-limit','32'],PACKET,mode,nonce,json.dumps(self.packet_config))
        observed=self.completed(identity)
        expected_frames=6 if mode.endswith(('-frag','-fragment')) else 3
        assert observed['sent_frames']==expected_frames and observed['cap_effective']==1<<13 and observed['no_new_privileges'],observed
        received=any(json.loads(line).get('nonce')==nonce for line in docker('logs',self.source_receiver).stdout.splitlines())
        if expect_delivery is not None:assert received==expect_delivery,(mode,received,observed)
        self.evidence.setdefault('source_packet_observations',[]).append({'phase':phase,'mode':mode,'receiver_nonce_observed':received,'sender':observed})
        self.save()
        return observed

    def source_counters(self,chain):
        entries=json.loads(self.exec(self.helper,'nft','--json','list','table','bridge','gh_s_'+self.attempt).stdout)['nftables']
        assert any(e.get('chain',{}).get('name')==self.owner.replace(':','_') for e in entries)
        return sum(x['counter']['packets'] for e in entries if 'rule' in e and e['rule']['chain']==chain for x in e['rule']['expr'] if 'counter' in x and any('drop' in v for v in e['rule']['expr']))

    def dropped(self,mode,chain,delivery=None):
        before=self.source_counters(chain);self.packet('after',mode,delivery)
        after=self.source_counters(chain)
        self.evidence.setdefault('source_drop_observations',[]).append({'mode':mode,'chain':chain,'before':before,'after':after})
        self.save();assert after>=before+3,(mode,chain,before,after)
        self.rpc('renew',expected_revision=self.revision)

    def rpc(self,operation,error=False,**fields):
        try:
            reply=super().rpc(operation,error=error,**fields)
        finally:
            if operation=='bind_source':
                observation=self.exec(self.helper,'nft','--json','list','table','bridge','gh_s_'+self.attempt,check=False)
                self.evidence['source_bind_kernel_observation']={'exit_code':observation.returncode,'stderr':observation.stderr,'json':json.loads(observation.stdout) if observation.returncode==0 else None}
                self.save()
        if operation=='remove' and not error:
            assert not reply['result']['source_guarded'] and reply['result']['source_binding_sha256'] is None
            assert not any(e.get('table',{}).get('name')=='gh_s_'+self.attempt and e['table']['family']=='bridge' for e in self.tables())
            self.evidence['owned_source_table_absent']=True
            self.save()
        return reply

    def open(self):
        # The v1 Ethernet raw-loss probe uses another ingress port; source
        # admission intentionally refuses it earlier in prerouting.
        if self.phase==3 and self.source_bound:
            peer=self.raw_peer;self.raw_peer=None
            try:reply=super().open()
            finally:self.raw_peer=peer
            assert reply['result']['source_guarded'] and reply['result']['source_binding_sha256']==self.source_digest,reply
            self.check('restart_adopts_the_owned_source_descriptor_without_forgetting_its_floor')
            return reply
        return super().open()

    def kernel_policy_cases(self):
        super().kernel_policy_cases()
        observed=json.loads(docker('inspect',self.guest).stdout)[0]
        endpoint=next(iter(observed['NetworkSettings']['Networks'].values()))
        inspector=self.container('source-inspector',['--runtime','runc','--network','container:'+self.guest,'--user','1000:1000','--memory','128m','--memory-swap','128m','--cpus','0.25','--pids-limit','32'],INSPECT)
        inspection=self.completed(inspector)
        assert json.loads(docker('inspect',inspector).stdout)[0]['HostConfig']['NetworkMode']=='container:'+self.guest
        assert inspection['cap_effective']==0 and inspection['no_new_privileges'] and inspection['uid']==1000
        assert len(inspection['links'])==1,inspection
        guest_link=inspection['links'][0];assert guest_link['mac']==endpoint['MacAddress']
        links=json.loads(self.exec(self.helper,'ip','-json','link','show','master',self.bridge).stdout)
        link=next(l for l in links if l['ifindex']==guest_link['iflink'])
        reverse=int(self.exec(self.helper,'cat','/sys/class/net/'+link['ifname']+'/iflink').stdout)
        assert reverse==guest_link['ifindex']
        binding={'port':link['ifname'],'ifindex':link['ifindex'],'mac':endpoint['MacAddress'],'ipv4':endpoint['IPAddress'],'ipv6':endpoint['GlobalIPv6Address']}
        self.evidence['trusted_endpoint_observation']={'provider_container':self.guest,'provider_network_endpoint':endpoint,'inspector':inspection,'host_port':link,'binding':binding}
        self.save()
        target_network=next(r['network_id'] for r in self.evidence['resources'] if r['role']=='target-net')
        bind4='0.0.0.0' if self.args.receiver_publication=='routed' else '127.0.0.1'
        bind6='::' if self.args.receiver_publication=='routed' else '::1'
        self.source_receiver=self.container('source-receiver',['--runtime','runc','--network',target_network,'--user','1000:1000','--memory','128m','--memory-swap','128m','--cpus','0.25','--pids-limit','32','--publish',bind4+'::19101/udp','--publish','['+bind6+']::19101/udp'],RECEIVER,self.attempt)
        self.ready(self.source_receiver)
        receiver=json.loads(docker('inspect',self.source_receiver).stdout)[0]
        publications=receiver['NetworkSettings']['Ports']
        assert all(not r['HostPort'] or r['HostIp'] in ('127.0.0.1','::1') for values in publications.values() for r in (values or [])),publications
        if self.args.receiver_publication=='routed':assert all(not r['HostPort'] for values in publications.values() for r in (values or [])),publications
        self.evidence['source_receiver_port_bindings']=publications
        target=next(iter(receiver['NetworkSettings']['Networks'].values()))
        gateway_mac=json.loads(self.exec(self.helper,'ip','-json','link','show','dev',self.bridge).stdout)[0]['address']
        self.packet_config={**binding,'gateway_mac':gateway_mac,'gateway4':self.gateway,'gateway6':self.gateway6,'target4':target['IPAddress'],'target6':target['GlobalIPv6Address'],'fake4':str(ipaddress.IPv4Address(int(ipaddress.IPv4Address(binding['ipv4']))+555)),'fake6':str(ipaddress.IPv6Address(int(ipaddress.IPv6Address(binding['ipv6']))+555))}
        self.evidence['trusted_source_scope']={'endpoint':binding,'gateway_mac':gateway_mac,'gateway4':self.gateway,'gateway6':self.gateway6}
        self.save()
        self.apply_config({'policies':[{'default_action':'allow','rules':[]}]})
        for mode in ('normal4','normal6','mac4','spoof4','spoof6'):
            self.packet('before',mode,True)
            self.rpc('renew',expected_revision=self.revision)
        self.check('source_spoof_vectors_reach_a_controlled_receiver_before_the_source_floor')
        for mode in ('normal4-frag','spoof4-frag','normal6-frag','spoof6-frag','normal6-hbh','spoof6-hbh','normal6-dest','spoof6-dest'):
            result=self.packet('before',mode,True)
            if mode.startswith('normal'):assert result['reply'],mode
            self.rpc('renew',expected_revision=self.revision)
        self.check('valid_ipv4_ipv6_fragments_and_ipv6_extension_spoof_vectors_reach_the_receiver_before_enforcement')
        self.rpc('quarantine',expected_revision=self.revision)
        if self.args.probe_only:
            refused=self.rpc('bind_source',expected_revision=self.revision,endpoint=binding,error=True)
            assert refused['error']['code']=='invalid_state',refused
            assert not self.rpc('inspect')['result']['source_guarded']
            self.evidence['source_prerequisite_refusal']=refused
            self.check('missing_ethernet_prerequisite_refuses_source_admission_without_claiming_a_guard')
            return
        reply=self.rpc('bind_source',expected_revision=self.revision,endpoint=binding)['result']
        assert reply['source_guarded'] and reply['source_binding_sha256'],reply
        self.source_bound=True;self.source_digest=reply['source_binding_sha256']
        self.evidence['confirmed_source_observation']=reply;self.save()
        self.apply_config({'policies':[{'default_action':'allow','rules':[]}]})
        for mode in ('normal4','normal6'):
            assert self.packet('after',mode,True)['reply']
            self.rpc('renew',expected_revision=self.revision)
        self.check('bound_ipv4_and_ipv6_sources_keep_real_routed_udp_admission')
        for mode in ('mac4','spoof4','spoof6','vlan4'):
            self.dropped(mode,'ipv6_source' if mode=='spoof6' else 'prerouting',False)
        self.check('foreign_mac_ip_sources_and_vlan_frames_hit_scoped_kernel_drops')
        for mode in ('normal4-frag','normal6-frag','normal6-hbh','normal6-dest'):
            assert self.packet('after',mode,True)['reply'],mode
            self.rpc('renew',expected_revision=self.revision)
        for mode in ('spoof4-frag','spoof6-frag','spoof6-hbh','spoof6-dest'):
            self.dropped(mode,'prerouting' if mode=='spoof4-frag' else 'ipv6_source',False)
        self.check('fragments_and_ipv6_extension_headers_preserve_owned_data_admission_without_foreign_source_bypass')
        for mode in ('arp-good','ns-good'):
            assert self.packet('after',mode)['reply'],mode
            self.rpc('renew',expected_revision=self.revision)
        self.check('canonical_arp_and_ipv6_neighbor_discovery_have_real_gateway_replies')
        neighbors=self.exec(self.helper,'ip','-json','neigh','show','dev',self.bridge).stdout
        for mode in ('arp-sha','arp-spa','ns-target','na-option','na-target','na-router'):
            self.dropped(mode,'arp_source' if mode.startswith('arp-') else 'neighbor_source')
        for mode in ('ns-extension','na-extension','na-fragment','ns-hop','ns-code'):
            self.dropped(mode,'neighbor_source')
        self.check('fragmented_or_extension_wrapped_neighbor_messages_and_wrong_hop_code_hit_source_drops')
        after=json.loads(self.exec(self.helper,'ip','-json','neigh','show','dev',self.bridge).stdout)
        wrong_mac=binding['mac'][:-2]+format(int(binding['mac'][-2:],16)^1,'02x')
        assert not any(row.get('lladdr')==wrong_mac for row in after),after
        self.evidence['source_neighbor_observations']={'before':json.loads(neighbors),'after':after}
        self.check('forged_arp_and_neighbor_targets_options_and_router_flags_cannot_change_host_neighbors')


class SourceContract(SourceCases,IPv6Contract):pass
class SourceProbeContract(SourceCases,IPv6ComponentContract):pass


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',default='goldenhoop-network-fixture:test')
    parser.add_argument('--runtime',choices=['runc','runsc'],default='runc')
    parser.add_argument('--output',required=True)
    parser.add_argument('--remove-image',action='store_true')
    parser.add_argument('--receiver-publication',choices=['loopback','routed'],default='loopback')
    parser.add_argument('--ci-host-diagnostics',action='store_true')
    parser.add_argument('--probe-only',action='store_true')
    parser.set_defaults(resolver_path='owned',component_only=False,expect_unavailable=False,raw_control=False)
    args=parser.parse_args()
    args.component_only=args.probe_only
    if args.ci_host_diagnostics and os.environ.get('GITHUB_ACTIONS')!='true':parser.error('ephemeral CI only')
    (SourceProbeContract if args.probe_only else SourceContract)(args).run()
