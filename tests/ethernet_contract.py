"""Actual immutable route-only Ethernet floor, or explicit unavailable refusal."""
import argparse
import hashlib
import json
import os
import time
from pathlib import Path

from egress_contract import RustContract
from ethernet_samples import RAW
from frontend_contract import FrontendContract
from network_contract import docker
from network_samples import TARGET


class EthernetContract(FrontendContract):
    def __init__(self,args):
        super().__init__(args)
        self.ethernet_table='gh_l_'+self.attempt
        self._cleaning=False
        self.peer_network=None
        self.raw_peer=None
        self.evidence['suite']='rust-ethernet-floor-unavailable' if args.expect_unavailable else 'rust-ethernet-floor'
        self.evidence['scope']='route-only Ethernet floor plus inherited IPv4/DNS boundary; actual IPv6 routing/credentials/API remain incomplete'
        if args.raw_control:
            self.evidence['suite']='ethernet-raw-positive-control'
            self.evidence['scope']='trusted NET_RAW diagnostics only; no production filter installed or workload capability granted'
        root=Path(__file__).resolve().parents[1]
        for name in ('ethernet_contract.py','ethernet_samples.py'):
            p=root/'tests'/name;self.evidence['source_files_sha256'][p.relative_to(root).as_posix()]=hashlib.sha256(p.read_bytes()).hexdigest()
        self.save()

    def allowed_capabilities(self,role):
        if role in {'raw-control-peer','raw-control-client','raw-owned-peer','raw-owned-client','raw-loss-client','raw-host-input-client'}:return {'NET_RAW'}
        return super().allowed_capabilities(role)

    def rpc(self,operation,error=False,**fields):
        if operation=='inspect' and (self._cleaning or self.args.expect_unavailable):fields['allow_uncertain']=True
        reply=super().rpc(operation,error=error,**fields)
        if operation=='install' and not error and not self.args.expect_unavailable:
            guard=super().rpc('enable_ethernet',expected_revision=self.revision)['result']
            assert guard['ethernet_guarded'] and guard['ethernet_sha256'],guard
            self.evidence['initial_ethernet_observation']=guard
            self.check('owned_ethernet_floor_is_confirmed_before_workload_publication')
        if operation=='remove' and not error:
            assert not reply['result']['ethernet_guarded']
            assert not any(e.get('table',{}).get('family')=='bridge' and e['table']['name']==self.ethernet_table for e in self.tables())
            self.evidence['owned_ethernet_table_absent']=True
            self.save()
        return reply

    def cleanup(self):
        self._cleaning=True
        try:super().cleanup()
        finally:self._cleaning=False

    def ethernet_packets(self,chain):
        entries=json.loads(self.exec(self.helper,'nft','--json','list','table','bridge',self.ethernet_table).stdout)['nftables']
        assert any(e.get('chain',{}).get('name')==self.owner.replace(':','_') for e in entries)
        return sum(expr['counter']['packets'] for e in entries if 'rule' in e and e['rule']['chain']==chain for expr in e['rule']['expr'] if 'counter' in expr)

    def ready(self,identity):
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            for line in docker('logs',identity).stdout.splitlines():
                value=json.loads(line)
                if value.get('ready'):return value
            time.sleep(.05)
        raise RuntimeError('owned Ethernet fixture did not become ready')

    def raw_container(self,role,network,mode,peer='unused'):
        return self.container(role,['--runtime','runc','--network',network,'--user','0:0','--cap-add','NET_RAW','--memory','128m','--memory-swap','128m','--cpus','0.25','--pids-limit','32'],RAW,mode,self.attempt,peer)

    def raw_probe(self,role,network,peer,expected):
        identity=self.raw_container(role,network,'client',peer)
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            state=json.loads(docker('inspect',identity).stdout)[0]['State']
            if not state['Running']:
                assert state['ExitCode']==0,state
                result=json.loads(docker('logs',identity).stdout)
                assert result['ok']==expected and result['cap_effective']==1<<13 and result['no_new_privileges'],result
                self.evidence.setdefault('raw_ethernet_observations',[]).append({'role':role,'observation':result})
                self.save()
                return result
            time.sleep(.05)
        raise RuntimeError('trusted Ethernet diagnostic did not complete')

    def kernel_policy_cases(self):
        super().kernel_policy_cases()
        self.peer_network=next(row['network_id'] for row in self.evidence['resources'] if row['role']=='guest-net')
        peer=self.container('ethernet-peer',['--runtime','runc','--network',self.peer_network,'--user','1000:1000','--memory','128m','--memory-swap','128m','--cpus','0.25','--pids-limit','32'],TARGET,self.attempt)
        self.ready(peer)
        peer_ip=next(iter(json.loads(docker('inspect',peer).stdout)[0]['NetworkSettings']['Networks'].values()))['IPAddress']
        assert self.probe(peer,'tcp',peer_ip,19001) and self.probe(peer,'udp',peer_ip,19002)
        self.apply_config({'policies':[{'default_action':'allow','rules':[]}]})
        before=self.ethernet_packets('forward')
        assert not self.probe(self.guest,'tcp',peer_ip,19001) and not self.probe(self.guest,'udp',peer_ip,19002)
        assert self.ethernet_packets('forward')>before
        self.check('same_bridge_tcp_and_udp_remain_denied_under_user_allow_while_the_peer_is_live')
        control,_=self.network('ethernet-control-net')
        raw_control=self.raw_container('raw-control-peer',control,'server')
        control_mac=self.ready(raw_control)['mac']
        self.raw_probe('raw-control-client',control,control_mac,True)
        self.raw_peer=self.raw_container('raw-owned-peer',self.peer_network,'server')
        self.raw_peer_mac=self.ready(self.raw_peer)['mac']
        before=self.ethernet_packets('forward')
        self.raw_probe('raw-owned-client',self.peer_network,self.raw_peer_mac,False)
        assert self.ethernet_packets('forward')>=before+3
        self.check('valid_nonce_ethernet_frames_have_an_independent_positive_control_and_are_dropped_on_the_owned_bridge')
        bridge_mac=json.loads(self.exec(self.helper,'ip','-json','link','show','dev',self.bridge).stdout)[0]['address']
        before=self.ethernet_packets('input')
        self.raw_probe('raw-host-input-client',self.peer_network,bridge_mac,False)
        assert self.ethernet_packets('input')>=before+3
        self.check('non_ip_frames_to_the_owned_host_gateway_hit_the_kernel_input_drop')

    def open(self):
        if self.phase==3 and self.raw_peer is not None:
            before=self.ethernet_packets('forward')
            self.raw_probe('raw-loss-client',self.peer_network,self.raw_peer_mac,False)
            assert self.ethernet_packets('forward')>=before+3
            self.check('ethernet_floor_denies_nonce_frames_after_the_rust_controller_exits')
        reply=super().open()
        if self.phase==3 and self.raw_peer is not None:
            assert reply['result']['ethernet_guarded'],reply
            self.evidence['restart_ethernet_observation']=reply['result']
            self.save()
        return reply

    def run_unavailable(self):
        failure=None
        try:
            image=json.loads(docker('image','inspect',self.args.image).stdout)[0]
            assert image['Config']['Labels'].get('dev.goldenhoop.fixture')=='network-interop'
            self.evidence['image_id']=image['Id']
            self.evidence['docker']=json.loads(docker('version','--format','{{json .Server}}').stdout)
            self.ensure_helper()
            _,observed=self.network('guest-net','--opt','com.docker.network.bridge.name='+self.bridge)
            self.gateway=observed['IPAM']['Config'][0]['Gateway']
            RustContract.apply(self,'fixture bootstrap only')
            candidate='gh_pre_'+self.attempt
            check=self.exec(self.helper,'nft','--check','--file','-',data=f'add table bridge {candidate}\nadd chain bridge {candidate} check {{ type filter hook forward priority -300; policy accept; }}\n',check=False)
            self.evidence['independent_bridge_check']={'exit':check.returncode,'stderr':check.stderr[:4096]}
            assert check.returncode!=0 and any(e in check.stderr.lower() for e in ['not supported','no such file']),check.stderr
            assert not any(e.get('table',{}).get('name')==candidate for e in self.tables())
            refused=self.rpc('enable_ethernet',expected_revision=self.revision,error=True)
            assert refused['error']['code']=='backend_unavailable',refused
            unknown=self.rpc('inspect')['result']
            assert unknown['uncertain'] and not unknown['ethernet_guarded'],unknown
            self.evidence['unavailable_observation']=unknown
            self.check('unavailable_bridge_family_is_independently_observed_and_cannot_confirm_the_floor')
            assert self.rpc('apply',expected_revision=self.revision,config={'policies':[{'default_action':'allow','rules':[]}]},error=True)['error']['code']=='invalid_state'
            assert self.rpc('renew',expected_revision=self.revision,error=True)['error']['code']=='invalid_state'
            self.check('uncertain_ethernet_installation_cannot_allow_or_renew_any_workload_policy')
            assert not any(row['role']=='guest' for row in self.evidence['resources'])
            self.evidence['result']='passed'
        except BaseException as error:
            failure=error;self.evidence['error']=str(error) or type(error).__name__
        finally:
            try:self.cleanup();self.evidence['cleanup']='complete'
            except BaseException as error:failure=failure or error;self.evidence['cleanup_error']=str(error);self.evidence['result']='failed'
            self.save()
            print(json.dumps({key:self.evidence.get(key) for key in ('suite','result','cleanup','error','cleanup_error')}))
        if failure:raise failure

    def run(self):
        if self.args.raw_control:self.run_raw_control()
        elif self.args.expect_unavailable:self.run_unavailable()
        else:super().run()

    def run_raw_control(self):
        failure=None
        try:
            image=json.loads(docker('image','inspect',self.args.image).stdout)[0]
            assert image['Config']['Labels'].get('dev.goldenhoop.fixture')=='network-interop'
            self.evidence['image_id']=image['Id']
            self.evidence['docker']=json.loads(docker('version','--format','{{json .Server}}').stdout)
            network,_=self.network('ethernet-control-net')
            server=self.raw_container('raw-control-peer',network,'server')
            self.raw_probe('raw-control-client',network,self.ready(server)['mac'],True)
            self.check('actual_capability_bounded_raw_ethernet_nonce_echo_has_a_positive_control')
            self.evidence['result']='passed'
        except BaseException as error:
            failure=error;self.evidence['error']=str(error) or type(error).__name__
        finally:
            try:
                self.cleanup();self.evidence['cleanup']='complete'
                self.evidence['cases'][-1]='owned_raw_diagnostic_containers_and_network_confirmed_absent'
            except BaseException as error:failure=failure or error;self.evidence['cleanup_error']=str(error);self.evidence['result']='failed'
            self.save()
            print(json.dumps({key:self.evidence.get(key) for key in ('suite','result','cleanup','error','cleanup_error')}))
        if failure:raise failure


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',default='goldenhoop-network-fixture:test')
    parser.add_argument('--runtime',choices=['runc','runsc'],default='runc')
    parser.add_argument('--output',required=True)
    parser.add_argument('--remove-image',action='store_true')
    parser.add_argument('--receiver-publication',choices=['loopback','routed'],default='loopback')
    parser.add_argument('--resolver-path',choices=['auto','embedded','owned'],default='owned')
    parser.add_argument('--ci-host-diagnostics',action='store_true')
    mode=parser.add_mutually_exclusive_group()
    mode.add_argument('--expect-unavailable',action='store_true')
    mode.add_argument('--raw-control',action='store_true')
    args=parser.parse_args()
    if args.ci_host_diagnostics and os.environ.get('GITHUB_ACTIONS')!='true':parser.error('ephemeral CI only')
    if (args.raw_control or args.expect_unavailable) and args.runtime!='runc':parser.error('diagnostic modes do not launch a gVisor workload')
    EthernetContract(args).run()
