"""Actual workload IPv4 DNS frontend and transparent redirect boundary."""
import argparse
import hashlib
import json
import os
from pathlib import Path

from dns_contract import DnsContract,question
from frontend_samples import CLIENT,MALFORMED_CLIENT
from network_contract import docker


class FrontendContract(DnsContract):
    def __init__(self,args):
        super().__init__(args)
        self.binding=None
        self.dns_target=None
        self.evidence['suite']='rust-workload-ipv4-dns'
        self.evidence['scope']='actual workload IPv4 DNS and private grant path; IPv6/L2/metadata/credentials/API integration incomplete'
        root=Path(__file__).resolve().parents[1]
        for p in [Path(__file__).resolve(),root/'tests/frontend_samples.py']:
            self.evidence['source_files_sha256'][p.relative_to(root).as_posix()]=hashlib.sha256(p.read_bytes()).hexdigest()
        self.save()

    def rpc(self,operation,error=False,**fields):
        response=super().rpc(operation,error=error,**fields)
        if operation=='enable_dns' and not error:
            listening=super().rpc('listen_dns',expected_revision=self.revision)['result']
            self.binding=listening['binding']
            assert self.binding['address']==self.gateway and self.binding['port']>=1024
            self.evidence['owned_dns_listener']=listening
            self.save()
        return response

    def container(self,role,options,script,*args):
        if role=='guest':options=[*options,'--dns',self.gateway]
        identity=super().container(role,options,script,*args)
        if role=='dns-target':self.dns_target=identity
        return identity

    def dns_probe(self,container,mode,address,port,name,expected=None):
        reply=json.loads(self.exec(container,'python3','-c',CLIENT,mode,address,str(port),json.dumps(question(name))).stdout)
        self.evidence.setdefault('workload_dns_observations',[]).append({'container_role':'guest' if container==self.guest else 'other-bridge','mode':mode,'address':address,'port':port,'name':name,'reply':reply})
        self.save()
        if expected is not None:
            assert reply['ok'] and reply['rcode']==expected,reply
            if expected==0:assert self.target_ip in reply['addresses'],reply
            else:assert not reply['addresses'] and reply['answers']==0,reply
        return reply

    def kernel_policy_cases(self):
        super().kernel_policy_cases()
        config={'policies':[{'default_action':'deny','rules':[{'destination':'*.test','ports':[],'action':'allow'},{'destination':'denied.test','ports':[],'action':'deny'}]}]}
        self.apply_config(config)
        self.rpc('renew',expected_revision=self.revision)
        assert not self.probe(self.guest,'tcp',self.target_ip,19001)
        self.dns_probe(self.guest,'udp',self.gateway,self.binding['port'],'listener.test',0)
        assert self.probe(self.guest,'tcp',self.target_ip,19001)
        self.check('workload_dns_listener_is_on_the_verified_gateway_and_grants_real_packets')
        self.rpc('renew',expected_revision=self.revision)
        self.dns_probe(self.guest,'udp','198.51.100.53',53,'redirect-udp.test',0)
        self.dns_probe(self.guest,'tcp','198.51.100.53',53,'redirect-tcp.test',0)
        self.check('arbitrary_ipv4_udp_and_tcp_dns_destinations_are_transparently_intercepted')
        queries=self.queries(self.dns_target)
        self.dns_probe(self.guest,'udp','198.51.100.53',53,'denied.test',5)
        self.dns_probe(self.guest,'tcp','198.51.100.53',53,'denied.test',5)
        assert self.queries(self.dns_target)==queries
        self.check('workload_denied_names_return_address_free_refused_without_upstream_queries')
        self.rpc('renew',expected_revision=self.revision)
        observed=json.loads(docker('inspect',self.guest).stdout)[0]
        assert observed['HostConfig']['Dns']==[self.gateway]
        resolv=self.exec(self.guest,'cat','/etc/resolv.conf').stdout
        assert 'nameserver 127.0.0.11' in resolv
        self.evidence['embedded_resolver_configuration']={'dns':observed['HostConfig']['Dns'],'resolv_conf':resolv}
        self.dns_probe(self.guest,'udp','127.0.0.11',53,'embedded.test',0)
        denied=self.dns_probe(self.guest,'udp','127.0.0.11',53,'denied.test')
        assert denied['ok'] and denied['rcode'] in (2,5) and not denied['addresses'],denied
        assert not any(row['query']=='denied.test' for row in self.queries(self.dns_target))
        self.check('docker_embedded_dns_uses_the_owned_policy_resolver_without_public_fallback')
        queries=self.queries(self.dns_target)
        other=self.dns_probe(self.dns_target,'udp',self.gateway,self.binding['port'],'foreign.test')
        assert not other['ok'],other
        assert self.queries(self.dns_target)==queries
        self.rpc('renew',expected_revision=self.revision)
        self.dns_probe(self.guest,'udp',self.gateway,self.binding['port'],'same-bridge.test',0)
        self.check('a_different_bridge_cannot_borrow_the_listener_identity')
        self.malformed_cases()
        self.partial_control_frame()

    def malformed_cases(self):
        self.rpc('renew',expected_revision=self.revision)
        queries=self.queries(self.dns_target)
        valid=bytes(question('malformed.test'))
        invalid_count=valid[:4]+b'\xff\xff'+valid[6:]
        oversized=valid+bytes(4097-len(valid))
        for mode,wire,rcode in [('udp',invalid_count,1),('udp',oversized,2),('partial',valid,None),('oversized',valid,None),('short',valid,None)]:
            reply=json.loads(self.exec(self.guest,'python3','-c',MALFORMED_CLIENT,mode,self.gateway,str(self.binding['port']),json.dumps(list(wire))).stdout)
            self.evidence.setdefault('malformed_workload_dns_observations',[]).append({'mode':mode,'wire_length':len(wire),'reply':reply})
            self.save()
            assert reply['ok'],reply
            if rcode is None:assert reply['closed_without_answer'],reply
            else:assert reply['rcode']==rcode and reply['counts']==[0,0,0,0] and reply['length']==12,reply
        assert self.queries(self.dns_target)==queries
        self.check('malformed_oversized_and_truncated_workload_dns_never_reaches_upstream_or_grants_an_answer')

    def partial_control_frame(self):
        self.rpc('renew',expected_revision=self.revision)
        self.controller.sequence+=1
        sequence=self.controller.sequence
        frame=json.dumps({'id':sequence,'command':{'operation':'renew','expected_revision':self.revision}})
        split=len(frame)//2
        self.controller.process.stdin.write(frame[:split]);self.controller.process.stdin.flush()
        self.dns_probe(self.guest,'udp',self.gateway,self.binding['port'],'partial-frame.test',0)
        self.controller.process.stdin.write(frame[split:]+'\n');self.controller.process.stdin.flush()
        response=json.loads(self.controller.rows.get(timeout=12))
        assert response['id']==sequence and not response['result']['uncertain'] and response['result']['revision']==self.revision,response
        self.check('dns_activity_does_not_discard_or_expand_a_partial_control_frame')


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
    FrontendContract(args).run()
