"""Actual workload IPv4 DNS frontend and transparent redirect boundary."""
import argparse
import hashlib
import json
import os
from pathlib import Path,PurePosixPath

from dns_contract import DnsContract,question
from frontend_samples import CLIENT,MALFORMED_CLIENT,SYSTEM_RESOLVER
from network_contract import docker


class FrontendContract(DnsContract):
    def __init__(self,args):
        super().__init__(args)
        self.binding=None
        self.dns_target=None
        requested=getattr(args,'resolver_path','auto')
        self.resolver_path=('owned' if args.runtime=='runsc' else 'embedded') if requested=='auto' else requested
        if args.runtime=='runsc' and self.resolver_path!='owned':raise ValueError('isolated runsc requires an owned reachable resolver configuration')
        self.resolver_volume=None
        self.resolver_source=None
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
        if role=='guest':
            options=[*options,'--dns',self.gateway]
            if self.resolver_path=='owned':
                self.prepare_resolver()
                options.extend(['--mount',f'type=volume,source={self.resolver_volume},target=/etc/resolv.conf,volume-subpath=resolv.conf,volume-nocopy,readonly'])
        identity=super().container(role,options,script,*args)
        if role=='guest' and self.resolver_path=='owned':
            configured=[m for m in json.loads(docker('inspect',identity).stdout)[0]['HostConfig']['Mounts'] if m['Target']=='/etc/resolv.conf']
            assert len(configured)==1 and configured[0]['Type']=='volume' and configured[0]['Source']==self.resolver_volume and configured[0]['ReadOnly'],configured
            assert configured[0]['VolumeOptions']['Subpath']=='resolv.conf' and configured[0]['VolumeOptions']['NoCopy'],configured
            self.evidence['owned_resolver_configuration']['observed_mount']=configured[0]
            self.save()
        if role=='dns-target':self.dns_target=identity
        return identity

    def validate_mounts(self,role,mounts):
        if role!='guest' or self.resolver_path!='owned':return super().validate_mounts(role,mounts)
        configuration=[m for m in mounts if m['Destination']=='/etc/resolv.conf']
        assert len(configuration)==1,mounts
        configured=configuration[0]
        assert configured['Type']=='volume' and configured['Name']==self.resolver_volume and not configured['RW'],configured
        super().validate_mounts(role,[m for m in mounts if m is not configured])

    def prepare_resolver(self):
        assert self.resolver_volume is None
        name='goldenhoop-network-'+self.attempt+'-dns-config'
        assert not docker('volume','ls','--filter','name='+name,'--format','{{.Name}}').stdout.strip()
        self.resolver_volume=docker('volume','create',*self.labels('dns-config'),name).stdout.strip()
        assert self.resolver_volume==name
        observed=json.loads(docker('volume','inspect',name).stdout)[0];self.owned(observed)
        source=PurePosixPath(observed['Mountpoint'])
        assert source.is_absolute() and source.name=='_data' and source.parent.name==name,observed
        self.resolver_source=str(source/'resolv.conf')
        self.evidence['resources'].append({'role':'dns-config','volume_name':name})
        self.save()
        config='nameserver '+self.gateway+'\noptions timeout:1 attempts:1\n'
        writer="import hashlib,json,os,sys;from pathlib import Path;data=sys.argv[1].encode('ascii');fd=os.open('/config/resolv.conf',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o444);os.write(fd,data);os.fsync(fd);os.close(fd);stored=Path('/config/resolv.conf').read_bytes();print(json.dumps({'sha256':hashlib.sha256(stored).hexdigest(),'bytes':len(stored)}))"
        result=docker('run','--rm','--name',name+'-writer',*self.labels('dns-config-writer'),'--runtime','runc','--network','none','--user','0:0','--cap-drop','ALL','--security-opt','no-new-privileges:true','--read-only','--memory','128m','--memory-swap','128m','--cpus','0.25','--pids-limit','32','--mount','type=volume,source='+name+',target=/config','--entrypoint','python3',self.args.image,'-c',writer,config)
        written=json.loads(result.stdout);assert written['sha256']==hashlib.sha256(config.encode()).hexdigest()
        self.evidence['owned_resolver_configuration']={'volume':name,'contents':config,'source':self.resolver_source,'sha256':written['sha256'],'mounted_readonly':True,'configured_before_workload_start':True}
        self.save()

    def cleanup(self):
        try:super().cleanup()
        finally:
            for name in docker('volume','ls','--filter','label=dev.goldenhoop.attempt='+self.attempt,'--format','{{.Name}}').stdout.split():
                observed=json.loads(docker('volume','inspect',name).stdout)[0];self.owned(observed)
                assert name==self.resolver_volume
                docker('volume','rm',name)
            assert not docker('volume','ls','--filter','label=dev.goldenhoop.attempt='+self.attempt,'--format','{{.Name}}').stdout.strip()
            self.evidence['owned_resolver_volume_absent']=True

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
        resolver='127.0.0.11' if self.resolver_path=='embedded' else self.gateway
        assert [line.split()[1] for line in resolv.splitlines() if line.startswith('nameserver ')]==[resolver],resolv
        self.evidence['workload_resolver_configuration']={'path':self.resolver_path,'dns':observed['HostConfig']['Dns'],'resolv_conf':resolv}
        self.dns_probe(self.guest,'udp',resolver,53,'system.test',0)
        denied=self.dns_probe(self.guest,'udp',resolver,53,'denied.test')
        assert denied['ok'] and denied['rcode'] in (2,5) and not denied['addresses'],denied
        system=json.loads(self.exec(self.guest,'python3','-c',SYSTEM_RESOLVER,'system.test').stdout)
        assert system['ok'] and system['addresses']==[self.target_ip],system
        if self.resolver_path=='owned':assert system['resolver_readonly'],system
        self.evidence['libc_resolver_observation']=system
        self.save()
        assert not any(row['query']=='denied.test' for row in self.queries(self.dns_target))
        self.check(('docker_embedded_dns' if self.resolver_path=='embedded' else 'readonly_owned_resolver')+'_uses_the_policy_resolver_and_libc_without_public_fallback')
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
    parser.add_argument('--resolver-path',choices=['auto','embedded','owned'],default='auto')
    parser.add_argument('--ci-host-diagnostics',action='store_true')
    args=parser.parse_args()
    if args.ci_host_diagnostics and os.environ.get('GITHUB_ACTIONS')!='true':parser.error('ephemeral CI only')
    FrontendContract(args).run()
