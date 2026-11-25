"""Actual native policy readback in an owned private network namespace; no Ready."""
import argparse
import hashlib
import json
import subprocess
import uuid
from datetime import datetime,timezone
from pathlib import Path
from policy_readback_samples import MANAGER


class Contract:
    def __init__(self,args):
        self.args=args;self.attempt=uuid.uuid4().hex;self.container=None;self.creation_pending=False;self.creator_settled=True;self.container_name=None;self.image_id=None
        self.report={'timestamp':datetime.now(timezone.utc).isoformat(),'suite':'native-effective-policy-readback','scope':'Actual inet rules in a disposable none-network namespace. This verifies policy structure, not host source/destination floors, packet delivery or workload Ready.','attempt':self.attempt,'result':'failed','cleanup':'unknown','cases':[],'observations':[]}
        paths=[Path(__file__),Path(__file__).with_name('policy_readback_samples.py'),Path('Cargo.toml'),Path('Cargo.lock'),Path('tests/fixtures/network.Dockerfile'),*Path('crates/egress').rglob('*.rs'),Path('crates/egress/Cargo.toml')]
        repository=Path(__file__).resolve().parents[1]
        self.report['source_files_sha256']={p.resolve().relative_to(repository).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
        self.report['binary_sha256']=hashlib.sha256(Path(args.binary).read_bytes()).hexdigest()

    def call(self,command,*,input=None,check=True,timeout=30):
        p=subprocess.run(command,input=input.encode('utf-8') if isinstance(input,str) else input,capture_output=True,timeout=timeout)
        p.stdout=p.stdout.decode('utf-8',errors='replace');p.stderr=p.stderr.decode('utf-8',errors='replace')
        if check:assert p.returncode==0,(command,p.stderr)
        return p

    def docker(self,*args,**kwargs):return self.call(['docker',*args],**kwargs)
    def native(self,*args,**kwargs):return self.docker('exec','--interactive',self.container,*args,**kwargs)
    def compile(self,value):return json.loads(self.call([self.args.binary],input=json.dumps(value)).stdout)
    def verify(self,value,native,*,refused=False):
        p=self.call([self.args.binary],input=json.dumps({**value,'native':native}),check=False)
        assert (p.returncode!=0)==refused,(refused,p.stdout,p.stderr)
        if not refused:assert json.loads(p.stdout)=={'verified_structure':True,'ready':False}
        return {'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
    def save(self):
        p=Path(self.args.output);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(self.report,indent=2)+'\n',encoding='utf-8',newline='\n')

    def run(self):
        failure=None
        try:
            image=json.loads(self.docker('image','inspect',self.args.image).stdout)[0];assert image['Config']['Labels']['dev.goldenhoop.fixture']=='network-interop';self.report['fixture_image_id']=image['Id']
            name='goldenhoop-policy-readback-'+self.attempt[:12]
            self.container_name=name;self.image_id=image['Id'];self.creation_pending=True;self.creator_settled=False;self.report['creation_intent']={'name':name,'image_id':image['Id']};self.save()
            self.container=self.docker('run','--detach','--name',name,'--label','dev.goldenhoop.test=policy-readback','--label','dev.goldenhoop.attempt='+self.attempt,'--network','none','--runtime','runc','--user','0:0','--read-only','--cap-drop','ALL','--cap-add','NET_ADMIN','--security-opt','no-new-privileges','--memory','128m','--memory-swap','128m','--cpus','0.25','--pids-limit','32','--entrypoint','/bin/sleep',image['Id'],'600').stdout.strip()
            assert len(self.container)==64 and all(c in '0123456789abcdef' for c in self.container);self.creation_pending=False;self.creator_settled=True;self.report['container_id']=self.container;self.save()
            actual=json.loads(self.docker('inspect',self.container).stdout)[0];self.report['actual_container']=actual;self.save()
            assert actual['HostConfig']['NetworkMode']=='none' and not actual['Mounts'] and actual['HostConfig']['ReadonlyRootfs'] and actual['HostConfig']['CapAdd'] in (['NET_ADMIN'],['CAP_NET_ADMIN'])
            generation=str(uuid.uuid4());bridge='ghn'+generation.replace('-','')[:12]
            self.native('ip','link','add',bridge,'type','bridge');self.native('ip','addr','add','192.0.2.1/24','dev',bridge);self.native('ip','addr','add','fd42::1/64','dev',bridge);self.native('ip','link','set',bridge,'up')
            link=json.loads(self.native('ip','--json','link','show','dev',bridge).stdout)[0]
            allocation={'installation_id':str(uuid.uuid4()),'sandbox_id':str(uuid.uuid4()),'generation':generation,'bridge':bridge,'ifindex':link['ifindex']};self.report['allocation']=allocation
            basic={'policies':[{'default_action':'deny','rules':[{'destination':'192.0.2.2','ports':[443],'action':'allow'},{'destination':'198.51.100.0/24','ports':[80,443],'action':'deny'},{'destination':'2001:db8::/32','ports':[],'action':'allow'}]},{'default_action':'allow','rules':[{'destination':'*','ports':[25],'action':'deny'}]}],'deny_always':[{'destination':'203.0.113.0/24','ports':[],'action':'deny'}],'allow_always':[{'destination':'203.0.114.4','ports':[8443],'action':'allow'}],'tcp_cap':[443,8443]}
            for mode in ['static','dns','deny-only']:
                config=json.loads(json.dumps(basic)) if mode!='deny-only' else {'policies':[{'default_action':'deny','rules':[]}]}
                value={'allocation':allocation,'revision':3,'config':config,'dns_enabled':mode=='dns','dns':[{'address':'192.0.2.1','port':40101},{'address':'fd42::1','port':40102}] if mode=='dns' else []}
                if mode=='dns':config['policies'][0]['rules'].append({'destination':'*.example.test','ports':[],'action':'allow'})
                script=self.compile(value)['script'];self.native('nft','--file','-',input=script)
                native=json.loads(self.native('nft','--json','--numeric','list','table','inet','gh_e_'+uuid.UUID(allocation['generation']).hex).stdout)
                text=self.native('nft','list','table','inet','gh_e_'+uuid.UUID(allocation['generation']).hex).stdout
                self.report['observations'].append({'mode':mode,'input':value,'script':script,'native':native,'native_text':text});self.save()
                accepted=self.verify(value,native);self.report['observations'][-1]['readback']=accepted
                self.report['cases'].append(mode+'_actual_full_structure_readback');print('passed',self.report['cases'][-1],flush=True)
                if mode=='dns':
                    token=uuid.uuid4();staged={**value,'dns_token':str(token)};script=self.compile(staged)['script'];self.native('nft','--file','-',input=script)
                    table='gh_e_'+uuid.UUID(allocation['generation']).hex
                    self.native('nft','--file','-',input='add element inet '+table+' d_'+token.hex+'_u4 { 192.0.2.2 timeout 5s }\nadd element inet '+table+' d_'+token.hex+'_o6 { 2001:db8::2 timeout 5s }\n')
                    native=json.loads(self.native('nft','--json','--numeric','list','table','inet',table).stdout);text=self.native('nft','list','table','inet',table).stdout
                    self.report['observations'].append({'mode':'staged-dns','input':staged,'script':script,'native':native,'native_text':text});self.save();self.report['observations'][-1]['readback']=self.verify(staged,native)
                    self.report['cases'].append('actual_staged_DNS_references_and_timed_elements_match_the_effective_policy');print('passed',self.report['cases'][-1],flush=True)
                    self.native('nft','--file','-',input='flush chain inet '+table+' decision\nadd rule inet '+table+' decision counter accept\n')
                    weakened=json.loads(self.native('nft','--json','--numeric','list','table','inet',table).stdout)
                    live=next(row['set'] for row in weakened['nftables'] if row.get('set',{}).get('name')=='live');assert live['elem'][0]['elem']['expires']>=1
                    self.report['actual_weakened_native_policy']={'native':weakened,'readback':self.verify(staged,weakened,refused=True)}
                    self.report['cases'].append('actual_weakened_policy_is_refused_despite_unchanged_owner_revision_and_live_lease');print('passed',self.report['cases'][-1],flush=True)
                self.native('nft','delete','table','inet','gh_e_'+uuid.UUID(allocation['generation']).hex)
            native={'allocation':allocation,'identity':{k:allocation[k] for k in ['installation_id','sandbox_id','generation']},'provisioning_token':str(uuid.uuid4()),'expires_at':datetime.now(timezone.utc).isoformat()};native['identity']['profile']='local-runc-dev'
            produced=self.native('python3','-B','-c',MANAGER,json.dumps({'allocation':allocation,'native_plan':native,'config':basic}),timeout=60)
            self.report['actual_production_manager']=json.loads(produced.stdout);assert self.report['actual_production_manager']['controller_exit_code']==0 and not self.report['actual_production_manager']['ready']
            self.report['cases'].extend(['actual_production_apply_renew_tamper_and_expired_lease_fences','actual_original_lifetime_clips_kernel_timeout_and_refuses_later_dispatch']);print('passed actual production manager policy and lease readbacks',flush=True)
            self.report['result']='passed'
        except BaseException as error:failure=error;self.report['error']=repr(error)
        finally:
            try:
                for identity in self.docker('ps','-aq','--no-trunc','--filter','label=dev.goldenhoop.attempt='+self.attempt).stdout.split():
                    actual=json.loads(self.docker('inspect',identity).stdout)[0];assert actual['Config']['Labels']['dev.goldenhoop.test']=='policy-readback' and actual['Config']['Labels']['dev.goldenhoop.attempt']==self.attempt and actual['Name']=='/'+self.container_name and actual['Image']==self.image_id and actual['HostConfig']['NetworkMode']=='none' and not actual['Mounts']
                    if self.creation_pending:self.container=identity;self.creator_settled=True
                    self.docker('rm','--force',identity);missing=self.docker('inspect',identity,check=False);assert missing.returncode and 'no such object' in missing.stderr.lower()
                if not self.creator_settled:raise RuntimeError('unacknowledged creator without a positively observed physical identity remains unknown')
                if self.container:
                    missing=self.docker('inspect',self.container,check=False);assert missing.returncode and 'no such object' in missing.stderr.lower()
                assert not self.docker('ps','-aq','--filter','label=dev.goldenhoop.attempt='+self.attempt).stdout.strip();self.report['creator_settled']=self.creator_settled;self.report['cleanup']='complete'
            except BaseException as error:failure=failure or error;self.report['cleanup_error']=repr(error)
            self.save();print(json.dumps({k:self.report.get(k) for k in ['result','cleanup','error','cleanup_error']}),flush=True)
        if failure:raise failure


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',required=True);p.add_argument('--image',default='goldenhoop-network-fixture:test');p.add_argument('--output',required=True);Contract(p.parse_args()).run()
