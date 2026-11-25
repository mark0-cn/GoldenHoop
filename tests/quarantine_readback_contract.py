"""Actual owned inet deny-table readback; no source, policy, lease or Ready claim."""
import argparse
import copy
import hashlib
import json
import subprocess
import uuid
from pathlib import Path
from network_provider_contract import Contract as ProviderContract

NATIVE = r'''
import json,pathlib,subprocess,sys,uuid
data=json.loads(sys.argv[1]);action=sys.argv[2];a=data['allocation'];generation=uuid.UUID(a['generation']).hex
assert a['bridge']=='ghn'+generation[:12]
table='gh_e_'+generation;owner=data['owner']
assert owner.startswith('goldenhoop_') and len(owner)==75
def nft(*args,input=None):
 p=subprocess.run(['nft',*args],input=input,capture_output=True,text=True,timeout=8)
 assert p.returncode==0,p.stderr
 return json.loads(p.stdout) if p.stdout.strip() else None
tables=nft('--json','list','tables')['nftables'];exists=any(row.get('table',{}).get('name')==table for row in tables)
if action=='install':
 assert not exists
 bridge=pathlib.Path('/sys/class/net')/a['bridge'];assert int((bridge/'ifindex').read_text())==a['ifindex'] and (bridge/'bridge').is_dir()
 nft('--file','-',input=data['script'])
 print(json.dumps(nft('--json','--numeric','list','table','inet',table)))
elif action=='collect':
 if exists:
  value=nft('--json','list','table','inet',table)
  chains=[row['chain']['name'] for row in value['nftables'] if 'chain' in row]
  assert owner in chains and 'revision_1' in chains
  nft('delete','table','inet',table)
 assert not any(row.get('table',{}).get('name')==table for row in nft('--json','list','tables')['nftables'])
 print(json.dumps({'owned_table_absent':True}))
else:raise RuntimeError('invalid native action')
'''


class Contract(ProviderContract):
    def helper(self, data, action):
        name='goldenhoop-quarantine-audit-'+uuid.uuid4().hex[:12]
        return json.loads(self.docker('run','--rm','--name',name,
            '--label','dev.goldenhoop.installation='+self.installation,'--label','dev.goldenhoop.role=network-provider-audit',
            '--label','dev.goldenhoop.test=network-provider','--label','dev.goldenhoop.attempt='+self.attempt,
            '--runtime','runc','--network','host','--user','0:0','--cap-drop','ALL','--cap-add','NET_ADMIN',
            '--security-opt','no-new-privileges:true','--read-only','--no-healthcheck','--memory','128m','--memory-swap','128m',
            '--cpus','0.25','--pids-limit','32','--entrypoint','python3',self.report['fixture_image_id'],
            '-B','-c',NATIVE,json.dumps(data),action).stdout)

    def readback(self, data, check=True):
        result=subprocess.run([self.args.readback_binary],input=json.dumps(data),capture_output=True,text=True,encoding='utf-8',timeout=10)
        self.report.setdefault('readback_invocations',[]).append({'input':data,'exit_code':result.returncode,'stdout':result.stdout,'stderr':result.stderr})
        self.save()
        if check:assert result.returncode==0,result.stderr
        return result

    def run(self):
        failure=None;data=None
        self.report.update(suite='actual-owned-quarantine-readback',scope='Actual inet quarantine on an owned bridge, exact Rust semantic readback and refusal of weakened rules. No Ethernet/source composition or workload readiness.')
        for path in [Path(__file__),Path('crates/egress/examples/quarantine_readback.rs')]:
            self.report['source_files_sha256'][path.relative_to(self.root).as_posix() if path.is_absolute() else path.as_posix()]=hashlib.sha256(path.read_bytes()).hexdigest()
        try:
            fixture=json.loads(self.docker('image','inspect',self.args.image).stdout)[0]
            assert fixture['Config']['Labels']['dev.goldenhoop.fixture']=='network-interop'
            self.report['fixture_image_id']=fixture['Id']
            self.invoke('init','--fault-after-create',expected=75);self.settled=True
            provider=self.invoke('recover')['provider'];observed=self.audit()
            assert observed['bridge_exists'] and not observed['owned_tables']
            allocation={key:self.plan['identity'][key] for key in ['installation_id','sandbox_id','generation']}
            allocation.update(bridge=observed['bridge'],ifindex=observed['ifindex'])
            request={'allocation':allocation,'revision':1,'dns':[{'address':provider['ipv4_gateway'],'port':40101},{'address':provider['ipv6_gateway'],'port':40102}]}
            generated=json.loads(self.readback(request).stdout)
            owner='goldenhoop_'+hashlib.sha256(json.dumps(allocation,separators=(',',':')).encode()).hexdigest()
            # Allocation's Rust field order is installation/sandbox/generation/bridge/ifindex.
            data={'allocation':allocation,'script':generated['script'],'owner':owner}
            native=self.helper(data,'install');request['native']=native
            self.report['actual_native_table']=native;self.save()
            assert json.loads(self.readback(request).stdout)=={'verified':True}
            self.check('the_actual_owned_dual_stack_inet_quarantine_passes_exact_Rust_readback')
            request['native']=copy.deepcopy(native)
            for row in request['native']['nftables']:
                if row.get('rule',{}).get('chain')=='guard':row['rule']['expr']=[{'accept':None}];break
            assert self.readback(request,check=False).returncode!=0
            self.check('an_actual_table_snapshot_with_a_weakened_guard_is_refused')
            if self.args.kernel_fixture:
                request['native']=native
                self.readback(request)
                output=Path(self.args.kernel_fixture);output.parent.mkdir(parents=True,exist_ok=True)
                output.write_text(json.dumps(request,indent=2)+'\n',encoding='utf-8',newline='\n')
                self.report['captured_kernel_fixture']={'path':output.as_posix(),'sha256':hashlib.sha256(output.read_bytes()).hexdigest()}
            self.report['result']='passed'
        except BaseException as error:
            failure=error;self.report.update(result='failed',error=repr(error));self.failure_observation()
        finally:
            try:
                if data:self.report['native_collection']=self.helper(data,'collect')
                self.cleanup();self.report['cleanup']='complete'
            except BaseException as error:
                failure=failure or error;self.report.update(result='failed',cleanup='unknown',cleanup_error=repr(error))
            self.save()
        if failure:raise failure


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--binary',required=True);parser.add_argument('--readback-binary',required=True)
    parser.add_argument('--image',default='goldenhoop-network-fixture:test');parser.add_argument('--agent-image',default='goldenhoop-agent:test')
    parser.add_argument('--work-dir',default='.test-work');parser.add_argument('--output',required=True)
    parser.add_argument('--kernel-fixture');parser.add_argument('--remove-image',action='store_true')
    Contract(parser.parse_args()).run()
