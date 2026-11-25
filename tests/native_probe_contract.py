"""Actual pre-native process loss and production worker cleanup without fake indices."""
import argparse
import hashlib
import json
import subprocess
import time
import uuid
from datetime import datetime,timezone
from pathlib import Path
from guarded_bootstrap_contract import Contract as GuardedContract
from network_provider_contract import Contract as ProviderContract

MARKER=r'''
import json,subprocess,sys,uuid
plan=json.loads(sys.argv[1]);marker=sys.argv[2];action=sys.argv[3]
generation=uuid.UUID(plan['identity']['generation']).hex;table='gh_e_'+generation
assert marker=='probe_test_'+sys.argv[4] and len(sys.argv[4])==32 and all(c in '0123456789abcdef' for c in sys.argv[4])
def nft(*args,input=None):
 p=subprocess.run(['nft',*args],input=input,capture_output=True,text=True,timeout=8);assert p.returncode==0,p.stderr
 return json.loads(p.stdout) if p.stdout.strip() else None
exists=any(row.get('table',{}).get('name')==table for row in nft('--json','list','tables')['nftables'])
if action=='create':
 assert not exists;nft('--file','-',input='add table inet '+table+'\nadd chain inet '+table+' '+marker+'\n');exists=True
if exists:
 native=nft('--json','list','table','inet',table);chains=[row['chain']['name'] for row in native['nftables'] if 'chain' in row];assert chains==[marker]
else:native=None
if action=='remove' and exists:nft('delete','table','inet',table);exists=False
print(json.dumps({'present':exists,'owned_table':native}))
'''


class Contract(GuardedContract):
    def __init__(self,args):
        super().__init__(args);self.probe_generation=str(uuid.uuid4());self.marker_attempted=False
        self.report['suite']='production-worker-pre-native-probe-recovery'
        self.report['scope']='Actual probe reservation/create/start producer-loss, zero-capability discovery, and production worker read-only native absence without a positive native checkpoint. No workload, lease or Ready.'
        path=Path(__file__);self.report['source_files_sha256'][path.relative_to(self.root).as_posix()]=hashlib.sha256(path.read_bytes()).hexdigest()

    def invoke(self,action,*extra,expected=0):
        if action.startswith('probe-'):
            extra=('--probe-generation',self.probe_generation,*extra)
            if action in ('probe-reserve','probe-create'):extra=('--controller-image',self.controller_image_id,*extra)
        try:return super().invoke(action,*extra,expected=expected)
        except BaseException:
            if action.startswith('probe-') and self.report['invocations'][-1]['timed_out']:self.creation_uncertain=True;self.settled=False
            raise

    def marker(self,action):
        result=self.docker('run','--rm','--name','goldenhoop-probe-marker-'+uuid.uuid4().hex[:12],
            '--label','dev.goldenhoop.installation='+self.installation,'--label','dev.goldenhoop.role=network-provider-audit',
            '--label','dev.goldenhoop.test=network-provider','--label','dev.goldenhoop.attempt='+self.attempt,
            '--runtime','runc','--network','host','--user','0:0','--cap-drop','ALL','--cap-add','NET_ADMIN',
            '--security-opt','no-new-privileges:true','--read-only','--memory','128m','--memory-swap','128m','--cpus','0.25','--pids-limit','32',
            '--entrypoint','python3',self.report['fixture_image_id'],'-B','-c',MARKER,json.dumps(self.plan),'probe_test_'+self.attempt,action,self.attempt)
        value=json.loads(result.stdout);self.report.setdefault('marker_observations',[]).append({'action':action,'observation':value});self.save();return value

    def cleanup(self):
        if self.marker_attempted:self.marker('remove')
        return super().cleanup()

    def run(self):
        failure=None
        try:
            fixture=json.loads(self.docker('image','inspect',self.args.image).stdout)[0];assert fixture['Config']['Labels']['dev.goldenhoop.fixture']=='network-interop'
            self.report['fixture_image_id']=fixture['Id']
            controller=json.loads(self.docker('image','inspect',self.args.controller_image).stdout)[0];assert controller['Config']['Labels']['dev.goldenhoop.egress']=='host-netfilter'
            self.controller_image_id=controller['Id'];self.report['controller_image_id']=controller['Id']
            self.invoke('init','--fault-after-create',expected=75);self.settled=True
            self.invoke('recover');before=self.audit();assert before['bridge_exists'] and not before['owned_tables']
            if self.args.mode in ('reserve','table-blocked'):
                self.invoke('probe-reserve')
            else:
                self.invoke('probe-create',*(['--fault-after-probe-create'] if self.args.mode=='create-loss' else []),expected=83 if self.args.mode=='create-loss' else 0)
                if self.args.mode=='start-loss':self.invoke('probe-run','--fault-after-probe-start',expected=84)
            records=self.records();record=next(row for row in records['controllers'] if row['controller_generation']==self.probe_generation)
            assert not records['network'].get('native') and not records['network'].get('binding') and 'native' not in record['plan']
            expected={'reserve':'reserved','table-blocked':'reserved','create-loss':'creating','start-loss':'starting'}[self.args.mode]
            assert record['phase']==expected and record['plan']['purpose']=='discover'
            self.report['interrupted_probe_checkpoint']=record;self.check('the_original_file_database_retains_the_exact_pre_native_dispatch_phase_without_a_synthetic_index')
            physical=None
            if self.args.mode in ('create-loss','start-loss'):
                created=next(frame['actual_probe_created'] for invocation in self.report['invocations'] for frame in invocation['frames'] if 'actual_probe_created' in frame)
                physical=created['container_id'];actual=json.loads(self.docker('inspect',physical).stdout)[0];self.owned(actual)
                assert actual['Config']['User']=='1000:1000' and actual['HostConfig']['CapDrop']==['ALL'] and not actual['HostConfig'].get('CapAdd') and not actual['Mounts']
                assert actual['HostConfig']['ReadonlyRootfs'] and actual['HostConfig']['NetworkMode']=='host' and not actual['Config'].get('Healthcheck')
                self.report['actual_interrupted_probe']=actual
                if self.args.mode=='create-loss':assert actual['State']['Status']=='created' and record['container_id'] is None and record['start_token'] is None
                else:
                    deadline=time.monotonic()+10
                    while actual['State']['Status']!='exited' and time.monotonic()<deadline:
                        time.sleep(0.05);actual=json.loads(self.docker('inspect',physical).stdout)[0]
                    assert actual['State']['Status']=='exited' and actual['State']['ExitCode']==0
                    observed=json.loads(self.docker('logs',physical).stdout);assert observed['observation']=='native' and observed['value']['allocation']['ifindex']==before['ifindex']
                    self.report['actual_uncommitted_native_observation']=observed
                self.check('independent_Docker_and_process_observations_preserve_the_zero_capability_original_probe_identity')
            if self.args.mode=='table-blocked':
                self.marker_attempted=True;assert self.marker('create')['present']
                # Start the same production worker; observe its negative read
                # before removing this test-owned marker to permit collection.
                self.log_handle=self.worker_log.open('ab')
                command=[self.args.worker_binary,'--database',str(self.database),'worker','--agent-image',self.args.agent_image,'--allow-runc-development','--egress-controller-image',self.controller_image_id]
                self.worker=subprocess.Popen(command,stdout=self.log_handle,stderr=subprocess.STDOUT,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0));self.report['worker_command']=command
                deadline=time.monotonic()+100
                while True:
                    assert self.worker.poll() is None
                    current=self.records()
                    attempts=[row for row in current['controllers'] if row['plan'].get('purpose')=='observe_absence' and row['phase']=='collected']
                    if attempts:break
                    if time.monotonic()>deadline:raise RuntimeError('production worker did not observe the occupied table scope')
                    time.sleep(0.1)
                assert current['network']['phase']=='collecting' and current['sandbox']['cleanup']!='complete' and current['network']['absence'] is None
                assert self.marker('inspect')['present'];self.report['actual_negative_absence_checkpoint']=current
                self.check('an_actual_remaining_table_blocks_cleanup_and_the_read_only_worker_does_not_delete_it')
                assert not self.marker('remove')['present']
            current=self.recover_with_worker()
            assert current['sandbox']['state']=='terminated' and not current['network'].get('native') and current['network']['absence']['bridge_absent'] and current['network']['absence']['owned_tables_absent']
            original=next(row for row in current['controllers'] if row['controller_generation']==self.probe_generation)
            assert original['create_token']==record['create_token'] and original['start_token']==record['start_token']
            if physical:assert original['container_id']==physical
            assert all('native' not in row['plan'] for row in current['controllers']) and any(row['plan']['purpose']=='observe_absence' for row in current['controllers'])
            self.report['final_probe_records']=current
            self.check('the_production_worker_settles_original_dispatches_and_confirms_actual_absence_without_replaying_or_binding_a_native_index')
            after=self.audit();assert not after['bridge_exists'] and not after['owned_tables'];self.report['independent_native_absence']=after
            assert not self.docker('ps','-a','--filter','label=dev.goldenhoop.installation='+self.installation,'--filter','label=dev.goldenhoop.role=sandbox','--format','{{.ID}}').stdout.strip()
            assert not any(row['kind']=='create' and row['state']=='succeeded' for row in current['operations'])
            self.check('no_workload_or_successful_create_is_published_and_actual_bridge_and_rule_scopes_are_absent')
            self.report['result']='passed'
        except BaseException as error:
            failure=error;self.report.update(result='failed',error=repr(error));self.failure_observation()
        finally:
            try:self.stop_worker();self.cleanup();self.report['cleanup']='complete'
            except BaseException as error:failure=failure or error;self.report.update(result='failed',cleanup='unknown',cleanup_error=repr(error))
            self.save();print(json.dumps({key:self.report.get(key) for key in ['result','cleanup','error','cleanup_error']}),flush=True)
        if failure:raise failure

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',required=True);parser.add_argument('--worker-binary',required=True)
    parser.add_argument('--image',default='goldenhoop-network-fixture:test');parser.add_argument('--agent-image',default='goldenhoop-agent:test');parser.add_argument('--controller-image',default='goldenhoop-egress:test')
    parser.add_argument('--runtime',choices=['runc'],default='runc');parser.add_argument('--mode',choices=['reserve','create-loss','start-loss','table-blocked'],required=True)
    parser.add_argument('--work-dir',required=True);parser.add_argument('--output',required=True);parser.add_argument('--remove-image',action='store_true')
    Contract(parser.parse_args()).run()
