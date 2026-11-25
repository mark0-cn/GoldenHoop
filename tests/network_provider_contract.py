"""Actual empty bridge allocation, lost consumer result, owned recovery/collection."""
import argparse
import hashlib
import ipaddress
import json
import shutil
import sqlite3
import subprocess
import tempfile
import uuid
from contextlib import closing
from datetime import datetime,timezone
from pathlib import Path


AUDIT=r'''
import datetime,json,pathlib,socket,subprocess,sys
p=json.loads(sys.argv[1]);bridge=p['identity']['generation'].replace('-','')[:12];bridge='ghn'+bridge
generation=p['identity']['generation'].replace('-','');names={prefix+generation for prefix in ['gh_e_','gh_l_','gh_s_','gh_d_']}
result=subprocess.run(['nft','--json','list','tables'],capture_output=True,text=True,timeout=5)
assert result.returncode==0,result.stderr
tables=[row['table'] for row in json.loads(result.stdout)['nftables'] if row.get('table',{}).get('name') in names]
path=pathlib.Path('/sys/class/net')/bridge;exists=path.exists();addresses=[];index=None;kind=False
if exists:
 index=int((path/'ifindex').read_text());assert index==socket.if_nametoindex(bridge)
 kind=(path/'bridge').is_dir();result=subprocess.run(['ip','--json','addr','show','dev',bridge],capture_output=True,text=True,timeout=5)
 assert result.returncode==0,result.stderr
 addresses=[a['local'] for link in json.loads(result.stdout) for a in link.get('addr_info',[]) if a.get('family') in ('inet','inet6')]
print(json.dumps({'bridge':bridge,'bridge_exists':exists,'ifindex':index,'is_bridge':kind,'addresses':addresses,'owned_tables':tables,'helper_observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat()}))
'''


def call(command,timeout=60,check=True):
    result=subprocess.run(command,capture_output=True,timeout=timeout)
    result.stdout=result.stdout.decode('utf-8');result.stderr=result.stderr.decode('utf-8',errors='replace')
    if check and result.returncode:raise RuntimeError(f'{command[0]} failed: {result.stderr[:4000]} {result.stdout[-2000:]}')
    return result


class Contract:
    def __init__(self,args):
        self.args=args;self.root=Path(__file__).resolve().parents[1];self.work=Path(args.work_dir).resolve();self.work.mkdir(parents=True,exist_ok=True)
        self.state=Path(tempfile.mkdtemp(prefix='goldenhoop-network-provider-',dir=self.work)).resolve();assert self.state.is_relative_to(self.work)
        self.database=self.state/'control.db';self.installation=None;self.sandbox=None;self.plan=None;self.settled=False;self.creation_uncertain=False
        self.attempt=uuid.uuid4().hex
        (self.state/'.goldenhoop-owner').write_text(self.attempt,encoding='ascii')
        self.report={'suite':'rust-owned-bridge-provider','scope':'actual empty Docker bridge and private journal recovery/collection; no workload publication or network-policy capability','timestamp':datetime.now(timezone.utc).isoformat(),'attempt':self.attempt,'temporary_directory':str(self.state),'result':'failed','cleanup':'unknown','cases':[],'invocations':[],'kernel_observations':[]}
        sources=[Path(__file__).resolve(),self.root/'Cargo.toml',self.root/'Cargo.lock',self.root/'images/agent/Dockerfile',self.root/'tests/fixtures/network.Dockerfile']
        for crate in ('control','core','protocol','runtime','docker','store','egress','policy'):
            sources.extend((self.root/'crates'/crate).rglob('*.rs'));sources.extend((self.root/'crates'/crate).rglob('*.sql'));sources.append(self.root/'crates'/crate/'Cargo.toml')
        self.report['source_files_sha256']={p.relative_to(self.root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
        self.report['binary_sha256']=hashlib.sha256(Path(args.binary).read_bytes()).hexdigest();self.save()

    def save(self):
        output=Path(self.args.output);output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(self.report,indent=2)+'\n',encoding='utf-8',newline='\n')

    def docker(self,*args,check=True):return call(['docker',*args],check=check)

    def recover_metadata(self):
        if not self.database.is_file():return
        with closing(sqlite3.connect(self.database.as_uri()+'?mode=ro',uri=True,timeout=2)) as connection:
            row=connection.execute("SELECT value FROM meta WHERE key='installation_id'").fetchone()
            if row:
                installation=str(uuid.UUID(row[0]));assert not self.installation or self.installation==installation;self.installation=installation;self.report['installation_id']=installation
            rows=connection.execute('SELECT payload FROM network_allocations').fetchall();assert len(rows)<=1
            if rows:
                record=json.loads(rows[0][0]);self.sandbox=record['sandbox_id']
                history=connection.execute('SELECT payload FROM network_allocation_events WHERE sandbox_id=? ORDER BY revision LIMIT 128',(self.sandbox,)).fetchall()
                dispatch=next((json.loads(r[0]) for r in history if json.loads(r[0])['phase']=='provisioning'),None)
                if dispatch:
                    sandbox=json.loads(connection.execute('SELECT payload FROM sandboxes WHERE id=?',(self.sandbox,)).fetchone()[0])
                    plan={'identity':{key:record[key] for key in ('installation_id','sandbox_id','generation','profile')},'provisioning_token':dispatch['token'],'expires_at':sandbox['expires_at']}
                    if not self.plan:self.plan=plan;self.report['plan']=plan

    def invoke(self,action,*extra,expected=0):
        command=[self.args.binary,'--database',str(self.database),'--action',action,'--agent-image',self.args.agent_image]
        if self.sandbox:command.extend(['--sandbox',self.sandbox])
        timed_out=False
        try:result=call([*command,*extra],check=False)
        except subprocess.TimeoutExpired as error:
            timed_out=True
            if action in ('init','negative'):self.creation_uncertain=True;self.settled=False
            result=subprocess.CompletedProcess(command,None,(error.stdout or b'').decode('utf-8',errors='replace'),(error.stderr or b'').decode('utf-8',errors='replace'))
        rows=[];malformed=False
        for line in result.stdout.splitlines():
            try:rows.append(json.loads(line))
            except ValueError:malformed=True
        self.report['invocations'].append({'action':action,'exit_code':result.returncode,'timed_out':timed_out,'malformed_frame':malformed,'stderr':result.stderr[:4096],'frames':rows})
        for row in rows:
            if 'installation_id' in row:
                if self.installation:assert self.installation==row['installation_id']
                self.installation=row['installation_id'];self.report['installation_id']=self.installation
            if 'intent' in row:
                self.sandbox=row['intent']['sandbox_id'];self.plan=row['plan'];self.report['plan']=self.plan
        if timed_out or malformed or result.returncode!=expected:self.recover_metadata()
        self.save();assert not timed_out and not malformed and result.returncode==expected,(action,result.returncode,result.stderr,rows)
        return rows[-1].get('result')

    def check(self,name):self.report['cases'].append(name);self.save();print('passed:',name,flush=True)

    def failure_observation(self):
        if not self.installation:return
        observation={'network_inspections':[]}
        try:
            identities=self.docker('network','ls','--filter','label=dev.goldenhoop.installation='+self.installation,'--format','{{.ID}}').stdout.split();assert len(identities)<=8
            for identity in identities:
                native=json.loads(self.docker('network','inspect',identity).stdout)[0];labels=self.owned(native)
                assert labels['dev.goldenhoop.role']=='egress-network' and self.plan and labels['dev.goldenhoop.network-generation']==self.plan['identity']['generation']
                observation['network_inspections'].append(native)
            observation['docker_server']=json.loads(self.docker('version','--format','{{json .Server}}').stdout)
            if self.plan:observation['native_before_cleanup']=self.audit()
            if self.database.exists():
                with closing(sqlite3.connect(self.database.as_uri()+'?mode=ro',uri=True,timeout=2)) as connection:
                    observation['journal_rows']=[json.loads(row[0]) for row in connection.execute('SELECT payload FROM network_allocations LIMIT 8')]
                    observation['journal_history']=[json.loads(row[0]) for row in connection.execute('SELECT payload FROM network_allocation_events ORDER BY revision LIMIT 128')]
        except BaseException as error:observation['diagnostic_error']=repr(error)
        self.report['failure_observation']=observation;self.save()

    def audit(self):
        assert self.plan and self.installation
        started=datetime.now(timezone.utc).isoformat();name='goldenhoop-provider-audit-'+uuid.uuid4().hex
        raw=self.docker('run','--rm','--name',name,'--label','dev.goldenhoop.installation='+self.installation,'--label','dev.goldenhoop.role=network-provider-audit','--label','dev.goldenhoop.test=network-provider','--label','dev.goldenhoop.attempt='+self.attempt,'--runtime','runc','--network','host','--user','0:0','--cap-drop','ALL','--cap-add','NET_ADMIN','--security-opt','no-new-privileges:true','--read-only','--memory','128m','--memory-swap','128m','--cpus','0.25','--pids-limit','32','--entrypoint','python3',self.args.image,'-B','-c',AUDIT,json.dumps(self.plan)).stdout
        observed=json.loads(raw);observed['collector_window_start']=started;observed['collector_window_end']=datetime.now(timezone.utc).isoformat();self.report['kernel_observations'].append(observed);self.save();return observed

    def owned(self,obj):
        labels=obj.get('Labels',obj.get('Config',{}).get('Labels',{}))
        assert labels.get('dev.goldenhoop.installation')==self.installation
        assert labels.get('dev.goldenhoop.role') in ('sandbox','bootstrap','agent-bundle','egress-network','network-provider-peer','network-provider-audit'),labels
        return labels

    def cleanup(self):
        if self.installation:
            for identity in self.docker('ps','-a','--filter','label=dev.goldenhoop.installation='+self.installation,'--format','{{.ID}}').stdout.split():
                obj=json.loads(self.docker('inspect',identity).stdout)[0];self.owned(obj);self.docker('rm','--force','--volumes',identity)
            for identity in self.docker('network','ls','--filter','label=dev.goldenhoop.installation='+self.installation,'--format','{{.ID}}').stdout.split():
                obj=json.loads(self.docker('network','inspect',identity).stdout)[0];labels=self.owned(obj)
                assert self.plan and labels['dev.goldenhoop.role']=='egress-network' and obj['Name']=='goldenhoop-net-'+self.plan['identity']['generation'].replace('-','') and not obj['Containers']
                assert labels['dev.goldenhoop.network-generation']==self.plan['identity']['generation'] and labels['dev.goldenhoop.network-provisioning']==self.plan['provisioning_token']
                self.docker('network','rm',identity)
            for name in self.docker('volume','ls','--filter','label=dev.goldenhoop.installation='+self.installation,'--format','{{.Name}}').stdout.split():
                obj=json.loads(self.docker('volume','inspect',name).stdout)[0];assert self.owned(obj)['dev.goldenhoop.role']=='agent-bundle';self.docker('volume','rm',name)
            for cmd,fmt in [(('ps','-a'),'{{.ID}}'),(('network','ls'),'{{.ID}}'),(('volume','ls'),'{{.Name}}')]:assert not self.docker(*cmd,'--filter','label=dev.goldenhoop.installation='+self.installation,'--format',fmt).stdout.strip()
            self.report['actual_owned_resource_inventories_empty']=True
            if self.plan:
                observed=self.audit();assert not observed['bridge_exists'] and not observed['owned_tables'];self.report['actual_bridge_and_owned_tables_absent']=True
            for cmd,fmt in [(('ps','-a'),'{{.ID}}'),(('network','ls'),'{{.ID}}'),(('volume','ls'),'{{.Name}}')]:assert not self.docker(*cmd,'--filter','label=dev.goldenhoop.installation='+self.installation,'--format',fmt).stdout.strip()
        if self.args.remove_image and self.report.get('fixture_image_id'):
            obj=json.loads(self.docker('image','inspect',self.args.image).stdout)[0];assert obj['Id']==self.report['fixture_image_id'] and obj['Config']['Labels'].get('dev.goldenhoop.fixture')=='network-interop'
            assert not self.docker('ps','-a','--filter','ancestor='+self.args.image,'--format','{{.ID}}').stdout.strip()
            self.docker('image','rm','--no-prune',self.args.image);assert self.args.image not in self.docker('image','ls','-a','--format','{{.Repository}}:{{.Tag}}').stdout.split();self.report['fixture_image_absent']=True
        assert self.state.is_relative_to(self.work) and self.state.name.startswith('goldenhoop-network-provider-')
        if self.creation_uncertain or (self.plan and not self.settled):
            self.report['recovery_state']=str(self.state)
            raise RuntimeError('provider creation settlement remains unknown; retain the private database for recovery')
        assert self.state.resolve().is_relative_to(self.work) and (self.state/'.goldenhoop-owner').read_text(encoding='ascii')==self.attempt
        shutil.rmtree(self.state);assert not self.state.exists();self.report['temporary_directory_absent']=True

    def run(self):
        failure=None
        try:
            image=json.loads(self.docker('image','inspect',self.args.image).stdout)[0];assert image['Config']['Labels'].get('dev.goldenhoop.fixture')=='network-interop';self.report['fixture_image_id']=image['Id']
            self.invoke('init','--fault-after-create','--leading-zero-subnet',expected=75);self.settled=True
            assert self.sandbox and self.plan
            identity={key:self.plan['identity'][key] for key in ('installation_id','sandbox_id','generation','profile')}
            digest=hashlib.sha256(json.dumps([1,identity],separators=(',',':')).encode('utf-8')).hexdigest()
            padded='fd'+digest[:2]+':'+digest[2:6]+':'+digest[6:10]+':1::/64';canonical=str(ipaddress.ip_network(padded))
            assert padded!=canonical
            self.report['derived_ipv6_subnet']={'padded_digest_spelling':padded,'canonical_subnet':canonical,'same_numeric_prefix':True};self.save()
            if self.args.fail_after_create:raise RuntimeError('controlled harness failure after settled creation before recovery')
            expected_plan=self.plan;self.installation=None;self.sandbox=None;self.plan=None
            self.recover_metadata();assert self.plan==expected_plan
            self.report['creator_output_discarded_and_recovered_from_file_database']=True;self.save()
            self.check('committed_intent_survives_actual_process_exit_after_creation_before_binding')
            name='goldenhoop-net-'+self.plan['identity']['generation'].replace('-','')
            created=json.loads(self.docker('network','inspect',name).stdout)[0];labels=self.owned(created)
            assert labels['dev.goldenhoop.network-provisioning']==self.plan['provisioning_token'] and labels['dev.goldenhoop.network-generation']==self.plan['identity']['generation']
            self.report['created_network_before_recovery']=created;before_recovery=self.audit();self.save()
            recovered=self.invoke('recover');provider=recovered['provider'];assert recovered['creation_replayed'] is False and recovered['journal']['phase']=='provisioning' and recovered['journal']['binding'] is None
            assert provider['ipv6_subnet']==canonical
            assert provider['network_id']==created['Id']
            self.report['recovered_provider']=provider
            self.report['owned_network_inspection']=json.loads(self.docker('network','inspect',provider['network_id']).stdout)[0]
            assert self.report['owned_network_inspection']['Created']==created['Created']
            self.check('fresh_process_recovers_one_owned_provider_network_without_replaying_creation')
            native=self.audit();assert native['bridge_exists'] and native['is_bridge'] and native['ifindex']>0 and not native['owned_tables']
            assert native['ifindex']==before_recovery['ifindex']
            assert {str(ipaddress.ip_address(provider['ipv4_gateway'])),str(ipaddress.ip_address(provider['ipv6_gateway']))}.issubset(native['addresses']),native
            self.check('actual_native_bridge_index_and_gateway_addresses_match_the_owned_provider')
            self.invoke('native','--native-ifindex',str(native['ifindex']),'--fault-after-native',expected=76)
            with closing(sqlite3.connect(self.database.as_uri()+'?mode=ro',uri=True,timeout=2)) as connection:
                checkpoint=json.loads(connection.execute('SELECT payload FROM network_allocations WHERE sandbox_id=?',(self.sandbox,)).fetchone()[0])
            assert checkpoint['phase']=='provisioning' and checkpoint['binding'] is None and checkpoint['native']['network_id']==provider['network_id']
            assert checkpoint['native']['allocation']['ifindex']==native['ifindex'] and checkpoint['revision']==2
            recovered=self.invoke('recover');assert recovered['journal']==checkpoint and recovered['provider']['network_id']==provider['network_id'] and not recovered['creation_replayed']
            same=self.invoke('native','--native-ifindex',str(native['ifindex']));assert same['journal']['revision']==2 and not same['packet_installation_performed']
            self.report['native_checkpoint_recovered_from_file_database']=checkpoint;self.save()
            self.check('actual_exit_after_native_checkpoint_keeps_the_original_provider_and_index_without_source_or_packet_confirmation')
            negative=self.invoke('negative');assert len(negative['checks'])==7 and negative['provider']['network_id']==provider['network_id'];self.check('foreign_owner_token_profile_deadline_ids_duplicate_and_expired_creation_refuse_without_mutation')
            peer_name='goldenhoop-provider-peer-'+self.attempt
            peer=self.docker('run','--detach','--name',peer_name,'--label','dev.goldenhoop.installation='+self.installation,'--label','dev.goldenhoop.role=network-provider-peer','--label','dev.goldenhoop.test=network-provider','--label','dev.goldenhoop.attempt='+self.attempt,'--runtime','runc','--network',provider['network_id'],'--user','1000:1000','--cap-drop','ALL','--security-opt','no-new-privileges:true','--read-only','--no-healthcheck','--memory','64m','--memory-swap','64m','--cpus','0.25','--pids-limit','32','--entrypoint','python3',self.args.image,'-B','-c','import time;time.sleep(600)').stdout.strip()
            obj=json.loads(self.docker('inspect',peer).stdout)[0];self.owned(obj);assert obj['HostConfig']['Privileged'] is False and not obj['HostConfig'].get('CapAdd') and obj['Mounts']==[]
            identity=json.loads(self.docker('exec','--user','1000:1000',peer,'python3','-B','-c',"import json,os;d=dict(line.split(':',1) for line in open('/proc/self/status') if ':' in line);print(json.dumps({'uid':os.getuid(),'gid':os.getgid(),'capabilities':int(d['CapEff'].strip(),16),'no_new_privileges':int(d['NoNewPrivs'].strip())}))").stdout)
            assert identity=={'uid':1000,'gid':1000,'capabilities':0,'no_new_privileges':1},identity
            self.report['diagnostic_identity']=identity;self.save()
            refused=self.invoke('reject-nonempty');assert refused['live_collection_refused'];self.check('an_actual_attached_zero_capability_diagnostic_prevents_network_collection')
            self.docker('rm','--force','--volumes',peer)
            removed=self.invoke('collect');assert removed['provider']['provider_absent'] and removed['journal']['phase']=='collecting' and removed['kernel_confirmation_pending']
            self.check('provider_removal_and_positive_inventory_do_not_prematurely_confirm_kernel_cleanup')
            native=self.audit();assert not native['bridge_exists'] and not native['owned_tables']
            absence={'provisioning_settled':True,'endpoints_absent':True,'network_absent':True,'bridge_absent':True,'owned_tables_absent':True,'observed_at':native['collector_window_start']}
            confirmed=self.invoke('confirm','--absence-json',json.dumps(absence));assert confirmed['journal']['phase']=='collected' and confirmed['sandbox']['cleanup']=='complete'
            assert [row['phase'] for row in confirmed['history']]==['reserved','provisioning','provisioning','collecting','collected']
            assert confirmed['journal']['native']['allocation']['ifindex']==checkpoint['native']['allocation']['ifindex']
            self.check('only_fresh_actual_native_absence_and_settled_creation_complete_the_durable_journal')
            self.report['result']='passed'
        except BaseException as error:
            failure=error;self.report['error']=repr(error);self.failure_observation()
        finally:
            try:self.cleanup();self.report['cleanup']='complete'
            except BaseException as error:failure=failure or error;self.report['cleanup']='unknown';self.report['cleanup_error']=repr(error);self.report['result']='failed'
            self.save();print(json.dumps({k:self.report.get(k) for k in ('result','cleanup','error','cleanup_error')}),flush=True)
        if failure:raise failure


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',required=True);p.add_argument('--image',default='goldenhoop-network-fixture:test');p.add_argument('--agent-image',default='goldenhoop-agent:test');p.add_argument('--work-dir',required=True);p.add_argument('--output',required=True);p.add_argument('--remove-image',action='store_true');p.add_argument('--fail-after-create',action='store_true');Contract(p.parse_args()).run()
