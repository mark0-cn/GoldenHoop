"""Production worker-held policies, renewal, updates, pause and crash recovery."""
import argparse
import base64
import copy
import hashlib
import json
import sqlite3
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import closing
from datetime import datetime,timezone
from pathlib import Path
from guarded_bootstrap_contract import Contract as GuardedContract


ALLOW={'policies':[{'default_action':'deny','rules':[{'destination':'93.184.216.34','ports':[443],'action':'allow'}]}]}
DENY={'policies':[{'default_action':'deny','rules':[]}]}


def current_ready_owner(records,policy,registration,desired_revision,previous_owner=None,now=None):
    """Observation filter only; the actual private lease gate must also reply."""
    try:
        now=now or datetime.now(timezone.utc)
        age=(now-datetime.fromisoformat(registration['heartbeat'].replace('Z','+00:00'))).total_seconds()
        owner=policy['owner']
        controllers=[row for row in records['controllers'] if row['controller_generation']==owner['controller_generation']]
        return (records['sandbox']['state']=='running' and policy['phase']=='active'
                and policy['desired_revision']==desired_revision and -5<=age<=10
                and owner['worker_id']==registration['id']
                and len(controllers)==1 and controllers[0]['phase']=='running'
                and controllers[0]['container_id']==owner['container_id']
                and (previous_owner is None or (owner['worker_id']!=previous_owner['worker_id']
                     and owner['controller_generation']!=previous_owner['controller_generation'])))
    except (KeyError,TypeError,ValueError):
        return False


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        return None


class Contract(GuardedContract):
    def __init__(self,args):
        super().__init__(args)
        self.report['suite']='production-worker-held-protected-policy'
        self.report['scope']='Trusted staged complete allocation, actual worker-owned controller/DNS recovery, finite policy renewal, Ready/commands, dynamic tightening, pause/resume and process crash. Initial public network provisioning and capability publication remain unavailable.'
        self.report['source_files_sha256']['tests/worker_network_policy_contract.py']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        self.report['policy_binary_sha256']=hashlib.sha256(Path(args.policy_binary).read_bytes()).hexdigest()

    def policy(self,action,*extra,expected=0):
        command=[self.args.policy_binary,'--database',str(self.database),'--sandbox',self.sandbox,action,*extra]
        result=subprocess.run(command,capture_output=True,text=True,encoding='utf-8',timeout=20)
        frames=[json.loads(line) for line in result.stdout.splitlines()]
        self.report.setdefault('policy_calls',[]).append({'command':command,'exit_code':result.returncode,'frames':frames,'stderr':result.stderr[-4096:]});self.save()
        assert result.returncode==expected and len(frames)==1,(result.returncode,frames,result.stderr)
        return frames[0]['result' if expected==0 else 'error']

    def control(self):
        with closing(sqlite3.connect(self.database.as_uri()+'?mode=ro',uri=True,timeout=2)) as db:
            return json.loads(db.execute('SELECT payload FROM network_policies WHERE sandbox_id=?',(self.sandbox,)).fetchone()[0])

    def registration(self):
        with closing(sqlite3.connect(self.database.as_uri()+'?mode=ro',uri=True,timeout=2)) as db:
            row=db.execute("SELECT value FROM meta WHERE key='worker'").fetchone()
            return json.loads(row[0]) if row else None

    def live_diagnostics(self,registration):
        endpoint=urllib.parse.urlsplit(registration['endpoint'])
        assert endpoint.scheme=='http' and endpoint.hostname in ('127.0.0.1','::1') and endpoint.port
        assert not endpoint.username and not endpoint.password and endpoint.path=='' and not endpoint.query and not endpoint.fragment
        request=urllib.request.Request(registration['endpoint']+'/internal/diagnostics',data=json.dumps({'sandbox_id':self.sandbox}).encode(),headers={'Authorization':'Bearer '+registration['token'],'Content-Type':'application/json'},method='POST')
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect()).open(request,timeout=7) as response:
                receipt=json.load(response)
        except (urllib.error.URLError,TimeoutError,OSError,json.JSONDecodeError) as error:
            self.report.setdefault('private_lease_gate_unavailable',[]).append({'error_type':type(error).__name__,'http_status':getattr(error,'code',None)})
            return None
        assert receipt['sandbox']['id']==self.sandbox
        sample=receipt['runtime']
        if sample is not None:assert sample['sandbox_id']==self.sandbox
        return receipt if receipt['sandbox']['state']=='running' and sample is not None and sample['running'] is True and sample['paused'] is False else None

    def start_live_worker(self):
        assert self.worker is None
        self.log_handle=self.worker_log.open('ab')
        command=[self.args.worker_binary,'--database',str(self.database),'worker','--agent-image',self.args.agent_image,'--allow-runc-development','--egress-controller-image',self.controller_image_id]
        self.worker=subprocess.Popen(command,stdout=self.log_handle,stderr=subprocess.STDOUT,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        self.worker_started=True;self.report.setdefault('live_worker_commands',[]).append(command);self.save()

    def wait_state(self,state,desired_revision=None,previous_owner=None):
        deadline=time.monotonic()+100
        while time.monotonic()<deadline:
            assert self.worker and self.worker.poll() is None,'worker exited'
            records=self.records();policy=self.control();registration=self.registration()
            if records['sandbox']['state']==state and (desired_revision is None or (policy['phase']=='active' and policy['desired_revision']==desired_revision)):
                diagnostics=None
                if state=='running':
                    if not current_ready_owner(records,policy,registration,desired_revision,previous_owner):
                        self.report.setdefault('historical_readiness_refused',[]).append({'state':state,'policy_phase':policy['phase'],'policy_owner':policy['owner'],'registered_worker_id':registration['id'] if registration else None})
                        time.sleep(0.25);continue
                    diagnostics=self.live_diagnostics(registration)
                    if diagnostics is None:
                        time.sleep(0.25);continue
                self.report.setdefault('observed_worker_states',[]).append({'records':records,'policy':policy,'current_worker_id':registration['id'] if registration else None,'live_diagnostics':diagnostics});self.save();return records,policy
            time.sleep(0.25)
        self.report['last_live_records']=self.records();self.report['last_live_policy']=self.control();self.save()
        raise RuntimeError('worker did not reach '+state)

    def command(self,marker):
        result=self.policy('command','--command-json',json.dumps({'argv':['/bin/sh','-c','printf '+marker],'timeout_seconds':10}))
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            with closing(sqlite3.connect(self.database.as_uri()+'?mode=ro',uri=True,timeout=2)) as db:
                row=db.execute('SELECT payload FROM executions WHERE id=?',(result['id'],)).fetchone();execution=json.loads(row[0])
            if execution['state'] in ('succeeded','failed','cancelled','timed_out'):
                assert execution['state']=='succeeded' and execution['exit_code']==0,execution
                with closing(sqlite3.connect(self.database.as_uri()+'?mode=ro',uri=True,timeout=2)) as db:
                    events=[json.loads(row[0]) for row in db.execute('SELECT payload FROM events WHERE execution_id=? ORDER BY sequence',(result['id'],))]
                stdout=b''.join(base64.b64decode(event['data']['data']) for event in events if event['kind']=='stdout')
                assert stdout==marker.encode() and len([event for event in events if event['kind']=='completed'])==1
                self.report.setdefault('worker_commands',[]).append({'execution':execution,'events':events});self.save();return execution
            time.sleep(0.1)
        raise RuntimeError('worker did not collect an explicit command exit')

    def same_runtime(self,original):
        current=self.target_runtime()
        assert current['Id']==original['Id'] and current['State']['Pid']==original['State']['Pid'] and current['State']['StartedAt']==original['State']['StartedAt']

    def after_startup(self):
        frozen=self.report['bootstrap_result']['protected_binding'];original=self.target_runtime()
        self.report['initial_owned_dns_spy']=copy.deepcopy(self.report['owned_dns_spy']);self.start_upstream()
        staged=self.policy('stage','--checkpoint-json',json.dumps(frozen),'--upstream',self.upstream,'--config-json',json.dumps(ALLOW))
        assert staged['phase']=='pending' and staged['owner'] is None and staged['observation'] is None
        self.check('a_staged_desired_policy_never_reconstructs_a_live_lease_or_publishes_Ready')
        self.start_live_worker();records,active=self.wait_state('running',0)
        assert active['owner']['controller_generation']!=self.controller_generation
        assert any(row['kind']=='create' and row['state']=='succeeded' for row in records['operations'])
        assert all(not {'network_policy','secret_injection'}.intersection(p['capabilities']) for p in records['profiles'])
        self.command('goldenhoop_first_live_policy');self.same_runtime(original)
        self.check('the_production_worker_recovers_exact_DNS_in_a_fresh_epoch_and_dispatches_only_after_actual_protected_policy_readback')
        initial_epoch=active['owner']['controller_generation'];initial_revision=active['observation']['binding']['revision']
        time.sleep(12)
        _,renewed=self.wait_state('running',0)
        assert renewed['owner']['controller_generation']==initial_epoch and renewed['observation']['binding']['revision']==initial_revision
        self.command('goldenhoop_after_kernel_lease_duration');self.same_runtime(original)
        self.report['independent_held_policy']=self.source_audit(renewed['observation']['binding'],self.report['bootstrap_native_alias']['alias'])
        self.check('a_dedicated_held_session_renews_the_actual_kernel_lease_beyond_its_original_ten_seconds_without_recreating_the_workload')
        changed=self.policy('update','--desired-revision','0','--config-json',json.dumps(DENY))
        assert changed['phase']=='pending' and changed['observation'] is None and changed['desired_revision']==1
        refused=self.policy('update','--desired-revision','0','--config-json',json.dumps(ALLOW),expected=1);assert refused['code']=='conflict'
        _,tightened=self.wait_state('running',1)
        assert tightened['observation']['binding']['revision']>initial_revision and tightened['config_sha256']!=renewed['config_sha256']
        assert tightened['owner']==renewed['owner']
        self.command('goldenhoop_after_tightening');self.same_runtime(original)
        self.check('desired_policy_CAS_invalidates_old_readiness_and_the_same_session_confirms_a_new_tightened_revision')
        self.policy('desired','--state','paused');self.wait_state('paused')
        assert self.target_runtime()['State']['Paused'] and self.control()['phase']=='fenced'
        refused=self.policy('command','--command-json',json.dumps({'argv':['/bin/true']}),expected=1);assert refused['code']=='invalid_state'
        self.policy('desired','--state','running');_,resumed=self.wait_state('running',1);self.same_runtime(original)
        assert resumed['owner']['controller_generation']!=initial_epoch
        self.command('goldenhoop_after_quarantined_resume')
        self.check('pause_collects_the_held_epoch_and_resume_requires_new_quarantine_DNS_and_policy_before_commands')
        old_owner=resumed['owner'];self.worker.kill();self.worker.wait(timeout=15);self.worker=None
        self.log_handle.close();self.log_handle=None
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            old_process=json.loads(self.docker('inspect',old_owner['container_id']).stdout)[0];self.owned(old_process)
            if not old_process['State']['Running']:break
            time.sleep(0.1)
        assert not old_process['State']['Running'],'old controller did not settle after worker crash'
        self.report['actual_old_controller_after_worker_crash']={'container_id':old_process['Id'],'state':old_process['State']}
        time.sleep(11)
        stale=self.control();assert stale['owner']==old_owner and stale['phase']=='active'
        self.report['historical_ack_after_worker_crash']=stale
        expired=self.source_audit(stale['observation']['binding'],self.report['bootstrap_native_alias']['alias'])
        sets=[row['set'] for row in expired['inet_table']['nftables'] if 'set' in row]
        live=[s for s in sets if s['name']=='live'];assert len(live)==1 and not live[0].get('elem')
        self.report['independent_expired_kernel_policy']=expired;self.same_runtime(original)
        self.start_live_worker();_,recovered=self.wait_state('running',1,previous_owner=old_owner)
        assert recovered['owner']['worker_id']!=old_owner['worker_id'] and recovered['owner']['controller_generation']!=old_owner['controller_generation']
        self.command('goldenhoop_after_worker_crash_recovery');self.same_runtime(original)
        self.check('actual_worker_crash_expires_the_kernel_lease_and_historical_active_metadata_cannot_bypass_fresh_epoch_recovery')
        logs=[json.loads(line) for line in self.docker('logs',self.upstream_id).stdout.splitlines()];assert not any(row.get('unexpected_query') for row in logs)
        self.report['owned_dns_spy']['logs']=logs;self.owned(json.loads(self.docker('inspect',self.upstream_id).stdout)[0]);self.docker('rm','--force','--volumes',self.upstream_id)
        self.policy('desired','--state','terminated')

    def recover_with_worker(self):
        # Failure paths also explicitly request terminal collection of a staged
        # allocation; the inherited collector never silently creates that intent.
        if self.database.exists() and self.sandbox:
            self.policy('desired','--state','terminated')
        return super().recover_with_worker()

    def verify_collected_publication(self,current):
        assert current['sandbox']['state']=='terminated'
        assert any(row['kind']=='create' and row['state']=='succeeded' for row in current['operations'])
        assert self.control()['phase']=='fenced' and self.control()['observation'] is None


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',required=True);p.add_argument('--worker-binary',required=True);p.add_argument('--policy-binary',required=True)
    p.add_argument('--runtime',choices=['runc','runsc'],default='runc');p.add_argument('--mode',choices=['full'],default='full')
    p.add_argument('--image',default='goldenhoop-network-fixture:test');p.add_argument('--agent-image',default='goldenhoop-agent:test');p.add_argument('--controller-image',default='goldenhoop-egress:test')
    p.add_argument('--work-dir',required=True);p.add_argument('--output',required=True);p.add_argument('--remove-image',action='store_true')
    Contract(p.parse_args()).run()
