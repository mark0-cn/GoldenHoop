"""Actual settled controller replacement and exact DNS socket recovery under deny."""
import argparse
import copy
import hashlib
import json
import sqlite3
import subprocess
import time
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from guarded_bootstrap_contract import Contract as GuardedContract
from dns_recovery_samples import PIN_SOCKET


def binding_conflict(frames):
    error=next(frame['error'] for frame in frames if 'error' in frame)
    assert error['code']=='conflict' and error['message']=='allocation contract observation differs',error
    assert not any('controller_intent' in frame for frame in frames),frames
    return error


class Contract(GuardedContract):
    def __init__(self,args):
        super().__init__(args)
        self.report['suite']='production-driver-exact-DNS-recovery'
        self.report['scope']='Actual source/DNS/destination bootstrap, positively collected old controller, exact DNS rebind in a fresh journal epoch, and denial on an occupied frozen port. No policy lease, Ready, or user execution.'
        for path in [Path(__file__),Path(__file__).with_name('dns_recovery_samples.py')]:
            self.report['source_files_sha256'][path.relative_to(self.root).as_posix()]=hashlib.sha256(path.read_bytes()).hexdigest()
        self.report['readback_binary_sha256']=hashlib.sha256(Path(args.readback_binary).read_bytes()).hexdigest()

    def verify_quarantine(self,binding,revision,native):
        request={'allocation':binding['allocation'],'revision':revision,'dns':binding['destinations']['dns'],'native':native}
        result=subprocess.run([self.args.readback_binary],input=json.dumps(request),capture_output=True,text=True,encoding='utf-8',timeout=10)
        self.report.setdefault('independent_quarantine_verification',[]).append({'input':request,'exit_code':result.returncode,'stdout':result.stdout,'stderr':result.stderr});self.save()
        assert result.returncode==0 and json.loads(result.stdout)=={'verified':True},result.stderr

    def collect_epoch(self):
        previous=self.controller_generation
        collected=self.invoke('controller-collect')
        assert collected['journal']['phase']=='collected' and collected['removed']['provider_absent']
        current=self.records();assert current['network']['phase']=='bound' and all(row['phase']=='collected' for row in current['controllers'])
        self.report.setdefault('settled_replaced_epochs',[]).append({'controller_generation':previous,'collection':collected,'records':current});self.save()

    def new_epoch(self,frozen):
        self.controller_generation=str(uuid.uuid4())
        created=self.invoke('controller-create','--controller-resume-binding-json',json.dumps(frozen))
        assert created['journal']['phase']=='created' and created['journal']['plan']['native']['expires_at']==self.plan['expires_at']
        assert created['journal']['plan']['native']['allocation']==frozen['allocation']
        return created

    def start_blocker(self,endpoint):
        blocker=self.docker('run','--detach','--name','goldenhoop-dns-port-blocker-'+self.attempt,
            '--label','dev.goldenhoop.installation='+self.installation,'--label','dev.goldenhoop.role=network-provider-audit',
            '--label','dev.goldenhoop.test=network-provider','--label','dev.goldenhoop.attempt='+self.attempt,
            '--runtime','runc','--network','host','--user','1000:1000','--cap-drop','ALL',
            '--security-opt','no-new-privileges:true','--read-only','--no-healthcheck','--memory','64m','--memory-swap','64m',
            '--cpus','0.25','--pids-limit','16','--entrypoint','python3',self.report['fixture_image_id'],'-B','-u','-c',PIN_SOCKET,json.dumps(endpoint)).stdout.strip()
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            logs=[json.loads(line) for line in self.docker('logs',blocker).stdout.splitlines()]
            if logs:
                assert logs==[{'ready':True,**endpoint}];self.report['occupied_frozen_DNS_port']={'container_id':blocker,'logs':logs};self.save();return blocker
            time.sleep(0.05)
        raise RuntimeError('owned exact-port blocker did not bind')

    def after_startup(self):
        assert self.args.mode=='full'
        frozen=self.report['bootstrap_result']['protected_binding']
        original=self.target_runtime();assert original and original['State']['Running']
        self.collect_epoch()
        # Use the original native alias, never a caller-chosen owner string.
        owner=self.report['bootstrap_native_alias']['alias']
        before=self.source_audit(frozen,owner);self.verify_quarantine(frozen,frozen['revision'],before['inet_table'])
        wrong=copy.deepcopy(frozen);port=wrong['destinations']['dns'][0]['port'];wrong['destinations']['dns'][0]['port']=port+1 if port<65535 else 1024
        self.controller_generation=str(uuid.uuid4())
        self.invoke('controller-create','--controller-resume-binding-json',json.dumps(wrong),expected=1)
        rejected=self.report['invocations'][-1]['frames']
        self.report['changed_original_DNS_port_refused_before_dispatch']={'frames':rejected,'expected_error':'conflict'};self.save()
        binding_conflict(rejected)
        assert all(row['controller_generation']!=self.controller_generation for row in self.records()['controllers'])
        assert not self.docker('ps','-a','--filter','label=dev.goldenhoop.installation='+self.installation,'--filter','label=dev.goldenhoop.role=egress-controller','--format','{{.ID}}').stdout.strip()
        self.check('the_old_actual_controller_is_positively_collected_while_the_owned_binding_and_deny_rules_remain')
        self.report['initial_owned_dns_spy']=copy.deepcopy(self.report['owned_dns_spy'])
        self.start_upstream();self.new_epoch(frozen)
        replacement_since=datetime.now(timezone.utc).isoformat()
        resumed=self.invoke('controller-resume','--controller-resume-binding-json',json.dumps(frozen),'--recovery-dns-upstream',self.upstream)
        recovered=resumed['exchange']['resume']['recovered_binding']
        assert recovered['revision']==frozen['revision']+1 and recovered['expires_at']==frozen['expires_at']
        assert recovered['source']==frozen['source'] and recovered['destinations']==frozen['destinations']
        assert resumed['exchange']['resume']['duplicate_recovery_refused'] and not resumed['exchange']['resume']['workload_ready'] and not resumed['exchange']['resume']['user_execution_dispatched']
        self.report['actual_replacement_recovery']=resumed
        after=self.source_audit(recovered,owner);self.verify_quarantine(recovered,recovered['revision'],after['inet_table'])
        for kind in ['source_table','destination_table']:
            old_table=next(row['table'] for row in before[kind]['nftables'] if 'table' in row)
            new_table=next(row['table'] for row in after[kind]['nftables'] if 'table' in row)
            assert old_table==new_table
        self.report['independent_recovered_native_binding']=after
        self.check('a_fresh_owned_controller_rebinds_the_exact_original_dual_stack_DNS_ports_and_preserves_immutable_guards_and_expiry')
        current=self.target_runtime();assert current['Id']==original['Id'] and current['State']['Pid']==original['State']['Pid'] and current['State']['StartedAt']==original['State']['StartedAt']
        events=self.runtime_events(replacement_since,datetime.now(timezone.utc).isoformat())
        assert not [e for e in events if e['Action'] in ('create','start') and e['Actor']['Attributes'].get('dev.goldenhoop.role')=='sandbox']
        with closing(sqlite3.connect(self.database.as_uri()+'?mode=ro',uri=True,timeout=2)) as connection:
            assert connection.execute('SELECT COUNT(*) FROM executions WHERE sandbox_id=?',(self.sandbox,)).fetchone()[0]==0
        self.report['replacement_runtime_events']=events
        self.check('controller_replacement_never_recreates_or_restarts_the_runtime_or_dispatches_user_execution')
        self.collect_epoch()
        blocker=self.start_blocker(frozen['destinations']['dns'][1]);self.new_epoch(frozen)
        self.invoke('controller-resume','--controller-resume-binding-json',json.dumps(frozen),'--recovery-dns-upstream',self.upstream,expected=1)
        frames=self.report['invocations'][-1]['frames'];error=next(frame['error'] for frame in frames if 'error' in frame)
        assert error['code']=='backend_unavailable' and error['message']=='cannot bind owned TCP DNS listener'
        assert any(frame.get('controller_failure_collection',{}).get('journal',{}).get('phase')=='collected' for frame in frames)
        collision=self.source_audit(frozen,owner);self.verify_quarantine(frozen,recovered['revision']+1,collision['inet_table'])
        self.report['failed_exact_port_recovery']={'frames':frames,'native':collision,'records':self.records()}
        current=self.target_runtime();assert current['Id']==original['Id'] and current['State']['Running'] and current['State']['Pid']==original['State']['Pid'] and current['State']['StartedAt']==original['State']['StartedAt']
        records=self.records();assert records['sandbox']['state']=='starting' and records['network']['phase']=='bound'
        assert not any(row['kind']=='create' and row['state']=='succeeded' for row in records['operations'])
        self.owned(json.loads(self.docker('inspect',blocker).stdout)[0]);self.docker('rm','--force','--volumes',blocker)
        logs=[json.loads(line) for line in self.docker('logs',self.upstream_id).stdout.splitlines()]
        assert not any(row.get('unexpected_query') for row in logs);self.report['owned_dns_spy']['logs']=logs
        self.owned(json.loads(self.docker('inspect',self.upstream_id).stdout)[0]);self.docker('rm','--force','--volumes',self.upstream_id)
        self.check('an_occupied_original_DNS_port_fences_recovery_without_selecting_new_ports_or_losing_the_complete_deny_floor')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',required=True);parser.add_argument('--worker-binary',required=True);parser.add_argument('--readback-binary',required=True)
    parser.add_argument('--runtime',choices=['runc','runsc'],default='runc');parser.add_argument('--mode',choices=['full'],default='full')
    parser.add_argument('--image',default='goldenhoop-network-fixture:test');parser.add_argument('--agent-image',default='goldenhoop-agent:test');parser.add_argument('--controller-image',default='goldenhoop-egress:test')
    parser.add_argument('--work-dir',required=True);parser.add_argument('--output',required=True);parser.add_argument('--remove-image',action='store_true')
    Contract(parser.parse_args()).run()
