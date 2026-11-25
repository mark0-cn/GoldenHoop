"""Actual full protected policy/renewal/tightening and expired-lease quarantine."""
import argparse
import copy
import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import datetime,timezone
from pathlib import Path
from dns_recovery_contract import Contract as RecoveryContract


class Contract(RecoveryContract):
    def __init__(self,args):
        super().__init__(args);self.report['suite']='production-driver-effective-protected-policy'
        self.report['scope']='Actual protected source/DNS/destination binding, held-session policy apply/renew/replace, finite lease expiry and quarantine. No worker Ready, user commands or capability publication.'
        self.report['source_files_sha256']['tests/effective_policy_contract.py']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    def after_startup(self):
        frozen=self.report['bootstrap_result']['protected_binding'];original=self.target_runtime();assert original and original['State']['Running']
        self.collect_epoch();owner=self.report['bootstrap_native_alias']['alias']
        before=self.source_audit(frozen,owner);self.verify_quarantine(frozen,frozen['revision'],before['inet_table'])
        self.report['initial_owned_dns_spy']=copy.deepcopy(self.report['owned_dns_spy']);self.start_upstream();self.new_epoch(frozen)
        since=datetime.now(timezone.utc).isoformat()
        resumed=self.invoke('controller-resume','--controller-resume-binding-json',json.dumps(frozen),'--recovery-dns-upstream',self.upstream,'--effective-policy-contract')
        result=resumed['exchange']['resume'];case=result['effective_policy'];assert resumed['packet_permissions_granted'] and not resumed['workload_publication'] and not result['workload_ready']
        recovered=result['recovered_binding'];assert recovered['revision']==frozen['revision']+1
        for name in ['applied','renewed','replaced']:
            receipt=case[name];binding=receipt['binding']
            assert binding['allocation']==frozen['allocation'] and binding['source']==frozen['source'] and binding['destinations']==frozen['destinations'] and binding['expires_at']==frozen['expires_at']
            assert 0<receipt['lease_remaining_milliseconds']<=10000 and len(receipt['config_sha256'])==len(receipt['native_sha256'])==64
        assert case['applied']['binding']['revision']==recovered['revision']+1 and case['renewed']['binding']['revision']==case['applied']['binding']['revision']
        assert case['applied']['config_sha256']==case['renewed']['config_sha256'] and case['duplicate_apply_refused']
        self.report['actual_effective_policy']=resumed;self.check('actual_full_policy_and_renewal_receipts_bind_the_same_native_floors_DNS_tuples_and_original_expiry')
        assert case['replaced']['binding']['revision']==case['renewed']['binding']['revision']+1 and case['replaced']['config_sha256']!=case['renewed']['config_sha256']
        assert case['tightened_config']['policies']==[{'default_action':'deny','rules':[]}]
        self.check('tightening_replaces_the_complete_effective_policy_and_clears_prior_permission_at_a_new_revision')
        quarantine=case['final_quarantine'];assert quarantine['revision']==case['replaced']['binding']['revision']+1
        assert case['expired_driver_renew_refused_before_dispatch'] and case['actual_expired_kernel_renewal']['code']=='conflict' and case['actual_expired_observation']['uncertain'] and case['quarantine_cannot_issue_effective_receipt']
        after=self.source_audit(quarantine,owner);self.verify_quarantine(quarantine,quarantine['revision'],after['inet_table'])
        for name in ['source_table','destination_table']:
            assert next(row['table'] for row in before[name]['nftables'] if 'table' in row)==next(row['table'] for row in after[name]['nftables'] if 'table' in row)
        self.report['independent_final_policy_quarantine']=after
        self.check('actual_kernel_lease_expiry_refuses_direct_renewal_and_requires_fresh_complete_quarantine')
        current=self.target_runtime();assert current['Id']==original['Id'] and current['State']['Pid']==original['State']['Pid'] and current['State']['StartedAt']==original['State']['StartedAt']
        events=self.runtime_events(since,datetime.now(timezone.utc).isoformat());assert not [e for e in events if e['Action'] in ('create','start') and e['Actor']['Attributes'].get('dev.goldenhoop.role')=='sandbox']
        with closing(sqlite3.connect(self.database.as_uri()+'?mode=ro',uri=True,timeout=2)) as db:assert db.execute('SELECT COUNT(*) FROM executions WHERE sandbox_id=?',(self.sandbox,)).fetchone()[0]==0
        records=self.records();assert records['sandbox']['state']=='starting' and not any(row['kind']=='create' and row['state']=='succeeded' for row in records['operations'])
        logs=[json.loads(line) for line in self.docker('logs',self.upstream_id).stdout.splitlines()];assert not any(row.get('unexpected_query') for row in logs)
        self.report['owned_dns_spy']['logs']=logs;self.owned(json.loads(self.docker('inspect',self.upstream_id).stdout)[0]);self.docker('rm','--force','--volumes',self.upstream_id)
        self.check('held_policy_transitions_never_restart_the_runtime_publish_Ready_dispatch_user_commands_or_query_the_upstream')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',required=True);p.add_argument('--worker-binary',required=True);p.add_argument('--readback-binary',required=True)
    p.add_argument('--runtime',choices=['runc','runsc'],default='runc');p.add_argument('--mode',choices=['full'],default='full')
    p.add_argument('--image',default='goldenhoop-network-fixture:test');p.add_argument('--agent-image',default='goldenhoop-agent:test');p.add_argument('--controller-image',default='goldenhoop-egress:test')
    p.add_argument('--work-dir',required=True);p.add_argument('--output',required=True);p.add_argument('--remove-image',action='store_true')
    Contract(p.parse_args()).run()
