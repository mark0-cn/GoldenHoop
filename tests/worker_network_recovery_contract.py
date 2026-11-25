"""Real expired network recovery by the production worker, without workload publication."""
import argparse
import hashlib
import json
import sqlite3
import subprocess
import time
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from network_provider_contract import Contract as ProviderContract


class Contract(ProviderContract):
    def __init__(self, args):
        super().__init__(args)
        self.worker = None
        self.worker_log = self.state/'worker.log'
        self.log_handle = None
        self.controller_generation = str(uuid.uuid4())
        self.controller_image_id = None
        self.report['suite'] = 'production-worker-owned-network-recovery'
        self.report['scope'] = 'Actual wall-clock expiry, persisted controller intent, live owned quarantine table and production worker collection; no workload or NetworkPolicy publication'
        self.report['source_files_sha256']['tests/worker_network_recovery_contract.py'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        self.report['worker_binary_sha256'] = hashlib.sha256(Path(args.worker_binary).read_bytes()).hexdigest()

    def invoke(self, action, *extra, expected=0):
        if action == 'init':
            extra = ('--ttl-seconds', '45', *extra)
        if action.startswith('controller-'):
            extra = ('--controller-generation', self.controller_generation, *extra)
            if action == 'controller-create':
                extra = ('--controller-image', self.controller_image_id, *extra)
        try:
            return super().invoke(action, *extra, expected=expected)
        except BaseException:
            if action == 'controller-create' and self.report['invocations'][-1]['timed_out']:
                self.creation_uncertain = True
                self.settled = False
            raise

    def records(self):
        with closing(sqlite3.connect(self.database.as_uri()+'?mode=ro', uri=True, timeout=2)) as connection:
            sandbox = json.loads(connection.execute('SELECT payload FROM sandboxes WHERE id=?', (self.sandbox,)).fetchone()[0])
            network = json.loads(connection.execute('SELECT payload FROM network_allocations WHERE sandbox_id=?', (self.sandbox,)).fetchone()[0])
            controllers = [json.loads(row[0]) for row in connection.execute('SELECT payload FROM network_controllers WHERE sandbox_id=? ORDER BY controller_generation', (self.sandbox,))]
            operations = [{'kind':row[0], 'state':row[1]} for row in connection.execute('SELECT kind,state FROM operations WHERE resource_id=?', (self.sandbox,))]
            registration = connection.execute("SELECT value FROM meta WHERE key='worker'").fetchone()
            profiles = json.loads(registration[0])['profiles'] if registration else []
            return {'sandbox':sandbox, 'network':network, 'controllers':controllers, 'operations':operations, 'profiles':profiles}

    def owned(self, obj):
        labels = obj.get('Labels', obj.get('Config', {}).get('Labels', {}))
        if labels.get('dev.goldenhoop.role') != 'egress-controller':
            return super().owned(obj)
        assert labels['dev.goldenhoop.installation'] == self.installation
        assert labels['dev.goldenhoop.sandbox'] == self.sandbox
        plan = json.loads(labels['dev.goldenhoop.controller-plan'])
        with closing(sqlite3.connect(self.database.as_uri()+'?mode=ro', uri=True, timeout=2)) as connection:
            row = connection.execute('SELECT payload FROM network_controllers WHERE sandbox_id=? AND controller_generation=?', (self.sandbox,plan['controller_generation'])).fetchone()
            assert row
            record = json.loads(row[0])
        assert record['plan'] == plan and (record['container_id'] is None or record['container_id'] == obj['Id'])
        assert obj['Image'] == obj['Config']['Image'] == plan['image_id']
        assert obj['Name'] == '/goldenhoop-egress-'+plan['native']['identity']['generation'].replace('-', '')+'-'+plan['controller_generation'].replace('-', '')
        return labels

    def stop_worker(self):
        if self.worker:
            if self.worker.poll() is None:
                self.worker.terminate()
            self.worker.wait(timeout=15)
            assert self.worker.poll() is not None
            self.report['worker_process_stopped'] = True
            self.worker = None
        if self.log_handle:
            self.log_handle.close()
            self.log_handle = None
        if self.worker_log.exists():
            self.report['worker_log_tail'] = self.worker_log.read_text(encoding='utf-8', errors='replace')[-8192:]

    def cleanup(self):
        try:
            return super().cleanup()
        except BaseException as original:
            # The parent leaves the private journal intact if native rules remain.
            # A failed worker must not leave this test's revision-zero quarantine.
            if not (self.state.exists() and self.plan and self.controller_image_id and not self.creation_uncertain):
                raise
            observed = self.audit()
            if observed['bridge_exists'] or not observed['owned_tables']:
                raise
            self.report['failure_cleanup_initial_error'] = repr(original)
            allocation = self.records()['network']['native']['allocation']
            name = 'goldenhoop-worker-collection-helper-'+self.attempt
            command = ['docker','run','--rm','--interactive','--name',name,
                       '--label','dev.goldenhoop.installation='+self.installation,
                       '--label','dev.goldenhoop.role=network-provider-audit',
                       '--label','dev.goldenhoop.test=network-provider',
                       '--label','dev.goldenhoop.attempt='+self.attempt,
                       '--runtime','runc','--network','host','--user','0:0',
                       '--cap-drop','ALL','--cap-add','NET_ADMIN',
                       '--security-opt','no-new-privileges:true','--read-only',
                       '--memory','128m','--memory-swap','128m','--cpus','0.25','--pids-limit','32',
                       '--entrypoint','/usr/local/bin/goldenhoop-egress',self.controller_image_id,'--collection-only']
            frames = [{'id':index,'command':request} for index,request in enumerate(
                      ({'operation':'open','allocation':allocation},{'operation':'remove','expected_revision':0}),start=1)]
            result = subprocess.run(command,input=''.join(json.dumps(frame)+'\n' for frame in frames),
                                    capture_output=True,text=True,encoding='utf-8',timeout=30)
            replies = [json.loads(line) for line in result.stdout.splitlines()]
            self.report['failure_cleanup_scoped_manager'] = {'exit_code':result.returncode,'replies':replies,'stderr':result.stderr[-4096:]}
            self.save()
            assert result.returncode == 0 and len(replies) == 2
            assert [reply['id'] for reply in replies] == [frame['id'] for frame in frames]
            receipt = replies[-1]['result']
            assert receipt['allocation'] == allocation and receipt['bridge_absent'] and receipt['owned_tables_absent']
            super().cleanup()

    def run(self):
        failure = None
        try:
            image = json.loads(self.docker('image','inspect',self.args.image).stdout)[0]
            assert image['Config']['Labels']['dev.goldenhoop.fixture'] == 'network-interop'
            self.report['fixture_image_id'] = image['Id']
            controller_image = json.loads(self.docker('image','inspect',self.args.controller_image).stdout)[0]
            assert controller_image['Config']['Labels']['dev.goldenhoop.egress'] == 'host-netfilter'
            self.controller_image_id = controller_image['Id']
            self.report['controller_image_id'] = self.controller_image_id
            self.invoke('init','--fault-after-create',expected=75)
            self.settled = True
            recovered = self.invoke('recover')
            native = self.audit()
            assert native['bridge_exists'] and native['ifindex'] > 0 and not native['owned_tables']
            self.invoke('native','--native-ifindex',str(native['ifindex']))
            checkpoint = self.records()['network']
            assert checkpoint['native']['network_id'] == recovered['provider']['network_id']
            self.report['native_checkpoint_recovered_from_file_database'] = checkpoint
            self.check('actual_owned_provider_and_native_identity_are_checkpointed_before_privileged_writes')
            self.invoke('controller-create')
            produced = self.invoke('controller-run','--controller-leave-quarantine')
            assert produced['exchange']['quarantine']['installed'] and produced['exchange']['quarantine']['revision'] == 0
            assert produced['exited']['status'] == 'exited' and produced['exited']['exit_code'] == 0
            before = self.records()
            assert len(before['controllers']) == 1 and before['controllers'][0]['phase'] == 'running'
            observed = self.audit()
            assert observed['bridge_exists'] and len(observed['owned_tables']) == 1
            self.report['before_worker_recovery'] = {'records':before, 'actual_native':observed, 'producer_result':produced}
            self.check('an_actual_owned_quarantine_table_survives_the_successfully_exited_producer_controller')
            expires = datetime.fromisoformat(self.plan['expires_at'].replace('Z','+00:00'))
            while datetime.now(timezone.utc) <= expires:
                time.sleep(min(1,max(0.01,(expires-datetime.now(timezone.utc)).total_seconds())))
            expired = self.audit()
            assert expired['bridge_exists'] and expired['owned_tables']
            self.report['actual_expiry_before_worker_start'] = {'observed_at':datetime.now(timezone.utc).isoformat(),'expires_at':self.plan['expires_at'],'native':expired}
            self.check('real_absolute_expiry_occurs_before_worker_start_while_the_owned_native_resources_remain')
            self.log_handle = self.worker_log.open('wb')
            events_since = datetime.now(timezone.utc).isoformat()
            command = [self.args.worker_binary,'--database',str(self.database),'worker','--agent-image',self.args.agent_image,'--allow-runc-development','--egress-controller-image',self.controller_image_id]
            self.worker = subprocess.Popen(command,stdout=self.log_handle,stderr=subprocess.STDOUT,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            self.report['worker_command'] = command
            self.save()
            deadline = time.monotonic()+100
            while True:
                assert self.worker.poll() is None, 'worker exited before collection'
                current = self.records()
                if current['sandbox']['cleanup'] == 'complete' and current['network']['phase'] == 'collected' and all(row['phase']=='collected' for row in current['controllers']):
                    break
                if time.monotonic() > deadline:
                    self.report['last_recovery_records'] = current
                    raise RuntimeError('production worker did not confirm owned network collection')
                time.sleep(0.25)
            assert current['sandbox']['state'] == 'terminated' and current['sandbox']['desired_state'] == 'terminated'
            assert not any(row['kind']=='create' and row['state']=='succeeded' for row in current['operations'])
            assert len(current['controllers']) == 2
            collector = next(row for row in current['controllers'] if row['plan'].get('purpose') == 'collect')
            assert collector['plan']['native']['expires_at'] == self.plan['expires_at']
            assert collector['plan']['collection_deadline'] > collector['plan']['native']['expires_at']
            assert collector['absence']['provider_absent'] and collector['absence']['creation_settled'] and collector['absence']['start_settled']
            self.report['after_worker_recovery'] = current
            self.check('the_production_worker_commits_collection_intents_and_confirms_both_controller_processes_absent')
            self.check('a_separate_bounded_collection_controller_runs_after_user_expiry_without_extending_the_sandbox_deadline')
            final = self.audit()
            assert not final['bridge_exists'] and not final['owned_tables']
            self.report['independent_native_absence_after_worker_recovery'] = final
            self.check('independent_host_readback_confirms_the_bridge_and_all_owned_table_scopes_are_absent')
            events_until = datetime.now(timezone.utc).isoformat()
            events = [json.loads(line) for line in self.docker('events','--since',events_since,'--until',events_until,
                      '--filter','type=container','--filter','event=create','--filter','label=dev.goldenhoop.sandbox='+self.sandbox,
                      '--format','{{json .}}').stdout.splitlines()]
            assert events and all(event['Actor']['Attributes']['dev.goldenhoop.role']=='egress-controller' for event in events)
            assert any(json.loads(event['Actor']['Attributes']['dev.goldenhoop.controller-plan']).get('purpose')=='collect' for event in events)
            self.report['target_container_creation_events'] = {'since':events_since,'until':events_until,'events':events}
            assert not self.docker('ps','-a','--filter','label=dev.goldenhoop.sandbox='+self.sandbox,'--format','{{.ID}}').stdout.strip()
            assert current['profiles'] and all(not {'network_policy','secret_injection'}.intersection(profile['capabilities']) for profile in current['profiles'])
            self.check('terminal_network_recovery_never_publishes_a_none_network_workload_or_successful_create_operation')
            self.report['result'] = 'passed'
        except BaseException as error:
            failure = error
            self.report['error'] = repr(error)
            self.failure_observation()
            if self.database.exists() and self.sandbox:
                try:
                    self.report['failure_recovery_records'] = self.records()
                except BaseException as diagnostic:
                    self.report['failure_records_error'] = repr(diagnostic)
        finally:
            try:
                self.stop_worker()
            except BaseException as error:
                failure = failure or error
                self.report.update(result='failed',cleanup='unknown',worker_stop_error=repr(error))
            if self.worker is None:
                try:
                    self.cleanup()
                    self.report['cleanup'] = 'complete'
                except BaseException as error:
                    failure = failure or error
                    self.report.update(result='failed',cleanup='unknown',cleanup_error=repr(error))
            self.save()
            print(json.dumps({k:self.report.get(k) for k in ('result','cleanup','error','cleanup_error')}),flush=True)
        if failure:
            raise failure


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',required=True)
    parser.add_argument('--worker-binary',required=True)
    parser.add_argument('--image',default='goldenhoop-network-fixture:test')
    parser.add_argument('--agent-image',default='goldenhoop-agent:test')
    parser.add_argument('--controller-image',default='goldenhoop-egress:test')
    parser.add_argument('--work-dir',required=True)
    parser.add_argument('--output',required=True)
    parser.add_argument('--remove-image',action='store_true')
    Contract(parser.parse_args()).run()
