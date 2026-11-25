"""Actual production-driver quarantined create/start and production-worker collection."""
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
from worker_network_recovery_contract import Contract as RecoveryContract
from guarded_bootstrap_samples import UPSTREAM

SOURCE_AUDIT = r'''
import datetime,json,pathlib,re,subprocess,sys,uuid
receipt=json.loads(sys.argv[1]);owner=sys.argv[2];allocation=receipt['allocation'];scope=receipt['source'];ep=scope['endpoint']
assert re.fullmatch('goldenhoop:[0-9a-f]{64}',owner)
assert re.fullmatch('ghn[0-9a-f]{12}',allocation['bridge']) and re.fullmatch('[a-z0-9_-]{2,15}',ep['port'])
root=pathlib.Path('/sys/class/net');bridge=root/allocation['bridge'];port=root/ep['port']
ports=list((bridge/'brif').iterdir());assert len(ports)==1 and ports[0].name==ep['port']
assert ports[0].is_symlink() and ports[0].resolve()==(port/'brport').resolve()
assert int((bridge/'ifindex').read_text())==allocation['ifindex'] and (bridge/'ifalias').read_text().strip()==owner
assert int((port/'ifindex').read_text())==ep['ifindex'] and int((port/'master/ifindex').read_text())==allocation['ifindex']
assert (bridge/'address').read_text().strip()==scope['gateway_mac']
p=subprocess.run(['ip','--json','addr','show','dev',allocation['bridge']],capture_output=True,text=True,timeout=5);assert p.returncode==0,p.stderr
addresses=[address['local'] for link in json.loads(p.stdout) for address in link.get('addr_info',[]) if address.get('family') in ('inet','inet6')]
assert scope['gateway4'] in addresses and (scope['gateway6'] is None or scope['gateway6'] in addresses)
table='gh_s_'+uuid.UUID(allocation['generation']).hex
p=subprocess.run(['nft','--json','list','table','bridge',table],capture_output=True,text=True,timeout=5);assert p.returncode==0,p.stderr
native=json.loads(p.stdout);tables=[row['table'] for row in native['nftables'] if 'table' in row]
assert len(tables)==1 and tables[0]['family']=='bridge' and tables[0]['name']==table
chains=[row['chain']['name'] for row in native['nftables'] if 'chain' in row]
assert owner.replace(':','_') in chains and 'source_version_1' in chains
result={'observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'bridge':allocation['bridge'],'bridge_ifindex':int((bridge/'ifindex').read_text()),'port':ep['port'],'port_ifindex':int((port/'ifindex').read_text()),'port_target':str(ports[0].resolve()),'gateway_addresses':addresses,'source_table':native}
if 'destinations' in receipt:
 table='gh_d_'+uuid.UUID(allocation['generation']).hex
 p=subprocess.run(['nft','--json','list','table','inet',table],capture_output=True,text=True,timeout=5);assert p.returncode==0,p.stderr
 result['destination_table']=json.loads(p.stdout)
 chains=[row['chain']['name'] for row in result['destination_table']['nftables'] if 'chain' in row]
 assert owner.replace(':','_') in chains and 'destination_version_2' in chains
 table='gh_e_'+uuid.UUID(allocation['generation']).hex
 p=subprocess.run(['nft','--json','--numeric','list','table','inet',table],capture_output=True,text=True,timeout=5);assert p.returncode==0,p.stderr
 result['inet_table']=json.loads(p.stdout)
print(json.dumps(result))
'''


class Contract(RecoveryContract):
    def __init__(self, args):
        super().__init__(args)
        self.report['suite'] = 'production-driver-quarantined-bootstrap'
        self.report['scope'] = 'Actual trusted-agent bootstrap under owned inet/Ethernet denial, or explicit unsupported-kernel refusal; Starting is not workload Ready; production worker collects all owned resources'
        self.report['runtime'] = args.runtime
        self.report['mode'] = args.mode
        self.report['source_files_sha256']['tests/guarded_bootstrap_contract.py'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        self.worker_started = False
        self.upstream = None
        samples=Path(__file__).with_name('guarded_bootstrap_samples.py')
        self.report['source_files_sha256']['tests/guarded_bootstrap_samples.py']=hashlib.sha256(samples.read_bytes()).hexdigest()

    def invoke(self, action, *extra, expected=0):
        if action == 'init':
            extra = ('--runtime', self.args.runtime, '--ttl-seconds', '3600' if self.args.mode=='full' else '600', '--workload-image', self.args.image, *extra)
        if action.startswith('controller-'):
            extra = ('--controller-generation', self.controller_generation, *extra)
            if action == 'controller-create':
                extra = ('--controller-image', self.controller_image_id, *extra)
        if action == 'controller-run':
            extra = ('--bootstrap-workload', *extra)
            if self.args.mode == 'unavailable':
                extra = ('--bootstrap-expect-bridge-unavailable', *extra)
            elif self.args.mode == 'prepared-exit':
                extra = ('--bootstrap-stop-after-prepare', *extra)
            else:
                assert self.upstream
                extra = ('--bootstrap-dns-upstream', self.upstream, *extra)
        try:
            return ProviderContract.invoke(self, action, *extra, expected=expected)
        except BaseException:
            if action in ('controller-create','controller-run','controller-resume') and self.report['invocations'][-1]['timed_out']:
                self.creation_uncertain = True
                self.settled = False
            raise

    def target_runtime(self):
        identities = self.docker('ps','-a','--no-trunc','--filter','label=dev.goldenhoop.sandbox='+self.sandbox,
                                 '--filter','label=dev.goldenhoop.role=sandbox','--format','{{.ID}}').stdout.split()
        assert len(identities) <= 1
        if not identities:
            return None
        actual = json.loads(self.docker('inspect',identities[0]).stdout)[0]
        self.owned(actual)
        assert actual['Config']['Labels']['dev.goldenhoop.profile'] == self.plan['identity']['profile']
        return actual

    def source_audit(self, receipt, owner):
        name='goldenhoop-source-binding-audit-'+uuid.uuid4().hex[:12]
        try:
            result=self.docker('run','--rm','--name',name,'--label','dev.goldenhoop.installation='+self.installation,
                '--label','dev.goldenhoop.role=network-provider-audit','--label','dev.goldenhoop.test=network-provider',
                '--label','dev.goldenhoop.attempt='+self.attempt,'--runtime','runc','--network','host','--user','0:0',
                '--cap-drop','ALL','--cap-add','NET_ADMIN','--security-opt','no-new-privileges:true','--read-only',
                '--memory','128m','--memory-swap','128m','--cpus','0.25','--pids-limit','32','--entrypoint','python3',
                self.report['fixture_image_id'],'-B','-c',SOURCE_AUDIT,json.dumps(receipt),owner)
        except subprocess.TimeoutExpired:
            self.creation_uncertain=True;self.settled=False
            raise
        observed=json.loads(result.stdout)
        assert not self.docker('ps','-a','--filter','name=^/'+name+'$','--format','{{.ID}}').stdout.strip()
        return observed

    def runtime_events(self, since, until):
        return [json.loads(line) for line in self.docker('events','--since',since,'--until',until,'--filter','type=container',
                '--filter','label=dev.goldenhoop.sandbox='+self.sandbox,'--format','{{json .}}').stdout.splitlines()]

    def after_startup(self):
        """Additional recovery contracts run after startup events are saved."""

    def start_upstream(self):
        self.upstream_id=self.docker('run','--detach','--name','goldenhoop-bootstrap-dns-'+self.attempt,
            '--label','dev.goldenhoop.installation='+self.installation,'--label','dev.goldenhoop.role=network-provider-audit',
            '--label','dev.goldenhoop.test=network-provider','--label','dev.goldenhoop.attempt='+self.attempt,
            '--runtime','runc','--network','host','--user','1000:1000','--cap-drop','ALL',
            '--security-opt','no-new-privileges:true','--read-only','--no-healthcheck','--memory','64m','--memory-swap','64m',
            '--cpus','0.25','--pids-limit','16','--entrypoint','python3',self.report['fixture_image_id'],'-B','-u','-c',UPSTREAM).stdout.strip()
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            logs=[json.loads(line) for line in self.docker('logs',self.upstream_id).stdout.splitlines()]
            ready=next((row for row in logs if row.get('ready')),None)
            if ready:
                self.upstream=ready['endpoint'];self.report['owned_dns_spy']={'container_id':self.upstream_id,'endpoint':self.upstream};return
            time.sleep(0.05)
        raise RuntimeError('owned bootstrap DNS spy did not start')

    def recover_with_worker(self):
        assert self.controller_image_id and self.plan and not self.creation_uncertain
        if self.worker is None:
            self.log_handle = self.worker_log.open('ab')
            command = [self.args.worker_binary,'--database',str(self.database),'worker','--agent-image',self.args.agent_image,
                       '--allow-runc-development','--egress-controller-image',self.controller_image_id]
            self.worker = subprocess.Popen(command,stdout=self.log_handle,stderr=subprocess.STDOUT,
                                           creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            self.report['worker_command'] = command
            self.worker_started = True
        deadline = time.monotonic()+100
        while True:
            assert self.worker.poll() is None, 'production worker exited before collection'
            current = self.records()
            if current['sandbox']['cleanup']=='complete' and current['network']['phase']=='collected' and all(row['phase']=='collected' for row in current['controllers']):
                self.report['after_worker_recovery'] = current
                return current
            if time.monotonic()>deadline:
                self.report['last_recovery_records'] = current
                raise RuntimeError('production worker did not confirm bootstrap collection')
            time.sleep(0.25)

    def run(self):
        failure = None
        try:
            fixture = json.loads(self.docker('image','inspect',self.args.image).stdout)[0]
            assert fixture['Config']['Labels']['dev.goldenhoop.fixture']=='network-interop'
            self.report['fixture_image_id'] = fixture['Id']
            controller = json.loads(self.docker('image','inspect',self.args.controller_image).stdout)[0]
            assert controller['Config']['Labels']['dev.goldenhoop.egress']=='host-netfilter'
            self.controller_image_id = controller['Id']
            self.report['controller_image_id'] = self.controller_image_id
            self.invoke('init','--fault-after-create',expected=75)
            self.settled = True
            recovered = self.invoke('recover')
            native = self.audit()
            assert native['bridge_exists'] and native['ifindex']>0 and not native['owned_tables']
            self.invoke('native','--native-ifindex',str(native['ifindex']))
            self.report['native_checkpoint_recovered_from_file_database'] = self.records()['network']
            self.check('a_real_file_database_and_owned_native_checkpoint_precede_runtime_creation')
            preflight=self.docker('run','--rm','--name','goldenhoop-bootstrap-preflight-'+self.attempt,
                    '--label','dev.goldenhoop.installation='+self.installation,'--label','dev.goldenhoop.role=network-provider-audit',
                    '--label','dev.goldenhoop.test=network-provider','--label','dev.goldenhoop.attempt='+self.attempt,
                    '--runtime','runc','--network','host','--user','0:0','--cap-drop','ALL','--cap-add','NET_ADMIN',
                    '--security-opt','no-new-privileges:true','--read-only','--memory','128m','--memory-swap','128m',
                    '--cpus','0.25','--pids-limit','32','--entrypoint','/usr/sbin/nft',self.args.image,
                    '--check','add','table','bridge','gh_bootstrap_'+self.attempt,check=False)
            self.report['actual_bridge_family_preflight']={'exit_code':preflight.returncode,'stdout':preflight.stdout,'stderr':preflight.stderr,'check_only':True}
            if self.args.mode=='unavailable':
                assert preflight.returncode!=0 and 'not supported' in preflight.stderr.lower()
            else:
                assert preflight.returncode==0,preflight.stderr
            since = datetime.now(timezone.utc).isoformat()
            if self.args.mode=='full':self.start_upstream()
            self.invoke('controller-create')
            result = self.invoke('controller-run',expected=79 if self.args.mode=='prepared-exit' else 0)
            if self.args.mode=='prepared-exit':
                prepared = next(row['bootstrap_prepared'] for row in self.report['invocations'][-1]['frames'] if 'bootstrap_prepared' in row)
                assert prepared['stored']['state']=='starting' and prepared['observation']['state']=='starting'
                self.report['prepared_exit_checkpoint'] = prepared
                self.check('actual_exit_79_leaves_the_original_runtime_identity_committed_before_any_start_request')
            else:
                bootstrap = result['exchange']['bootstrap']
                assert bootstrap['missing_floor_refused_before_creation'] and not bootstrap['workload_ready']
                self.report['bootstrap_result'] = bootstrap
                self.report['bootstrap_native_alias'] = result['exchange']['native_alias']
                self.check('an_inet_deny_table_without_the_Ethernet_floor_refuses_runtime_creation')
            actual = self.target_runtime()
            if self.args.mode=='unavailable':
                assert actual is None and bootstrap['mode']=='unsupported_bridge_refusal'
                self.check('the_unsupported_bridge_kernel_refuses_before_creating_or_starting_a_workload')
            else:
                assert actual
                config=actual['Config'];host=actual['HostConfig']
                assert config['Entrypoint']==['/opt/goldenhoop/goldenhoop-agent','serve']
                assert config['Healthcheck']['Test']==['NONE'] and not config.get('Cmd') and config['User']=='0:0'
                assert config['Entrypoint'] != fixture['Config'].get('Entrypoint')
                assert host['NetworkMode']==recovered['provider']['network_id'] and host['Runtime']==self.args.runtime
                assert not host['Privileged'] and host['ReadonlyRootfs'] and host['CapDrop']==['ALL']
                assert set(host['CapAdd'])=={'SETUID','SETGID','KILL','CHOWN','FOWNER','DAC_OVERRIDE'}
                assert len(actual['Mounts'])==1 and actual['Mounts'][0]['Destination']=='/opt/goldenhoop' and not actual['Mounts'][0]['RW']
                assert json.loads(config['Labels']['dev.goldenhoop.workload-network-plan'])['native']['expires_at']==self.plan['expires_at']
                self.report['independent_runtime_inspection'] = actual
                self.check('independent_inspection_confirms_the_fixed_trusted_supervisor_disabled_image_hooks_and_exact_owned_network')
                if self.args.mode=='prepared-exit':
                    assert actual['State']['Status']=='created' and not actual['State']['Running'] and actual['State']['Pid']==0
                    self.check('the_prepared_runtime_is_still_unstarted_after_the_producer_exits')
                else:
                    assert actual['State']['Running'] and actual['State']['Pid']>0
                    assert bootstrap['none_network_fallback_refused'] and bootstrap['duplicate_start_refused'] and bootstrap['nonempty_bootstrap_refused']
                    link=next(iter(actual['NetworkSettings']['Networks'].values()))
                    assert link['EndpointID']==bootstrap['endpoint']['endpoint_id'] and link['MacAddress']==bootstrap['endpoint']['mac']
                    assert link['IPAddress']==bootstrap['endpoint']['ipv4'] and link['GlobalIPv6Address']==bootstrap['endpoint']['ipv6']
                    assert not bootstrap['user_execution_dispatched'] and bootstrap['guard']['ethernet_guarded'] and not bootstrap['guard']['uncertain']
                    self.check('actual_supervisor_start_cross_checks_the_sole_endpoint_and_refuses_duplicate_or_none_network_startup')
                    source=bootstrap['source_binding']
                    assert source['allocation']==bootstrap['network']['native']['allocation'] and source['revision']+1==bootstrap['guard']['revision']
                    assert source['source']['endpoint']['mac']==link['MacAddress'] and source['source']['endpoint']['ipv4']==link['IPAddress'] and source['source']['endpoint']['ipv6']==link['GlobalIPv6Address']
                    assert bootstrap['duplicate_source_binding_refused'] and bootstrap['guard']['source_guarded']
                    self.report['independent_native_source_binding']=self.source_audit(source,result['exchange']['native_alias']['alias'])
                    self.check('the_provider_addresses_bind_to_the_unique_actual_host_port_and_an_independently_owned_source_table')
                    binding=bootstrap['protected_binding']
                    assert binding['source']==source['source'] and binding['allocation']==source['allocation'] and binding['revision']==bootstrap['guard']['revision']
                    assert binding['expires_at']==self.plan['expires_at'] and bootstrap['duplicate_protection_refused'] and bootstrap['guard']['destinations_guarded']
                    assert len(binding['destinations']['dns'])==2 and bootstrap['network_journal']['phase']=='bound'
                    assert bootstrap['network_journal']['binding']['destinations']==binding['destinations']
                    self.report['independent_protected_binding']=self.source_audit(binding,result['exchange']['native_alias']['alias'])
                    logs=[json.loads(line) for line in self.docker('logs',self.upstream_id).stdout.splitlines()]
                    assert not any(row.get('unexpected_query') for row in logs)
                    self.report['owned_dns_spy']['logs']=logs
                    self.owned(json.loads(self.docker('inspect',self.upstream_id).stdout)[0]);self.docker('rm','--force','--volumes',self.upstream_id)
                    self.check('live_DNS_tasks_and_actual_destination_rules_bind_the_original_one_hour_expiry_without_a_lease_or_upstream_query')
            before=self.records()
            assert before['sandbox']['state'] in ('pending','starting')
            assert not any(row['kind']=='create' and row['state']=='succeeded' for row in before['operations'])
            with closing(sqlite3.connect(self.database.as_uri()+'?mode=ro',uri=True,timeout=2)) as connection:
                assert connection.execute('SELECT COUNT(*) FROM executions WHERE sandbox_id=?',(self.sandbox,)).fetchone()[0]==0
            self.report['before_worker_recovery']={'records':before,'native':self.audit()}
            self.check('neither_runtime_state_nor_an_endpoint_publishes_Ready_or_a_successful_create_operation')
            # Capture target startup before the worker's unrelated profile probes.
            # Docker retains only the last 256 historical daemon events.
            startup_until=datetime.now(timezone.utc).isoformat()
            events=self.runtime_events(since,startup_until)
            creates=[e for e in events if e['Action']=='create' and e['Actor']['Attributes'].get('dev.goldenhoop.role')=='sandbox']
            starts=[e for e in events if e['Action']=='start' and e['Actor']['Attributes'].get('dev.goldenhoop.role')=='sandbox']
            self.report['target_runtime_events']={'since':since,'until':startup_until,'events':events,'runtime_creates':len(creates),'runtime_starts':len(starts),'capture_phase':'before production worker probes'}
            self.save()
            assert len(creates)==(0 if self.args.mode=='unavailable' else 1)
            assert len(starts)==(1 if self.args.mode=='full' else 0)
            self.after_startup()
            current=self.recover_with_worker()
            assert current['sandbox']['state']=='terminated' and not any(row['kind']=='create' and row['state']=='succeeded' for row in current['operations'])
            assert current['profiles'] and all(not {'network_policy','secret_injection'}.intersection(p['capabilities']) for p in current['profiles'])
            final=self.audit();assert not final['bridge_exists'] and not final['owned_tables']
            self.report['independent_native_absence_after_worker_recovery']=final
            until=datetime.now(timezone.utc).isoformat()
            self.report['target_recovery_events']={'since':startup_until,'until':until,'events':self.runtime_events(startup_until,until)}
            self.check('the_production_worker_collects_the_exact_bootstrap_runtime_controller_bridge_and_owned_rules')
            self.check('actual_Docker_events_match_the_single_runtime_creation_and_expected_start_count')
            self.report['result']='passed'
        except BaseException as error:
            failure=error;self.report['error']=repr(error);self.failure_observation()
            if self.database.exists() and self.sandbox:
                try:self.report['failure_recovery_records']=self.records()
                except BaseException as diagnostic:self.report['failure_records_error']=repr(diagnostic)
        finally:
            # Retry actual recovery on a harness failure before destructive test cleanup.
            if failure and self.controller_image_id and self.plan and not self.creation_uncertain:
                try:
                    if self.records()['network'].get('native'):
                        self.recover_with_worker()
                except BaseException as error:
                    self.report['failure_recovery_error']=repr(error)
            try:
                self.stop_worker()
            except BaseException as error:
                failure=failure or error;self.report.update(result='failed',cleanup='unknown',worker_stop_error=repr(error))
            if self.worker is None:
                try:
                    ProviderContract.cleanup(self)
                    self.report['cleanup']='complete'
                except BaseException as error:
                    failure=failure or error;self.report.update(result='failed',cleanup='unknown',cleanup_error=repr(error))
            self.save()
            print(json.dumps({k:self.report.get(k) for k in ('result','cleanup','error','cleanup_error','worker_stop_error')}),flush=True)
        if failure:raise failure


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',required=True);p.add_argument('--worker-binary',required=True)
    p.add_argument('--image',default='goldenhoop-network-fixture:test');p.add_argument('--agent-image',default='goldenhoop-agent:test')
    p.add_argument('--controller-image',default='goldenhoop-egress:test')
    p.add_argument('--runtime',choices=['runc','runsc'],default='runc');p.add_argument('--mode',choices=['full','prepared-exit','unavailable'],default='full')
    p.add_argument('--work-dir',required=True);p.add_argument('--output',required=True);p.add_argument('--remove-image',action='store_true')
    Contract(p.parse_args()).run()
