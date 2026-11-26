"""Trusted private-namespace producer; no workload Ready or execution grant."""
MANAGER=r'''
import datetime,hashlib,json,pathlib,subprocess,sys,time
value=json.loads(sys.argv[1]);allocation=value['allocation'];native=value['native_plan'];table='gh_e_'+allocation['generation'].replace('-','')
events=[];captures=[];sequence=0
p=subprocess.Popen(['/usr/local/libexec/goldenhoop-egress'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
def rpc(operation,*,error=False,**fields):
 global sequence
 sequence+=1;request={'id':sequence,'command':{'operation':operation,**fields}}
 p.stdin.write(json.dumps(request)+'\n');p.stdin.flush();line=p.stdout.readline();assert line,'missing explicit controller reply'
 reply=json.loads(line);assert reply['id']==sequence and ('error' in reply)==error,reply
 events.append({'request':request,'reply':reply,'at':datetime.datetime.now(datetime.timezone.utc).isoformat()})
 return reply.get('error' if error else 'result')
def nft(*args,input=None):
 result=subprocess.run(['nft',*args],input=input,capture_output=True,text=True,timeout=8);assert result.returncode==0,result.stderr;return result.stdout
def capture(kind):
 before=time.monotonic();text=nft('list','table','inet',table);after=time.monotonic();actual=json.loads(nft('--json','--numeric','list','table','inet',table));row={'kind':kind,'native':actual,'native_text':text,'read_seconds':after-before,'at':datetime.datetime.now(datetime.timezone.utc).isoformat()};captures.append(row);return actual
original_deadline=time.monotonic()+25
native['expires_at']=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=25)).isoformat()
try:
 rpc('bind_native',plan=native);rpc('open',allocation=allocation);rpc('install')
 rpc('configure_dns',expected_revision=0,upstream='127.0.0.1:19004');rpc('listen_dns',expected_revision=0)
 applied=rpc('apply',expected_revision=1,config=value['config']);assert applied['revision']==2 and not applied['uncertain']
 renewed=rpc('renew',expected_revision=2);assert renewed['revision']==2 and not renewed['uncertain'];capture('actual_applied_and_renewed_policy')
 refused=rpc('inspect_policy',expected_revision=2,error=True);assert refused['code']=='invalid_state'
 refused=rpc('renew_policy',expected_revision=2,error=True);assert refused['code']=='invalid_state'
 assert not rpc('inspect')['uncertain'],'refusing a partial allocation must not fabricate a protected receipt or mutate its existing basic lease'
 observation=rpc('inspect_credential_ingress');assert all(v==0 for v in observation.values()) and len(observation)==8
 nft('--file','-',input='flush chain inet '+table+' decision\nadd rule inet '+table+' decision counter accept\n')
 actual=capture('actual_tampered_same_revision_policy');assert any(row.get('set',{}).get('name')=='live' and row['set'].get('elem') for row in actual['nftables'])
 refused=rpc('renew',expected_revision=2,error=True);assert refused['code']=='conflict'
 observed=rpc('inspect');assert observed['uncertain']
 rpc('quarantine',expected_revision=2)
 deny={'policies':[{'default_action':'deny','rules':[]}]};rpc('apply',expected_revision=3,config=deny)
 time.sleep(10.5)
 actual=capture('actual_expired_global_lease');live=next(row['set'] for row in actual['nftables'] if row.get('set',{}).get('name')=='live');assert not live.get('elem')
 refused=rpc('renew',expected_revision=4,error=True);assert refused['code']=='conflict';assert rpc('inspect')['uncertain']
 rpc('quarantine',expected_revision=4)
 time.sleep(max(0,original_deadline-time.monotonic()-4))
 result=rpc('apply',expected_revision=5,config=deny);assert result['revision']==6 and not result['uncertain']
 actual=capture('actual_live_timeout_clipped_to_original_expiry');live=next(row['set'] for row in actual['nftables'] if row.get('set',{}).get('name')=='live');entry=live['elem'][0]['elem'];assert entry['val']==allocation['bridge'] and 0<=entry['expires']<=4 and 0<=entry['timeout']<=4
 time.sleep(max(0,original_deadline-time.monotonic()+.2))
 refused=rpc('renew',expected_revision=6,error=True);assert refused['code']=='deadline_exceeded'
 refused=rpc('apply',expected_revision=6,config=deny,error=True);assert refused['code']=='deadline_exceeded'
 actual=capture('actual_original_expiry_has_no_live_element');assert not next(row['set'] for row in actual['nftables'] if row.get('set',{}).get('name')=='live').get('elem')
finally:
 p.stdin.close()
 try:code=p.wait(timeout=5)
 except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5);raise
 stderr=p.stderr.read();assert code==0,stderr
print(json.dumps({'events':events,'captures':captures,'controller_exit_code':code,'original_native_plan':native,'full_protected_receipt_refused':True,'protected_renewal_refused':True,'ready':False}))
'''
