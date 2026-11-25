"""Actual destination-plan install/readback on an empty owned bridge; no packet acceptance claim."""
import argparse
import hashlib
import ipaddress
import json
import subprocess
import uuid
from datetime import datetime,timezone
from pathlib import Path


def run(args):
    root=Path(__file__).resolve().parents[1];attempt=uuid.uuid4().hex
    bridge='ghdp'+attempt[:10];table='gh_d_'+attempt
    helper='goldenhoop-destination-plan-'+attempt
    labels=['--label','dev.goldenhoop.test=network-contract','--label','dev.goldenhoop.attempt='+attempt]
    report={'timestamp':datetime.now(timezone.utc).isoformat(),'suite':'destination-plan-native-readback','scope':'real immutable inet floor on an empty owned internal bridge; no workload, DNS grant or runtime capability','attempt':attempt,'result':'failed','cleanup':'pending'}
    owner=None;network=None
    def docker(*values,check=True,input=None):
        return subprocess.run(['docker',*values],input=input,capture_output=True,check=check,timeout=30)
    def execute(*values,check=True,input=None):return docker('exec','--interactive',helper,*values,check=check,input=input)
    def tables():return json.loads(execute('nft','--json','list','tables').stdout)['nftables']
    def present():return any(e.get('table',{}).get('family')=='inet' and e['table']['name']==table for e in tables())
    def compile_(value):
        result=subprocess.run([args.plan_exe],input=json.dumps(value).encode(),capture_output=True,timeout=20)
        return result
    try:
        image=json.loads(docker('image','inspect',args.image).stdout)[0]
        assert image['Config']['Labels'].get('dev.goldenhoop.fixture')=='network-interop'
        report['image_id']=image['Id']
        prefix=f'fd{attempt[:2]}:{attempt[2:6]}:{attempt[6:10]}:9::/64'
        network=docker('network','create',*labels,'--driver','bridge','--internal','--ipv6','--subnet',prefix,'--opt','com.docker.network.bridge.name='+bridge,'goldenhoop-destination-net-'+attempt).stdout.decode().strip()
        observed=json.loads(docker('network','inspect',network).stdout)[0]
        assert observed['Internal'] and not observed['Containers'] and observed['Labels']['dev.goldenhoop.attempt']==attempt
        docker('run','--detach','--name',helper,*labels,'--runtime','runc','--network','host','--user','0:0','--cap-drop','ALL','--cap-add','NET_ADMIN','--security-opt','no-new-privileges:true','--read-only','--memory','128m','--memory-swap','128m','--cpus','0.25','--pids-limit','32','--entrypoint','python3',args.image,'-c','import time;time.sleep(3600)')
        link=json.loads(execute('ip','-json','link','show','dev',bridge).stdout)[0]
        gateways=[str(ipaddress.ip_address(c['Gateway'])) for c in observed['IPAM']['Config']]
        gateways.sort(key=lambda s:ipaddress.ip_address(s).version)
        value={'allocation':{'installation_id':str(uuid.uuid4()),'sandbox_id':str(uuid.uuid4()),'generation':str(uuid.UUID(attempt)),'bridge':bridge,'ifindex':link['ifindex']},'definition':{'scope':{'host_addresses':gateways,'control_addresses':['203.0.113.9','2001:db8::9'],'private_exceptions':['10.20.0.0/16','fd42::/16']},'dns':[{'address':ip,'port':15053} for ip in gateways]}}
        report['input']=value;report['network']={'id':network,'bridge':bridge,'ifindex':link['ifindex'],'internal':True,'endpoints':0}
        compiled=compile_(value);assert compiled.returncode==0,compiled.stderr
        script=compiled.stdout;assert 1000<len(script)<512*1024
        owner=script.decode().splitlines()[1].split()[-1];assert owner.startswith('goldenhoop_') and len(owner)==75
        report['script_sha256']=hashlib.sha256(script).hexdigest()
        assert not present()
        program="import hashlib,json,subprocess,sys;s=sys.stdin.buffer.read();assert len(s)>1000;r=subprocess.run(['nft','--file','-'],input=s,capture_output=True);print(json.dumps({'stdin_bytes':len(s),'stdin_sha256':hashlib.sha256(s).hexdigest(),'exit_code':r.returncode,'stderr':r.stderr.decode(errors='replace')[:16000]}))"
        installed=json.loads(execute('python3','-c',program,input=script).stdout)
        report['installation']=installed
        assert installed['stdin_bytes']==len(script) and installed['stdin_sha256']==report['script_sha256']
        assert installed['exit_code']==0,installed
        observation=json.loads(execute('nft','--json','list','table','inet',table).stdout)
        report['observation']=observation
        verify=compile_({**value,'observation':observation})
        report['verification']={'exit_code':verify.returncode,'stderr':verify.stderr.decode(errors='replace')[:4096]}
        assert verify.returncode==0 and json.loads(verify.stdout)=={'verified':True},report['verification']
        assert not json.loads(docker('network','inspect',network).stdout)[0]['Containers']
        report['result']='passed'
    except BaseException as exc:
        report['error']=repr(exc)
        raise
    finally:
        errors=[]
        try:
            state=docker('inspect',helper,check=False)
            if state.returncode==0:
                labels_=json.loads(state.stdout)[0]['Config']['Labels'];assert labels_.get('dev.goldenhoop.attempt')==attempt
                if present():
                    value_=json.loads(execute('nft','--json','list','table','inet',table).stdout)
                    owners=[e['chain']['name'] for e in value_['nftables'] if 'chain' in e and e['chain']['name'].startswith('goldenhoop_')]
                    assert owner is not None and owners==[owner],owners
                    execute('nft','delete','table','inet',table)
                assert not present();report['owned_table_absent']=True
        except BaseException as exc:errors.append(repr(exc))
        try:
            remaining=docker('ps','-a','--filter','label=dev.goldenhoop.attempt='+attempt,'--format','{{.ID}}').stdout.decode().splitlines()
            for identity in remaining:
                obj=json.loads(docker('inspect',identity).stdout)[0];assert obj['Config']['Labels'].get('dev.goldenhoop.attempt')==attempt and obj['Config']['Labels'].get('dev.goldenhoop.test')=='network-contract';docker('rm','--force','--volumes',identity)
            networks=docker('network','ls','--filter','label=dev.goldenhoop.attempt='+attempt,'--format','{{.ID}}').stdout.decode().splitlines()
            for identity in networks:
                obj=json.loads(docker('network','inspect',identity).stdout)[0];assert obj['Labels'].get('dev.goldenhoop.attempt')==attempt and obj['Labels'].get('dev.goldenhoop.test')=='network-contract' and not obj['Containers'];docker('network','rm',identity)
            for command in [('ps','-a'),('network','ls'),('volume','ls')]:
                fmt='{{.Name}}' if command[0]=='volume' else '{{.ID}}'
                assert not docker(*command,'--filter','label=dev.goldenhoop.attempt='+attempt,'--format',fmt).stdout.strip()
        except BaseException as exc:errors.append(repr(exc))
        report['cleanup']='complete' if not errors else 'failed'
        if errors:report['cleanup_errors']=errors;report['result']='failed'
        paths=[Path(__file__).resolve(),root/'crates/egress/src/destination_plan.rs',root/'crates/egress/src/destinations.rs',root/'crates/egress/examples/destination_plan.rs',root/'crates/egress/Cargo.toml',root/'Cargo.lock']
        report['source_files_sha256']={p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
        Path(args.output).parent.mkdir(parents=True,exist_ok=True);Path(args.output).write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
        print(json.dumps({k:report.get(k) for k in ['result','cleanup','error','cleanup_errors']}))
        if errors:raise RuntimeError('destination-plan cleanup unconfirmed: '+str(errors))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan-exe',required=True)
    parser.add_argument('--image',default='goldenhoop-network-fixture:test')
    parser.add_argument('--output',required=True)
    run(parser.parse_args())
