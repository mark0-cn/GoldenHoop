"""Read/check-only source-plan prerequisite; never a packet enforcement gate."""
import argparse
import hashlib
import json
import subprocess
import uuid
from datetime import datetime,timezone
from pathlib import Path

def run(args):
    data=json.loads(Path(args.input).read_text(encoding='utf-8'));data=data.get('input',data)
    attempt=uuid.uuid4().hex
    data['allocation']['generation']=str(uuid.UUID(attempt))
    data['allocation']['bridge']='ghpre'+attempt[:10]
    compiled=subprocess.run([args.plan_exe],input=json.dumps(data).encode(),capture_output=True,timeout=15)
    assert compiled.returncode==0,compiled.stderr
    script=compiled.stdout;assert 1000<len(script)<65536
    image=subprocess.run(['docker','image','inspect',args.image],capture_output=True,check=True)
    observed_image=json.loads(image.stdout)[0]
    assert observed_image['Config']['Labels'].get('dev.goldenhoop.fixture')=='network-interop'
    program=r'''
import hashlib,json,subprocess,sys
script=sys.stdin.buffer.read();assert len(script)>1000
name=sys.argv[1]
def tables():
 p=subprocess.run(['nft','-j','list','tables'],capture_output=True,check=True);return json.loads(p.stdout)['nftables']
before=any(e.get('table',{}).get('name')==name for e in tables());assert not before
r=subprocess.run(['nft','--check','--file','-'],input=script,capture_output=True)
after=any(e.get('table',{}).get('name')==name for e in tables())
print(json.dumps({'stdin_bytes':len(script),'stdin_sha256':hashlib.sha256(script).hexdigest(),'before_installed':before,'after_installed':after,'check_exit':r.returncode,'stderr':r.stderr.decode(errors='replace')[:24000]}))
assert not after
'''
    command=['docker','run','--rm','--interactive','--name','goldenhoop-source-preflight-'+attempt,'--label','dev.goldenhoop.test=network-contract','--label','dev.goldenhoop.attempt='+attempt,'--runtime','runc','--network','host','--user','0:0','--cap-drop','ALL','--cap-add','NET_ADMIN','--security-opt','no-new-privileges:true','--read-only','--memory','128m','--memory-swap','128m','--cpus','0.25','--pids-limit','32','--entrypoint','python3',args.image,'-c',program,'gh_s_'+attempt]
    root=Path(__file__).resolve().parents[1]
    report={'timestamp':datetime.now(timezone.utc).isoformat(),'suite':'source-plan-read-only-prerequisite','scope':'synthetic planning descriptor, actual checked stdin and nft check-only invocation; no packet policy installed','result':'failed','cleanup':'pending','attempt':attempt,'expect_unavailable':args.expect_unavailable,'input':data,'image_id':observed_image['Id'],'source_files_sha256':{p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__).resolve(),root/'crates/egress/src/source.rs',root/'crates/egress/examples/source_plan.rs']},'script_sha256':hashlib.sha256(script).hexdigest()}
    try:
        result=subprocess.run(command,input=script,capture_output=True,timeout=40);assert result.returncode==0,result.stderr
        observed=json.loads(result.stdout);report['observation']=observed
        assert observed['stdin_bytes']==len(script) and observed['stdin_sha256']==hashlib.sha256(script).hexdigest()
        error=observed['stderr'].lower()
        expected=observed['check_exit']==0 if not args.expect_unavailable else observed['check_exit']!=0 and 'not supported' in error and 'syntax error' not in error
        assert expected,'source native prerequisite did not meet the explicit expected condition'
        report['result']='passed'
    except BaseException as exc:
        report['error']=repr(exc)
        raise
    finally:
        try:
            remaining=subprocess.run(['docker','ps','-a','--filter','label=dev.goldenhoop.attempt='+attempt,'--format','{{.ID}}'],capture_output=True,check=True,timeout=15)
            for identity in remaining.stdout.decode().splitlines():
                inspect=subprocess.run(['docker','inspect',identity],capture_output=True,check=True,timeout=15)
                labels=json.loads(inspect.stdout)[0]['Config']['Labels']
                assert labels.get('dev.goldenhoop.attempt')==attempt and labels.get('dev.goldenhoop.test')=='network-contract'
                subprocess.run(['docker','rm','--force',identity],capture_output=True,check=True,timeout=15)
            remaining=subprocess.run(['docker','ps','-a','--filter','label=dev.goldenhoop.attempt='+attempt,'--format','{{.ID}}'],capture_output=True,check=True,timeout=15)
            assert not remaining.stdout.strip()
            report['cleanup']='complete'
        except BaseException as exc:
            report['cleanup']='failed';report['cleanup_error']=repr(exc)
            raise
        finally:
            Path(args.output).write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
            print(json.dumps({k:report[k] for k in ('result','cleanup','attempt')}))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',required=True)
    parser.add_argument('--plan-exe',required=True)
    parser.add_argument('--image',default='goldenhoop-network-fixture:test')
    parser.add_argument('--output',required=True)
    parser.add_argument('--expect-unavailable',action='store_true')
    run(parser.parse_args())
