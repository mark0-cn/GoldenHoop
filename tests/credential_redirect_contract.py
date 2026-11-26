"""Actual owned inet redirect readback; no bridge/runtime capability claim."""
import argparse
import copy
import hashlib
import json
import re
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

MANAGER = r'''
import datetime,json,pathlib,subprocess,sys,uuid
a=json.loads(sys.argv[1]);table='gh_c_'+a['generation'].replace('-','');events=[];captures=[];sequence=0;failure=None
p=subprocess.Popen(['/usr/local/libexec/goldenhoop-egress'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
def rpc(operation,error=False,**fields):
 global sequence
 sequence+=1;request={'id':sequence,'command':dict(operation=operation,**fields)}
 p.stdin.write(json.dumps(request)+'\n');p.stdin.flush();line=p.stdout.readline();assert line,'missing explicit manager reply'
 reply=json.loads(line);events.append(dict(request=request,reply=reply))
 assert reply['id']==sequence and ('error' in reply)==error,reply
 return reply.get('error' if error else 'result')
def nft(*args):
 r=subprocess.run(['nft',*args],capture_output=True,text=True,timeout=8);assert r.returncode==0,r.stderr;return json.loads(r.stdout)
def capture(phase,present=True):
 inventory=nft('--json','list','tables');found=any(r.get('table',{}).get('name')==table for r in inventory['nftables'])
 observed=nft('--json','list','table','inet',table) if found else None
 captures.append(dict(phase=phase,present=found,native=observed))
 assert found==present,(phase,'credential redirect presence differs')
try:
 native=dict(allocation=a,identity={**{k:a[k] for k in ('installation_id','sandbox_id','generation')},'profile':'local-runc-dev'},provisioning_token=str(uuid.uuid4()),expires_at=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=90)).isoformat())
 rpc('bind_native',plan=native);rpc('open',allocation=a);capture('before_install')
 rpc('install');capture('after_install')
 policy={'policies':[{'default_action':'deny','rules':[]}]}
 applied=rpc('apply',expected_revision=0,config=policy);assert applied['revision']==1 and not applied['uncertain'];capture('after_apply')
 rpc('quarantine',expected_revision=1);capture('after_quarantine')
 refused=rpc('remove',expected_revision=2,error=True);assert refused['code']=='conflict';capture('remove_refused_while_bridge_exists')
 removed=subprocess.run(['ip','link','delete',a['bridge']],capture_output=True,text=True,timeout=8);assert removed.returncode==0,removed.stderr
 assert not pathlib.Path('/sys/class/net',a['bridge']).exists()
 rpc('remove',expected_revision=2);capture('after_bridge_absence_and_remove',False)
except BaseException as error:failure=repr(error)
finally:
 p.stdin.close()
 try:code=p.wait(timeout=5)
 except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5);raise
 stderr=p.stderr.read()
print(json.dumps(dict(events=events,captures=captures,controller_exit_code=code,controller_stderr=stderr,error=failure,ready=False)))
assert code==0 and failure is None,failure or stderr
'''


def run(args):
    attempt = str(uuid.uuid4())
    report = dict(suite="native-credential-redirect-readback", attempt=attempt,
                  timestamp=datetime.now(timezone.utc).isoformat(), result="failed",
                  cleanup="unknown", scope="Private inet namespace, not transparent runtime acceptance",
                  cases=[], commands=[])
    container = None
    dispatched = False
    settled = False
    failure = None

    def save():
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    def call(argv, value=None, check=True):
        process = subprocess.run(argv, input=value.encode("utf-8") if value is not None else None,
                                 capture_output=True, timeout=30)
        process.stdout = process.stdout.decode("utf-8", errors="replace")
        process.stderr = process.stderr.decode("utf-8", errors="replace")
        report["commands"].append(dict(argv=argv, exit_code=process.returncode,
                                       stdout=process.stdout, stderr=process.stderr))
        if check:
            assert process.returncode == 0, (argv, process.stderr)
        return process

    def compiler(value, refused=False):
        process = call([args.binary], json.dumps(value), check=False)
        report["commands"][-1]["expected_refusal"] = refused
        assert (process.returncode != 0) == refused, (process.returncode, process.stderr)
        return None if refused else json.loads(process.stdout)

    try:
        paths = [Path(__file__), Path("Cargo.lock"), Path("crates/egress/Cargo.toml"),
                 *Path("crates/egress/src").rglob("*.rs"), Path("crates/egress/examples/credential_redirect.rs")]
        repo = Path(__file__).resolve().parents[1]
        report["source_files_sha256"] = {p.resolve().relative_to(repo).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
        report["binary_sha256"] = hashlib.sha256(Path(args.binary).read_bytes()).hexdigest()
        image = json.loads(call(["docker", "image", "inspect", args.image]).stdout)[0]
        assert image["Config"]["Labels"]["dev.goldenhoop.fixture"] == "network-interop"
        report["image_id"] = image["Id"]
        allocation = dict(installation_id=str(uuid.uuid4()), sandbox_id=str(uuid.uuid4()),
                          generation=str(uuid.uuid4()), bridge="ghcredprobe", ifindex=37)
        if args.manager:
            allocation["bridge"] = "ghn" + uuid.UUID(allocation["generation"]).hex[:12]
        definition = dict(v4=dict(address="198.19.0.1", port=44000),
                          v6=dict(address="fd42::1", port=44001), ports={"80": "http", "443": "https"})
        value = dict(allocation=allocation, definition=definition)
        dispatched = True
        save()
        container = call(["docker", "create", "--name", "goldenhoop-credential-readback-" + attempt[:8],
                          "--network", "none", "--read-only", "--cap-drop", "ALL", "--cap-add", "NET_ADMIN",
                          "--security-opt", "no-new-privileges:true", "--cpus", "1", "--memory", "64m",
                          "--pids-limit", "32", "--label", "dev.goldenhoop.test=credential-redirect-readback",
                          "--label", "dev.goldenhoop.attempt=" + attempt,
                          "--entrypoint", "/bin/sleep", image["Id"], "600"]).stdout.strip()
        assert re.fullmatch("[0-9a-f]{64}", container)
        settled = True
        report["container_id"] = container
        save()
        call(["docker", "start", container])
        call(["docker", "exec", container, "ip", "link", "add", allocation["bridge"], "type", "bridge"])
        allocation["ifindex"] = int(call(["docker", "exec", container, "cat", "/sys/class/net/" + allocation["bridge"] + "/ifindex"]).stdout.strip())
        compiled = compiler(value)
        report["input"] = value
        call(["docker", "exec", "--interactive", container, "/usr/sbin/nft", "--file", "-"], compiled["script"])
        table = "gh_c_" + allocation["generation"].replace("-", "")
        native = json.loads(call(["docker", "exec", container, "/usr/sbin/nft", "--json", "--numeric", "list", "table", "inet", table]).stdout)
        assert compiler({**value, "native": native}) == dict(verified=True, ready=False)
        report["native"] = native
        report["cases"].append("actual_v4_v6_native_redirect_matches_exact_owned_plan")
        for case in range(6):
            changed = copy.deepcopy(native)
            rules = [r["rule"] for r in changed["nftables"] if "rule" in r]
            if case == 0:
                rules[0]["expr"][0]["match"]["right"] = "ghforeign"
            elif case == 1:
                rules[0]["expr"][1]["match"]["right"] = allocation["ifindex"] + 1
            elif case == 2:
                rules[0]["expr"][-1]["dnat"]["port"] += 1
            elif case == 3:
                changed["nftables"].remove(next(r for r in changed["nftables"] if "rule" in r))
            elif case == 4:
                changed["nftables"].append({"rule": dict(family="inet", table=table, chain="prerouting", expr=[{"accept": None}])})
            else:
                chain = next(r["chain"] for r in changed["nftables"] if r.get("chain", {}).get("hook") == "prerouting")
                chain["prio"] += 1
            compiler({**value, "native": changed}, refused=True)
        report["cases"].append("changed_source_destination_order_extra_verdict_and_hook_are_refused")
        invalid = copy.deepcopy(value)
        invalid["definition"]["ports"]["53"] = "http"
        compiler(invalid, refused=True)
        report["cases"].append("dns_transport_cannot_be_selected_as_credential_port")
        if args.manager:
            result = call(["docker", "exec", container, "python3", "-B", "-c", MANAGER, json.dumps(allocation)], check=False)
            report["actual_manager_lifecycle"] = json.loads(result.stdout)
            save()
            assert result.returncode == 0 and not report["actual_manager_lifecycle"]["ready"], result.stderr
            report["cases"].extend([
                "actual_manager_preserves_owned_redirect_across_install_apply_and_quarantine",
                "actual_manager_refuses_redirect_removal_while_bridge_exists",
                "actual_manager_removes_redirect_only_after_independent_bridge_absence"])
        report["result"] = "passed"
    except BaseException as error:
        report["error"] = repr(error)
        failure = error
    finally:
        try:
            if container:
                observed = json.loads(call(["docker", "inspect", container]).stdout)[0]
                assert observed["Id"] == container and observed["Config"]["Labels"]["dev.goldenhoop.attempt"] == attempt
                call(["docker", "rm", "--force", container])
                absent = call(["docker", "inspect", container], check=False)
                assert absent.returncode and re.search(r"No such (object|container)", absent.stderr, re.I)
            assert not call(["docker", "ps", "-a", "--filter", "label=dev.goldenhoop.attempt=" + attempt, "--format", "{{.ID}}"]).stdout.strip()
            if not dispatched or settled:
                report["cleanup"] = "complete"
        except BaseException as error:
            report["cleanup_error"] = repr(error)
            failure = failure or error
        save()
    print(json.dumps({k: report[k] for k in ("result", "cleanup")}))
    if failure:
        raise failure
    assert report["cleanup"] == "complete"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--image", default="goldenhoop-network-fixture:test")
    parser.add_argument("--output", required=True)
    parser.add_argument("--manager", action="store_true", help="Also run the production Linux manager's actual private redirect lifecycle")
    run(parser.parse_args())
