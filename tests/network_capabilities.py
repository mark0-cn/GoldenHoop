"""Read/check-only Linux host capabilities; no production policy is established."""
import argparse
import hashlib
import json
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path


def docker(*args, check=True):
    result = subprocess.run(["docker", *args], capture_output=True, text=True,
                            encoding="utf-8", timeout=40)
    if check and result.returncode:
        raise RuntimeError(f"Docker {args[0]} failed: {result.stderr.strip()}")
    return result


def collect(args):
    attempt = uuid.uuid4().hex
    name = "goldenhoop-net-check-" + attempt
    table = "ghcheck_" + attempt
    root = Path(__file__).resolve().parents[1]
    evidence = {"suite": "host-netfilter-capability-probe", "result": "failed",
                "cleanup": "unknown", "timestamp": datetime.now(timezone.utc).isoformat(),
                "scope": "capability checks only; no packet policy or credential service",
                "required_families": args.families,
                "attempt": attempt, "cases": [], "image_removed": False,
                "source_files_sha256": {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in [Path(__file__).resolve(), root / "tests/fixtures/network.Dockerfile"]}}
    container = None
    failure = None
    script = r'''
import json,os,subprocess,sys
name=sys.argv[1]
required=sys.argv[2].split(",")
def run(*args, data=None):
 return subprocess.run(list(args),input=data,capture_output=True,text=True,timeout=15)
observation={"checks":[],"kernel":os.uname().release,"error":None}
try:
 observation["nft_version"]=run("nft","--version").stdout.strip()
 status=open("/proc/self/status").read().splitlines()
 credentials={line.split(":",1)[0]:line.split(":",1)[1].strip() for line in status if line.startswith(("CapEff:","CapPrm:","NoNewPrivs:"))}
 observation["credentials"]=credentials
 assert int(credentials["CapEff"],16)==1<<12,credentials
 assert credentials["NoNewPrivs"]=="1",credentials
 result=run("nft","-j","list","tables")
 if result.returncode: raise RuntimeError(result.stderr.strip())
 tables=[entry["table"] for entry in json.loads(result.stdout)["nftables"] if "table" in entry]
 assert not any(table["name"]==name for table in tables),"candidate table already exists"
 observation["existing_table_families"]=sorted({table["family"] for table in tables})
 for family in required:
  hook={"inet":"forward","bridge":"prerouting"}[family]
  rules=f"add table {family} {name}\nadd chain {family} {name} test {{ type filter hook {hook} priority -190; policy accept; }}\nadd rule {family} {name} test iifname \"gh-never-live\" counter drop\n"
  check=run("nft","--check","--file","-",data=rules)
  after=run("nft","-j","list","tables")
  if after.returncode: raise RuntimeError(after.stderr.strip())
  installed=any(entry.get("table",{}).get("family")==family and entry["table"]["name"]==name for entry in json.loads(after.stdout)["nftables"])
  observation["checks"].append({"family":family,"hook":hook,"check_only":True,"table_installed":installed,"available":check.returncode==0,"error":check.stderr.strip()[:4096] if check.returncode else None})
  if installed:
   removed=run("nft","delete","table",family,name)
   absence=run("nft","-j","list","tables")
   gone=absence.returncode==0 and not any(entry.get("table",{}).get("family")==family and entry["table"]["name"]==name for entry in json.loads(absence.stdout)["nftables"])
   observation["checks"][-1]["unexpected_table_removed"]=removed.returncode==0 and gone
  assert not installed,"check-only command unexpectedly installed a table"
 if not all(check["available"] for check in observation["checks"]):
  observation["error"]="one or more required nftables families are unavailable"
except BaseException as error:
 observation["error"]=str(error)
print(json.dumps(observation))
sys.exit(1 if observation["error"] else 0)
'''
    try:
        image = json.loads(docker("image", "inspect", args.image).stdout)[0]
        assert image["Config"]["Labels"].get("dev.goldenhoop.fixture") == "network-interop"
        evidence["image_id"] = image["Id"]
        container = docker("create", "--name", name, "--runtime", "runc", "--network", "host", "--cap-drop", "ALL",
                           "--cap-add", "NET_ADMIN", "--security-opt", "no-new-privileges:true",
                           "--read-only", "--memory", "128m", "--memory-swap", "128m",
                           "--cpus", "0.25", "--pids-limit", "32", "--restart", "no",
                           "--label", "dev.goldenhoop.test=network-contract",
                           "--label", "dev.goldenhoop.attempt=" + attempt,
                           "--entrypoint", "python3", args.image, "-c", script, table, ','.join(args.families)).stdout.strip()
        observed = json.loads(docker("inspect", container).stdout)[0]
        assert observed["Config"]["Labels"]["dev.goldenhoop.attempt"] == attempt
        host = observed["HostConfig"]
        evidence["requested_boundary"] = {key: host.get(key) for key in
            ("Runtime", "NetworkMode", "ReadonlyRootfs", "CapDrop", "CapAdd", "Memory", "MemorySwap", "NanoCpus", "PidsLimit", "SecurityOpt")}
        assert host["Runtime"] == "runc", host["Runtime"]
        assert host["NetworkMode"] == "host" and host["ReadonlyRootfs"]
        assert {cap.removeprefix("CAP_") for cap in host["CapDrop"]} == {"ALL"}, host["CapDrop"]
        assert {cap.removeprefix("CAP_") for cap in host["CapAdd"]} == {"NET_ADMIN"}, host["CapAdd"]
        assert not observed.get("Mounts")
        output = docker("start", "--attach", container, check=False)
        observed = json.loads(docker("inspect", container).stdout)[0]
        evidence["observation"] = json.loads(output.stdout)
        evidence["container_id"] = container
        assert observed["State"]["ExitCode"] == 0, evidence["observation"]
        evidence["cases"] = ["narrow_trusted_host_namespace_privilege", "required_families_check_only_transactions",
                             "check_only_does_not_install_candidate_tables"]
        evidence["result"] = "passed"
    except BaseException as error:
        failure = error
        evidence["error"] = str(error)
    finally:
        try:
            owned = docker("container", "inspect", name, check=False)
            if owned.returncode == 0:
                record = json.loads(owned.stdout)[0]
                assert record["Config"]["Labels"].get("dev.goldenhoop.attempt") == attempt
                assert record["Config"]["Labels"].get("dev.goldenhoop.test") == "network-contract"
                docker("rm", "--force", "--volumes", record["Id"])
            remaining = docker("ps", "--all", "--filter", "label=dev.goldenhoop.attempt=" + attempt,
                               "--format", "{{.ID}}").stdout.strip()
            assert not remaining, remaining
            for check in evidence.get("observation", {}).get("checks", []):
                assert not check["table_installed"] or check.get("unexpected_table_removed"), check
            evidence["cleanup"] = "complete"
            evidence["cases"].append("owned_container_confirmed_absent")
            if args.remove_image:
                remaining = docker("ps", "--all", "--filter", "ancestor=" + args.image, "--format", "{{.ID}}").stdout.strip()
                assert not remaining, remaining
                image = json.loads(docker("image", "inspect", args.image).stdout)[0]
                assert image["Id"] == evidence["image_id"]
                assert image["Config"]["Labels"].get("dev.goldenhoop.fixture") == "network-interop"
                docker("image", "rm", args.image)
                remaining = docker("image", "ls", "--filter", "reference=" + args.image, "--format", "{{.ID}}").stdout.strip()
                evidence["image_removed"] = not remaining
                assert evidence["image_removed"]
        except BaseException as error:
            evidence["cleanup"] = "unknown"
            evidence["result"] = "failed"
            evidence["cleanup_error"] = str(error)
            failure = failure or error
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({key: evidence.get(key) for key in ("suite", "result", "cleanup", "image_removed", "error")}))
    if failure:
        raise failure


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="goldenhoop-network-fixture:test")
    parser.add_argument("--output", required=True)
    parser.add_argument("--remove-image", action="store_true")
    parser.add_argument("--families", nargs='+', choices=['inet', 'bridge'], default=['inet', 'bridge'])
    collect(parser.parse_args())
