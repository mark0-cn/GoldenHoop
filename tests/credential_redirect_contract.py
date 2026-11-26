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
    run(parser.parse_args())
