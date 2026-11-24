"""Observe owned unreferenced nft timeout sets; installs no packet hook."""
import argparse
import hashlib
import json
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


def docker(*args, data=None, check=True):
    result = subprocess.run(["docker", *map(str, args)], input=data.encode() if data is not None else None,
                            capture_output=True, timeout=25)
    if check and result.returncode:
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace")[:4096])
    return result


def probe(args):
    attempt = uuid.uuid4().hex
    name = "goldenhoop-dns-set-" + attempt
    allocation = {"installation_id": str(uuid.uuid4()), "sandbox_id": str(uuid.uuid4()),
                  "generation": str(uuid.UUID(attempt)), "bridge": "ghsetprobe", "ifindex": 1}
    table = "gh_e_" + attempt
    owner = "goldenhoop_" + hashlib.sha256(json.dumps(allocation, separators=(",", ":")).encode()).hexdigest()
    output = Path(args.output)
    root = Path(__file__).resolve().parents[1]
    report = {"suite": "unreferenced-dns-set-expiry-probe", "attempt": attempt,
        "timestamp": datetime.now(timezone.utc).isoformat(), "result": "failed", "cleanup": "unknown",
        "scope": "kernel expiry observation only; no hook or network capability",
        "table": table, "owner_chain": owner, "allocation": allocation,
        "source_files_sha256": {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in [Path(__file__).resolve(), root/"images/agent/Dockerfile", root/"Cargo.lock",root/"Cargo.toml",root/"crates/egress/Cargo.toml",
                      *list((root/"crates/egress").rglob("*.rs"))]}}
    container = None
    table_attempted = False
    failure = None

    def save():
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")

    def owned(observed):
        labels = observed["Config"]["Labels"]
        assert labels.get("dev.goldenhoop.test") == "dns-set-probe" and labels.get("dev.goldenhoop.attempt") == attempt

    def nft(*values, data=None):
        return docker("exec", "--interactive", container, "/usr/sbin/nft", *values, data=data).stdout

    def present():
        rows = json.loads(nft("--json", "list", "tables"))["nftables"]
        return any(r.get("table", {}).get("family") == "inet" and r["table"]["name"] == table for r in rows)

    def snapshot():
        started = time.monotonic_ns()
        value = json.loads(nft("--json", "list", "table", "inet", table))
        ended = time.monotonic_ns()
        rows = value["nftables"]
        assert any(r.get("chain", {}).get("name") == owner and r["chain"]["table"] == table for r in rows)
        assert not any("hook" in r.get("chain", {}) for r in rows)
        native_started = time.monotonic_ns()
        native = nft("list", "table", "inet", table).decode("utf-8")
        native_ended = time.monotonic_ns()
        return {"read_started_monotonic_ns": started, "read_finished_monotonic_ns": ended, "kernel": value,
                "native_read_started_monotonic_ns": native_started, "native_read_finished_monotonic_ns": native_ended,
                "native": native}

    try:
        save()
        image = json.loads(docker("image", "inspect", args.image).stdout)[0]
        assert image["Config"]["Labels"].get("dev.goldenhoop.egress") == "host-netfilter"
        report["image_id"] = image["Id"]
        container = docker("create", "--name", name, "--runtime", "runc", "--network", "host", "--user", "0:0",
            "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--security-opt", "no-new-privileges:true", "--read-only",
            "--memory", "128m", "--memory-swap", "128m", "--cpus", "0.25", "--pids-limit", "32", "--restart", "no",
            "--label", "dev.goldenhoop.test=dns-set-probe", "--label", "dev.goldenhoop.attempt="+attempt,
            "--entrypoint", "/bin/sleep", args.image, "300").stdout.decode().strip()
        observed = json.loads(docker("inspect", container).stdout)[0]
        owned(observed)
        host = observed["HostConfig"]
        assert observed["Image"] == image["Id"] and not observed.get("Mounts")
        assert host["NetworkMode"] == "host" and host["ReadonlyRootfs"] and host["Runtime"] == "runc"
        assert host["Memory"] == host["MemorySwap"] == 134217728 and host["NanoCpus"] == 250000000 and host["PidsLimit"] == 32
        assert {v.removeprefix("CAP_") for v in host["CapDrop"]} == {"ALL"}
        assert {v.removeprefix("CAP_") for v in host["CapAdd"]} == {"NET_ADMIN"}
        report["container_id"] = container
        save()
        docker("start", container)
        assert not present()
        table_attempted = True
        nft("--file", "-", data=f'''add table inet {table}
add chain inet {table} {owner}
add chain inet {table} revision_0
add set inet {table} v4 {{ type ipv4_addr; flags timeout; }}
add set inet {table} v6 {{ type ipv6_addr; flags timeout; }}
add element inet {table} v4 {{ 192.0.2.1 timeout 10s }}
add element inet {table} v6 {{ 2001:db8::1 timeout 10s }}
''')
        first = snapshot()
        report["snapshots"] = [first]
        save()
        time.sleep(1.05)
        second = snapshot()
        report["snapshots"].append(second)
        values = []
        for observation in report["snapshots"]:
            sets = [r["set"] for r in observation["kernel"]["nftables"] if "set" in r]
            assert len(sets) == 2
            remaining = {}
            for record in sets:
                assert record["family"] == "inet" and record["table"] == table
                assert record["type"] == {"v4": "ipv4_addr", "v6": "ipv6_addr"}[record["name"]]
                assert "timeout" in record["flags"] and len(record["elem"]) == 1
                element = record["elem"][0]["elem"]
                assert element["val"] == {"v4": "192.0.2.1", "v6": "2001:db8::1"}[record["name"]]
                assert element["timeout"] == 10 and 0 < element["expires"] <= 10
                remaining[record["name"]] = element["expires"]
            values.append(remaining)
        assert all(values[0][family] - values[1][family] >= 1 for family in ("v4", "v6"))
        report["expiry_units"] = "integer seconds"
        if args.rust:
            result = docker("exec", "--interactive", container, "/usr/local/bin/goldenhoop-egress",
                            "--probe-dns-sets", data=json.dumps(allocation)).stdout
            report["rust_staging"] = json.loads(result)
            assert report["rust_staging"]["result"] == "passed"
            assert report["rust_staging"]["staged_sets_confirmed_absent"]
            assert report["rust_staging"]["ledger_committed"] is False
            assert report["rust_staging"]["packet_hooks_installed"] is False
        report["result"] = "passed"
    except BaseException as error:
        failure = error
        report["error"] = str(error) or type(error).__name__
    finally:
        try:
            observed = docker("inspect", name, check=False)
            if observed.returncode == 0:
                observed = json.loads(observed.stdout)[0]
                owned(observed)
                container = observed["Id"]
                if not observed["State"]["Running"]:
                    docker("start", container)
                if table_attempted and present():
                    snapshot()  # Exact owner and no hooks before deletion.
                    nft("delete", "table", "inet", table)
                assert not present()
                report["owned_table_confirmed_absent"] = True
                docker("rm", "--force", "--volumes", container)
            assert not docker("ps", "-a", "--filter", "label=dev.goldenhoop.attempt="+attempt, "--format", "{{.ID}}").stdout.strip()
            report["owned_container_confirmed_absent"] = True
            report["cleanup"] = "complete"
        except BaseException as error:
            failure = failure or error
            report["cleanup_error"] = str(error)
            report["result"] = "failed"
        save()
    print(json.dumps({key: report.get(key) for key in ("suite", "result", "cleanup", "expiry_units", "error", "cleanup_error")}))
    if failure:
        raise failure


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="goldenhoop-egress:test")
    parser.add_argument("--output", required=True)
    parser.add_argument("--rust", action="store_true", help="also verify the actual Rust staging/readback adapter")
    probe(parser.parse_args())
