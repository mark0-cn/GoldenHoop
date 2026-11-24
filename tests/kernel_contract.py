"""Real Rust/Jupyter IPC experiment. Owns one labeled disposable Linux container."""
import argparse
import hashlib
import json
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path


def docker(*args, timeout=30):
    result = subprocess.run(["docker", *args], capture_output=True, text=True, encoding="utf-8", timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"Docker {args[0]} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def run(args):
    attempt = str(uuid.uuid4())
    name = "goldenhoop-kernel-" + uuid.uuid4().hex[:12]
    evidence = {"suite": "kernel-ipc-contract", "timestamp": datetime.now(timezone.utc).isoformat(),
                "runtime": args.runtime, "result": "failed", "cleanup": "unknown", "attempt": attempt}
    failure = None
    try:
        image = json.loads(docker("image", "inspect", args.image))[0]
        assert image["Config"]["Labels"].get("dev.goldenhoop.fixture") == "kernel-interop"
        evidence["image_id"] = image["Id"]
        root = Path(__file__).resolve().parents[1]
        files = [root / "Cargo.toml", root / "Cargo.lock", Path(__file__).resolve(), root / "images/kernel/Dockerfile"]
        files.extend((root / "crates/jupyter").rglob("*.rs"))
        files.append(root / "crates/jupyter/Cargo.toml")
        evidence["source_files_sha256"] = {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(files)}
        identity = docker("run", "-d", "--name", name, "--runtime", args.runtime,
                          "--label", "dev.goldenhoop.test=kernel-contract", "--label", f"dev.goldenhoop.attempt={attempt}",
                          "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                          "--memory", "1g", "--cpus", "1", "--pids-limit", "256", "--user", "1000:1000", "--init",
                          "--tmpfs", "/tmp:rw,nosuid,nodev,size=32m,mode=1777",
                          "--tmpfs", "/workspace:rw,nosuid,nodev,size=128m,uid=1000,gid=1000,mode=2770", args.image)
        exit_code = int(docker("wait", identity, timeout=60))
        observed = json.loads(docker("inspect", identity))[0]
        host = observed["HostConfig"]
        assert host["Runtime"] == args.runtime and host["NetworkMode"] == "none" and host["ReadonlyRootfs"]
        assert host["Memory"] == 1073741824 and host["PidsLimit"] == 256
        assert host["NanoCpus"] == 1000000000 and "ALL" in host["CapDrop"]
        assert any("no-new-privileges" in value for value in host["SecurityOpt"])
        assert observed["Config"]["User"] == "1000:1000"
        evidence["effective_limits"] = {"memory_bytes": host["Memory"], "pids": host["PidsLimit"],
                                        "cpu_nanos": host["NanoCpus"], "network": host["NetworkMode"],
                                        "user": observed["Config"]["User"], "readonly_rootfs": host["ReadonlyRootfs"],
                                        "cap_drop": host["CapDrop"], "security_options": host["SecurityOpt"]}
        evidence["runtime_state"] = observed["State"]
        records = []
        logs = subprocess.run(["docker", "logs", identity], capture_output=True, text=True, encoding="utf-8", timeout=10)
        for line in logs.stdout.splitlines():
            try:
                record = json.loads(line)
                if record.get("suite") == "jupyter-ipc-interoperability":
                    records.append(record)
            except (ValueError, AttributeError):
                pass
        if exit_code != 0 or len(records) != 1:
            evidence["logs"] = (logs.stdout + logs.stderr)[-65536:]
            raise AssertionError(f"kernel experiment failed: exit={exit_code}, records={len(records)}")
        result = records[0]
        assert result["result"] == "passed" and result["kernel_exit_code"] == 0 and result["private_files_removed"] is True
        assert [run["reply"]["status"] for run in result["runs"]] == ["ok", "ok", "error"]
        assert result["runs"][1]["stream"] == "42\n" and result["runs"][2]["exception"] == "ValueError"
        evidence["interoperability"] = result
        evidence["docker"] = json.loads(docker("version", "--format", "{{json .Server}}"))
        if args.runtime == "runsc":
            evidence["runsc_version"] = subprocess.run(["runsc", "--version"], capture_output=True, text=True, check=True, timeout=10).stdout.strip()
        evidence["result"] = "passed"
    except BaseException as error:
        failure = error
        evidence["error"] = str(error)
    finally:
        try:
            existing = docker("ps", "-a", "--no-trunc", "--filter", f"name=^/{name}$", "--format", "{{.ID}}")
            if existing:
                assert len(existing.splitlines()) == 1
                labels = json.loads(docker("inspect", "--format", "{{json .Config.Labels}}", existing))
                assert labels.get("dev.goldenhoop.test") == "kernel-contract" and labels.get("dev.goldenhoop.attempt") == attempt
                docker("rm", "-f", "-v", existing)
            assert not docker("ps", "-a", "--filter", f"name=^/{name}$", "--format", "{{.ID}}")
            if args.remove_image:
                info = json.loads(docker("image", "inspect", args.image))[0]
                assert info["Config"]["Labels"].get("dev.goldenhoop.fixture") == "kernel-interop"
                assert not docker("ps", "-a", "--filter", f"ancestor={args.image}", "--format", "{{.ID}}")
                docker("image", "rm", args.image)
                check = subprocess.run(["docker", "image", "inspect", args.image], capture_output=True, timeout=10)
                assert check.returncode != 0
                evidence["fixture_image_removed"] = True
            evidence["cleanup"] = "complete"
        except BaseException as error:
            evidence["cleanup_error"] = str(error)
            evidence["result"] = "failed"
            failure = failure or error
        rendered = json.dumps(evidence, indent=2)
        if args.output:
            path = Path(args.output)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(rendered + "\n", encoding="utf-8")
        print(json.dumps({key: evidence.get(key) for key in ("suite", "runtime", "result", "cleanup", "error")}))
    if failure:
        raise failure


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", default="goldenhoop-kernel-fixture:test")
    parser.add_argument("--runtime", choices=("runc", "runsc"), default="runc")
    parser.add_argument("--remove-image", action="store_true", help="only for a fixture image built for this test")
    parser.add_argument("--output")
    run(parser.parse_args())
