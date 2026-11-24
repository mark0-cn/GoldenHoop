"""Actual Docker agent contract. Only removes the container this process creates."""
import argparse
import base64
import hashlib
import json
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


def docker(*args, input_text=None, timeout=30):
    result = subprocess.run(
        ["docker", *args], input=input_text, text=True, encoding="utf-8",
        capture_output=True, timeout=timeout,
    )
    if result.returncode:
        raise RuntimeError(f"docker {args[0]} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def logs(container):
    result = subprocess.run(["docker", "logs", container], text=True,
                            encoding="utf-8", capture_output=True, timeout=10)
    return result.stdout + result.stderr


def source_fingerprint():
    root = Path(__file__).resolve().parents[1]
    paths = [root / "Cargo.toml", root / "Cargo.lock", Path(__file__).resolve(),
             root / "images/agent/Dockerfile"]
    paths.extend((root / "crates").rglob("*.rs"))
    paths.extend((root / "crates").rglob("Cargo.toml"))
    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(paths)}


class AgentError(RuntimeError):
    def __init__(self, error):
        self.code = error["code"]
        super().__init__(error["message"])


class Contract:
    def __init__(self, image, runtime):
        self.container = None
        self.results = []
        self.runtime = runtime
        self.image = image

    def start(self):
        # Save the name before Docker runs: a failed start may still create a container.
        self.container = f"goldenhoop-agent-contract-{uuid.uuid4().hex[:12]}"
        self.container = docker(
            "run", "-d", "--name", self.container,
            "--label", "dev.goldenhoop.test=agent-contract",
            "--runtime", self.runtime, "--network", "none",
            "--cap-drop", "ALL", "--cap-add", "SETUID", "--cap-add", "SETGID",
            "--cap-add", "KILL", "--cap-add", "CHOWN", "--cap-add", "FOWNER",
            "--cap-add", "DAC_OVERRIDE", "--security-opt", "no-new-privileges",
            "--read-only", "--init", "--memory", "256m", "--cpus", "1",
            "--pids-limit", "128",
            "--tmpfs", "/workspace:rw,nosuid,nodev,size=128m,uid=1000,gid=1000,mode=2770",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=32m,mode=1777",
            "--tmpfs", "/run/goldenhoop:rw,nosuid,nodev,size=32m,mode=700",
            self.image,
        )
        last_error = None
        for _ in range(50):
            try:
                self.rpc({"method": "ping"})
                return
            except (RuntimeError, ValueError) as error:
                last_error = error
                time.sleep(0.1)
        raise RuntimeError(f"agent did not start: {last_error}\n{logs(self.container)}")

    def rpc(self, request):
        raw = docker(
            "exec", "-i", "--user", "0", self.container,
            "/usr/local/bin/goldenhoop-agent", "rpc",
            input_text=json.dumps(request) + "\n",
        )
        reply = json.loads(raw)
        if reply["status"] == "error":
            raise AgentError(reply["data"])
        return reply["data"]

    def reject(self, request, codes=("forbidden", "invalid_request")):
        try:
            self.rpc(request)
        except AgentError as error:
            assert error.code in codes, (error.code, str(error))
            return
        raise AssertionError(f"request unexpectedly allowed: {request['method']}")

    def execute(self, argv, timeout=5, output_limit=4 * 1024 * 1024):
        identity = str(uuid.uuid4())
        self.rpc({"method": "start", "id": identity, "command": {
            "argv": argv, "timeout_seconds": timeout, "max_output_bytes": output_limit,
        }})
        return self.wait(identity), identity

    def wait(self, identity, limit=15):
        cursor, events = 0, []
        deadline = time.monotonic() + limit
        while time.monotonic() < deadline:
            packet = self.rpc({"method": "events", "id": identity, "after": cursor})
            events.extend(packet["value"])
            if packet["value"]:
                cursor = packet["value"][-1]["sequence"]
            record = self.rpc({"method": "inspect", "id": identity})["value"]
            if record["state"] in ("succeeded", "failed", "cancelled", "timed_out"):
                # Consume any final batch written before terminal state publication.
                packet = self.rpc({"method": "events", "id": identity, "after": cursor})
                events.extend(packet["value"])
                sequences = [event["sequence"] for event in events]
                assert sequences == sorted(set(sequences))
                assert sum(event["kind"] == "completed" for event in events) == 1
                assert record["cleanup"] == "complete", record
                return record, events
            if record["state"] == "unknown":
                raise AssertionError(f"cleanup/execution unknown: {record}")
            time.sleep(0.05)
        raise AssertionError(f"execution observation timed out: {identity}")

    @staticmethod
    def output(events, kind="stdout"):
        return b"".join(base64.b64decode(event["data"]["data"])
                        for event in events if event["kind"] == kind)

    def check(self, name, function):
        started = time.monotonic()
        function()
        self.results.append({"case": name, "result": "passed",
                             "seconds": round(time.monotonic() - started, 3)})

    def properties(self):
        config = json.loads(docker("inspect", self.container))[0]
        host = config["HostConfig"]
        assert host["Runtime"] == self.runtime
        assert host["NetworkMode"] == "none"
        assert host["ReadonlyRootfs"] is True
        assert "ALL" in host["CapDrop"]
        assert any("no-new-privileges" in item for item in host["SecurityOpt"])
        assert host["PidsLimit"] == 128
        assert host["Memory"] == 256 * 1024 * 1024

    def command_and_identity(self):
        (record, events), _ = self.execute(["python3", "-c",
            "import os,sys; assert os.getuid()==1000; assert os.getgroups()==[]; "
            "s=open('/proc/self/status').read(); "
            "assert 'CapEff:\\t0000000000000000' in s; assert 'NoNewPrivs:\\t1' in s; "
            "sys.stdout.buffer.write(bytes([0,255,10])); sys.stderr.write('err\\n')"])
        assert record["state"] == "succeeded" and record["exit_code"] == 0
        assert self.output(events) == bytes([0, 255, 10])
        assert self.output(events, "stderr") == b"err\n"

    def no_shell_interpolation(self):
        (record, events), _ = self.execute(["printf", "%s", "$(touch /workspace/injected)"])
        assert record["state"] == "succeeded"
        assert self.output(events) == b"$(touch /workspace/injected)"
        self.reject({"method": "read_file", "path": "injected", "max_bytes": 64},
                    codes=("not_found",))

    def failure_and_launch_error(self):
        (record, _), _ = self.execute(["sh", "-c", "exit 23"])
        assert record["state"] == "failed" and record["exit_code"] == 23
        (record, _), _ = self.execute(["/does/not/exist"])
        assert record["state"] == "failed" and record["exit_code"] is None

    def files(self):
        data = base64.b64encode(bytes(range(256))).decode()
        self.rpc({"method": "write_file", "path": "nested/binary", "data_base64": data})
        actual = self.rpc({"method": "read_file", "path": "nested/binary", "max_bytes": 512})
        assert actual["value"]["data_base64"] == data
        (record, _), _ = self.execute(["python3", "-c",
            "from pathlib import Path; p=Path('/workspace/nested/binary'); "
            "p.write_bytes(p.read_bytes()+b'child')"])
        assert record["state"] == "succeeded"
        self.reject({"method": "read_file", "path": "../etc/passwd", "max_bytes": 1024})
        self.reject({"method": "write_file", "path": "/etc/escaped", "data_base64": data})
        self.reject({"method": "read_file", "path": "/run/goldenhoop/agent.sock", "max_bytes": 1024})
        (record, _), _ = self.execute(["sh", "-c", "ln -s /etc /workspace/escape"])
        assert record["state"] == "succeeded"
        self.reject({"method": "read_file", "path": "escape/passwd", "max_bytes": 4096})
        self.reject({"method": "write_file", "path": "escape/forbidden", "data_base64": data})
        self.rpc({"method": "remove_file", "path": "nested/binary"})
        self.reject({"method": "read_file", "path": "nested/binary", "max_bytes": 512},
                    codes=("not_found",))

    def denied_network(self):
        (record, _), _ = self.execute(["python3", "-c",
            "import socket; "
            "s=socket.socket(); s.settimeout(1); "
            "r=s.connect_ex(('1.1.1.1',443)); assert r!=0, r"])
        assert record["state"] == "succeeded"

    def timeout_and_descendants(self):
        (record, _), _ = self.execute(
            ["sh", "-c", "sleep 30 & sleep 30"], timeout=1)
        assert record["state"] == "timed_out"
        self.assert_no_workload_processes()

    def assert_no_workload_processes(self):
        code = (
            "from pathlib import Path; "
            "s=[p.read_text() for p in Path('/proc').glob('[0-9]*/status') if p.exists()]; "
            "alive=[v for v in s if any(x.startswith('Uid:') and x.split()[1]=='1000' "
            "for x in v.splitlines()) and not any(x.startswith('State:') and "
            "x.split()[1] in ('Z','X') for x in v.splitlines())]; assert not alive, alive"
        )
        docker("exec", "--user", "0", self.container, "python3", "-c", code)

    def cancellation_collects_setsid_descendant(self):
        identity = str(uuid.uuid4())
        code = (
            "import os,time; "
            "pid=os.fork(); "
            "os.setsid() if pid==0 else None; "
            "time.sleep(30)"
        )
        self.rpc({"method": "start", "id": identity, "command": {
            "argv": ["python3", "-c", code], "timeout_seconds": 10,
        }})
        for _ in range(30):
            record = self.rpc({"method": "inspect", "id": identity})["value"]
            if record["state"] == "running":
                break
            time.sleep(0.05)
        time.sleep(0.2)
        self.rpc({"method": "cancel", "id": identity})
        record, _ = self.wait(identity)
        assert record["state"] == "cancelled"
        self.assert_no_workload_processes()

    def bounded_output(self):
        (record, events), _ = self.execute(
            ["python3", "-c", "import sys; sys.stdout.write('x'*65536)"],
            output_limit=1024,
        )
        assert record["state"] == "succeeded"
        assert record["output_truncated"]
        assert len(self.output(events)) <= 1024
        assert sum(e["kind"] == "output_truncated" for e in events) == 1

    def idempotency(self):
        identity = str(uuid.uuid4())
        request = {"method": "start", "id": identity, "command": {
            "argv": ["sh", "-c", "echo once >> /workspace/count"],
        }}
        self.rpc(request)
        self.rpc(request)
        record, _ = self.wait(identity)
        assert record["state"] == "succeeded"
        data = self.rpc({"method": "read_file", "path": "count", "max_bytes": 64})
        assert base64.b64decode(data["value"]["data_base64"]) == b"once\n"
        request["command"]["argv"] = ["true"]
        self.reject(request, codes=("conflict",))

    def start_session(self, argv, terminal=None, timeout=20):
        identity = str(uuid.uuid4())
        request = {"method": "start_session", "id": identity, "session": {
            "command": {"argv": argv, "timeout_seconds": timeout}, "terminal": terminal,
        }}
        self.rpc(request)
        self.rpc(request)
        for _ in range(100):
            if self.rpc({"method": "inspect", "id": identity})["value"]["state"] == "running":
                return identity
            time.sleep(0.05)
        raise AssertionError("session did not become running")

    def session_control(self, identity, sequence, action):
        request = {"method": "session_control", "id": identity,
                   "control": {"sequence": sequence, "action": action}}
        receipt = self.rpc(request)["value"]
        assert receipt["execution_id"] == identity and receipt["sequence"] == sequence
        assert self.rpc(request)["value"] == receipt, "replay changed the receipt"
        assert self.rpc({"method": "session_control_status", "id": identity,
                         "sequence": sequence})["value"] == receipt
        return receipt

    def wait_output(self, identity, marker):
        for _ in range(100):
            events = self.rpc({"method": "events", "id": identity, "after": 0})["value"]
            if marker in self.output(events):
                return
            time.sleep(0.05)
        raise AssertionError(f"session output marker missing: {marker!r}")

    @staticmethod
    def input_action(data):
        return {"kind": "write", "data_base64": base64.b64encode(data).decode()}

    def shell_retains_state_and_controls_are_deduplicated(self):
        identity = self.start_session(["/bin/sh"])
        action = self.input_action(b"value=golden; mkdir -p /workspace/session-dir; cd /workspace/session-dir; printf 'READY\\n'\n")
        assert self.session_control(identity, 1, action)["state"] == "applied"
        self.wait_output(identity, b"READY\n")
        queued = str(uuid.uuid4())
        self.rpc({"method": "start", "id": queued, "command": {"argv": ["printf", "queued"]}})
        assert self.rpc({"method": "inspect", "id": queued})["value"]["state"] == "pending"
        action = self.input_action(b"printf '%s:%s\\n' \"$value\" \"$PWD\"; printf once >> /workspace/session-count\n")
        assert self.session_control(identity, 2, action)["state"] == "applied"
        self.reject({"method": "session_control", "id": identity, "control": {
            "sequence": 2, "action": self.input_action(b"echo changed\n")}}, codes=("conflict",))
        self.reject({"method": "session_control", "id": identity, "control": {
            "sequence": 4, "action": {"kind": "close_input"}}}, codes=("conflict",))
        assert self.session_control(identity, 3, {"kind": "close_input"})["state"] == "applied"
        record, events = self.wait(identity)
        assert record["state"] == "succeeded", record
        assert b"golden:/workspace/session-dir\n" in self.output(events)
        stored = self.rpc({"method": "read_file", "path": "session-count", "max_bytes": 32})
        assert base64.b64decode(stored["value"]["data_base64"]) == b"once"
        assert self.session_control(identity, 2, action)["state"] == "applied"
        queued_record, queued_events = self.wait(queued)
        assert queued_record["state"] == "succeeded" and self.output(queued_events) == b"queued"
        self.assert_no_workload_processes()

    def real_pty_binary_input_resize_and_controlling_terminal(self):
        code = (
            "import os,signal,sys,termios,tty,time; "
            "assert all(os.isatty(fd) for fd in (0,1,2)); "
            "assert os.getsid(0)==os.getpid(); assert os.getuid()==1000; "
            "assert 'CapEff:\\t0000000000000000' in open('/proc/self/status').read(); "
            "open('/dev/tty').close(); tty.setraw(0); "
            "signal.signal(signal.SIGWINCH,lambda *_:print('SIZE:%d:%d'%termios.tcgetwinsize(0),flush=True)); "
            "print('READY:%d:%d'%termios.tcgetwinsize(0),flush=True); "
            "data=os.read(0,3); print('BIN:'+data.hex(),flush=True); time.sleep(.1)"
        )
        identity = self.start_session(["python3", "-c", code], {"rows": 24, "columns": 80})
        self.wait_output(identity, b"READY:24:80\n")
        resized = self.session_control(identity, 1, {"kind": "resize", "size": {"rows": 40, "columns": 100}})
        assert resized["state"] == "applied", resized
        self.wait_output(identity, b"SIZE:40:100\n")
        half_close = self.session_control(identity, 2, {"kind": "close_input"})
        assert half_close["state"] == "rejected" and half_close["error"]["code"] == "unsupported_capability"
        assert self.session_control(identity, 3, self.input_action(b"\x00\xff\n"))["state"] == "applied"
        record, events = self.wait(identity)
        assert record["state"] == "succeeded", record
        assert b"BIN:00ff0a\n" in self.output(events)
        assert not self.output(events, "stderr"), "PTY must expose one merged stream"
        self.assert_no_workload_processes()

    def uncertain_input_is_not_retried(self):
        code = "import fcntl,time; fcntl.fcntl(0,fcntl.F_SETPIPE_SZ,4096); print('READY',flush=True); time.sleep(30)"
        identity = self.start_session(["python3", "-c", code])
        self.wait_output(identity, b"READY\n")
        receipt = self.session_control(identity, 1, self.input_action(b"x" * 65536))
        assert receipt["state"] == "unknown", receipt
        rejected = self.session_control(identity, 2, self.input_action(b"other"))
        assert rejected["state"] == "rejected" and rejected["error"]["code"] == "invalid_state"
        self.rpc({"method": "cancel", "id": identity})
        record, _ = self.wait(identity)
        assert record["state"] == "cancelled", record
        self.assert_no_workload_processes()

    def terminal_cancel_collects_escaped_descendants(self):
        code = "import os,time; pid=os.fork(); os.setsid() if pid==0 else None; print('READY',flush=True); time.sleep(30)"
        identity = self.start_session(["python3", "-c", code], {"rows": 24, "columns": 80})
        self.wait_output(identity, b"READY")
        self.rpc({"method": "cancel", "id": identity})
        record, _ = self.wait(identity)
        assert record["state"] == "cancelled", record
        self.assert_no_workload_processes()

    def cleanup(self):
        if not self.container:
            return
        existing = docker("ps", "-a", "--no-trunc", "--filter",
                          f"id={self.container}" if len(self.container) == 64
                          else f"name=^/{self.container}$", "--format", "{{.ID}}")
        if existing:
            assert len(existing.splitlines()) == 1
            labels = docker("inspect", "--format", "{{json .Config.Labels}}", existing)
            assert json.loads(labels).get("dev.goldenhoop.test") == "agent-contract"
            docker("rm", "-f", existing)
            assert not docker("ps", "-a", "--filter", f"id={existing}", "--format", "{{.ID}}")

    def run(self, output=None):
        evidence = {
            "suite": "agent-contract", "timestamp": datetime.now(timezone.utc).isoformat(),
            "runtime": self.runtime, "image": self.image, "cases": self.results,
            "result": "failed", "cleanup": "unknown",
            "source_files_sha256": source_fingerprint(),
        }
        try:
            self.start()
            evidence["image_id"] = docker("inspect", "--format", "{{.Image}}", self.container)
            evidence["docker"] = json.loads(docker("version", "--format", "{{json .Server}}"))
            if self.runtime == "runsc":
                version = subprocess.run(["runsc", "--version"], text=True,
                                         capture_output=True, check=True, timeout=10)
                evidence["runsc_version"] = version.stdout.strip()
            for name in (
                "properties", "command_and_identity", "no_shell_interpolation",
                "failure_and_launch_error", "files", "denied_network",
                "timeout_and_descendants", "cancellation_collects_setsid_descendant",
                "bounded_output", "idempotency",
                "shell_retains_state_and_controls_are_deduplicated",
                "real_pty_binary_input_resize_and_controlling_terminal",
                "uncertain_input_is_not_retried",
                "terminal_cancel_collects_escaped_descendants",
            ):
                self.check(name, getattr(self, name))
            evidence["result"] = "passed"
        except Exception as error:
            evidence["error"] = str(error)
            if self.container:
                evidence["logs"] = logs(self.container)
            raise
        finally:
            try:
                self.cleanup()
                evidence["cleanup"] = "complete"
            finally:
                rendered = json.dumps(evidence, indent=2)
                print(json.dumps({key: evidence[key] for key in ("suite", "runtime", "result", "cleanup", "cases")})) if output else print(rendered)
                if output:
                    Path(output).parent.mkdir(parents=True, exist_ok=True)
                    Path(output).write_text(rendered + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", default="goldenhoop-agent:test")
    parser.add_argument("--runtime", default="runc")
    parser.add_argument("--output", help="JSON evidence path, including cleanup result")
    args = parser.parse_args()
    Contract(args.image, args.runtime).run(args.output)
