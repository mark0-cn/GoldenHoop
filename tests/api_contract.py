"""Actual independent API/worker process contract; owns one fresh installation."""
import argparse
import base64
import hashlib
import json
import os
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from contextlib import closing
from pathlib import Path


def docker(*args):
    result = subprocess.run(["docker", *args], capture_output=True, text=True,
                            encoding="utf-8", timeout=20)
    if result.returncode:
        raise RuntimeError(f"Docker {args[0]} failed: {result.stderr.strip()}")
    return result.stdout.strip()


class ApiFailure(RuntimeError):
    def __init__(self, status, error):
        self.status, self.error = status, error
        super().__init__(f"HTTP {status}: {error.get('code')}: {error.get('message')}")


class Contract:
    def __init__(self, args):
        self.args = args
        self.work = Path(args.work_dir).resolve()
        self.work.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="goldenhoop-api-", dir=self.work)
        self.root = Path(self.temporary.name).resolve()
        assert self.root.is_relative_to(self.work)
        self.database = self.root / "control.db"
        self.token = secrets.token_urlsafe(32)
        self.processes, self.logs, self.log_handles = {}, [], []
        self.base = None
        self.installation = None
        self.results = []
        self.client = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def launch(self, role):
        path = self.root / f"{role}-{len(self.logs)}.log"
        log = path.open("wb")
        self.logs.append(path)
        self.log_handles.append(log)
        command = [str(Path(self.args.binary).resolve()), "--database", str(self.database), role]
        environment = dict(os.environ)
        if role == "api":
            command.extend(["--bind", "127.0.0.1:0"])
            environment["GOLDENHOOP_API_TOKEN"] = self.token
        else:
            command.extend(["--agent-image", self.args.image])
            if self.args.runtime == "runc":
                command.append("--allow-runc-development")
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log,
                                   stderr=subprocess.STDOUT, env=environment,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self.processes[role] = process
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f"{role} exited during startup: {path.read_text(encoding='utf-8')}")
            for line in path.read_text(encoding="utf-8").splitlines():
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if event.get("event") == f"{role}_started":
                    if role == "api":
                        self.base = "http://" + event["address"]
                    self.installation = event["installation_id"]
                    return
            time.sleep(0.05)
        raise RuntimeError(f"{role} startup timed out")

    def stop(self, role):
        process = self.processes.pop(role, None)
        if process and process.poll() is None:
            process.kill()
            process.wait(timeout=10)

    def request(self, method, path, body=None, key=None, authenticated=True):
        headers = {"content-type": "application/json"}
        if authenticated:
            headers["authorization"] = "Bearer " + self.token
        if key:
            headers["idempotency-key"] = key
        request = urllib.request.Request(self.base + path, method=method, headers=headers,
                                         data=None if body is None else json.dumps(body).encode())
        try:
            response = self.client.open(request, timeout=25)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(24 * 1024 * 1024 + 1)
            if len(raw) > 24 * 1024 * 1024:
                raise RuntimeError("API response exceeded limit")
            value = json.loads(raw) if raw else None
            if response.status >= 400:
                raise ApiFailure(response.status, value)
            return value

    def reject(self, method, path, status, code, **kwargs):
        try:
            self.request(method, path, **kwargs)
        except ApiFailure as error:
            assert (error.status, error.error["code"]) == (status, code), str(error)
            return
        raise AssertionError(f"request unexpectedly succeeded: {path}")

    def wait_operation(self, identity, expected="succeeded"):
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            record = self.request("GET", f"/v1/operations/{identity}")
            if record["state"] in ("succeeded", "failed", "cancelled"):
                assert record["state"] == expected, record
                return record
            time.sleep(0.1)
        raise AssertionError(f"operation did not finish: {identity}")

    def create(self, ttl=120, image=None, memory=268435456):
        body = {"profile": "local-gvisor" if self.args.runtime == "runsc" else "local-runc-dev",
                "image": image or self.args.image, "ttl_seconds": ttl,
                "resources": {"cpu_millis": 1000, "memory_bytes": memory, "pids": 128}}
        key = str(uuid.uuid4())
        created = self.request("POST", "/v1/sandboxes", body, key)
        again = self.request("POST", "/v1/sandboxes", body, key)
        assert created["sandbox"]["id"] == again["sandbox"]["id"]
        return created

    def execute(self, argv, timeout=10, key=None, output_limit=4096):
        return self.request("POST", f"/v1/sandboxes/{self.primary}/commands",
                            {"argv": argv, "timeout_seconds": timeout, "max_output_bytes": output_limit},
                            key or str(uuid.uuid4()))

    def wait_execution(self, identity, limit=25):
        deadline = time.monotonic() + limit
        while time.monotonic() < deadline:
            record = self.request("GET", f"/v1/executions/{identity}")
            if record["state"] in ("succeeded", "failed", "cancelled", "timed_out"):
                assert record["cleanup"] == "complete", record
                return record
            time.sleep(0.1)
        raise AssertionError(f"execution did not finish: {identity}")

    def events(self, identity, after=None, first_output=False):
        headers = {"authorization": "Bearer " + self.token}
        if after:
            headers["last-event-id"] = after
        request = urllib.request.Request(self.base + f"/v1/executions/{identity}/events", headers=headers)
        values, data, event_id, kind = [], [], None, None
        with self.client.open(request, timeout=25) as response:
            for raw in response:
                line = raw.decode().rstrip("\r\n")
                if line.startswith("id:"):
                    event_id = line[3:].strip()
                elif line.startswith("event:"):
                    kind = line[6:].strip()
                elif line.startswith("data:"):
                    data.append(line[5:].lstrip())
                elif not line and data:
                    value = json.loads("\n".join(data))
                    if kind == "error":
                        raise ApiFailure(200, value)
                    values.append((event_id, value))
                    data, event_id, kind = [], None, None
                    if first_output and value["kind"] == "stdout":
                        break
        return values

    @staticmethod
    def output(events, kind="stdout"):
        return b"".join(base64.b64decode(value["data"]["data"]) for _, value in events
                        if value["kind"] == kind)

    def container(self, sandbox):
        ids = docker("ps", "-a", "--no-trunc", "--filter",
                     f"label=dev.goldenhoop.installation={self.installation}", "--filter",
                     f"label=dev.goldenhoop.sandbox={sandbox}", "--format", "{{.ID}}")
        assert len(ids.splitlines()) == 1, ids
        return ids

    def check(self, name, function):
        started = time.monotonic()
        function()
        self.results.append({"case": name, "result": "passed",
                             "seconds": round(time.monotonic() - started, 3)})
        print(f"passed: {name}", flush=True)

    def authentication_and_profile_refusal(self):
        self.reject("GET", "/v1/profiles", 401, "unauthorized", authenticated=False)
        profiles = self.request("GET", "/v1/profiles")
        assert any(p["availability"] == "available" for p in profiles), profiles
        unavailable = next((p for p in profiles if p["availability"] == "unavailable"), None)
        if unavailable:
            self.reject("POST", "/v1/sandboxes", 503, "backend_unavailable",
                        body={"profile": unavailable["id"], "image": self.args.image}, key=str(uuid.uuid4()))
        profile = "local-gvisor" if self.args.runtime == "runsc" else "local-runc-dev"
        self.reject("POST", "/v1/sandboxes", 422, "unsupported_capability", body={
            "profile": profile, "image": self.args.image, "required_capabilities": ["memory_snapshot"]}, key=str(uuid.uuid4()))

    def lifecycle_commands_files_and_events(self):
        created = self.create()
        self.primary = created["sandbox"]["id"]
        self.wait_operation(created["operation"]["id"])
        data = base64.b64encode(bytes(range(256))).decode()
        path = f"/v1/sandboxes/{self.primary}/files"
        self.request("PUT", path, {"path": "nested/binary", "data_base64": data})
        assert self.request("GET", path + "?path=nested/binary")["data_base64"] == data
        self.reject("GET", path + "?path=../etc/passwd", 403, "forbidden")
        command = self.execute(["python3", "-c", "import os,sys; assert os.getuid()==1000; "
                                "sys.stdout.buffer.write(bytes([0,255,10])); sys.stderr.write('err')"])
        record = self.wait_execution(command["id"])
        assert record["state"] == "succeeded" and record["exit_code"] == 0, record
        events = self.events(command["id"])
        assert self.output(events) == bytes([0, 255, 10]) and self.output(events, "stderr") == b"err"
        assert sum(value["kind"] == "completed" for _, value in events) == 1
        self.completed = command["id"]

    def observer_disconnect_and_resume(self):
        command = self.execute(["python3", "-c", "import time; print('first',flush=True); time.sleep(1); print('last',flush=True)"])
        first = self.events(command["id"], first_output=True)
        assert first and first[-1][1]["kind"] == "stdout"
        record = self.wait_execution(command["id"])
        assert record["state"] == "succeeded"
        rest = self.events(command["id"], after=first[-1][0])
        combined = first + rest
        assert self.output(combined) == b"first\nlast\n"
        sequences = [value["sequence"] for _, value in combined]
        assert sequences == sorted(set(sequences))

    def command_failure_timeout_cancel_and_idempotency(self):
        failed = self.execute(["sh", "-c", "exit 23"])
        record = self.wait_execution(failed["id"])
        assert record["state"] == "failed" and record["exit_code"] == 23
        timed = self.execute(["sh", "-c", "sleep 30 & sleep 30"], timeout=1)
        assert self.wait_execution(timed["id"])["state"] == "timed_out"
        key = str(uuid.uuid4())
        first = self.execute(["sh", "-c", "echo once >> /workspace/count"], key=key)
        assert self.execute(["sh", "-c", "echo once >> /workspace/count"], key=key)["id"] == first["id"]
        assert self.wait_execution(first["id"])["state"] == "succeeded"
        data = self.request("GET", f"/v1/sandboxes/{self.primary}/files?path=count")
        assert base64.b64decode(data["data_base64"]) == b"once\n"
        command = self.execute(["python3", "-c", "import os,time; p=os.fork(); os.setsid() if p==0 else None; time.sleep(30)"], timeout=30)
        for _ in range(50):
            if self.request("GET", f"/v1/executions/{command['id']}")["state"] == "running":
                break
            time.sleep(0.05)
        else:
            raise AssertionError("cancellation target never ran")
        time.sleep(0.2)
        self.request("POST", f"/v1/executions/{command['id']}/cancel")
        assert self.wait_execution(command["id"])["state"] == "cancelled"

    def worker_restart_retains_runtime_and_executes_once(self):
        container = self.container(self.primary)
        started = docker("inspect", "--format", "{{.State.StartedAt}}", container)
        command = self.execute(["python3", "-c", "from pathlib import Path; import time; "
                                "p=Path('/workspace/restart-count'); p.open('a').write('once\\n'); "
                                "print('before',flush=True); time.sleep(2); print('after',flush=True)"])
        first = self.events(command["id"], first_output=True)
        assert self.output(first) == b"before\n"
        self.stop("worker")
        time.sleep(11)
        self.reject("GET", "/v1/profiles", 503, "backend_unavailable")
        self.reject("GET", f"/v1/sandboxes/{self.primary}/diagnostics", 503, "backend_unavailable")
        self.launch("worker")
        assert self.container(self.primary) == container
        assert docker("inspect", "--format", "{{.State.StartedAt}}", container) == started
        assert self.wait_execution(command["id"])["state"] == "succeeded"
        rest = self.events(command["id"], after=first[-1][0])
        assert self.output(first + rest) == b"before\nafter\n"
        data = self.request("GET", f"/v1/sandboxes/{self.primary}/files?path=restart-count")
        assert base64.b64decode(data["data_base64"]) == b"once\n"

    def api_restart_keeps_results_and_private_worker_route_is_restricted(self):
        self.stop("api")
        self.launch("api")
        assert self.request("GET", f"/v1/sandboxes/{self.primary}")["state"] == "running"
        assert self.request("GET", f"/v1/executions/{self.completed}")["state"] == "succeeded"
        self.reject("POST", "/internal/files", 404, "not_found", body={})
        with closing(sqlite3.connect(self.database)) as connection:
            worker = json.loads(connection.execute("SELECT value FROM meta WHERE key='worker'").fetchone()[0])
        assert worker["token"] not in json.dumps(self.request("GET", "/v1/profiles"))
        request = urllib.request.Request(worker["endpoint"] + "/internal/files", method="POST", headers={
            "content-type": "application/json", "authorization": "Bearer " + worker["token"]},
            data=json.dumps({"sandbox_id": self.primary, "request": {"method": "start",
                 "id": str(uuid.uuid4()), "command": {"argv": ["true"]}}}).encode())
        try:
            self.client.open(request, timeout=5)
        except urllib.error.HTTPError as error:
            with error:
                assert error.status == 403 and json.load(error)["code"] == "forbidden"
        else:
            raise AssertionError("private file route accepted an execution request")

    def paused_expiry_continues_while_api_is_down(self):
        created = self.create(ttl=8)
        identity = created["sandbox"]["id"]
        self.wait_operation(created["operation"]["id"])
        pause = self.request("POST", f"/v1/sandboxes/{identity}/pause", key=str(uuid.uuid4()))
        self.wait_operation(pause["id"])
        expires = datetime.fromisoformat(created["sandbox"]["expires_at"].replace("Z", "+00:00")).timestamp()
        self.stop("api")
        time.sleep(max(0, expires - time.time()))
        deadline = time.monotonic() + 20
        while docker("ps", "-a", "--filter", f"label=dev.goldenhoop.sandbox={identity}", "--format", "{{.ID}}"):
            if time.monotonic() >= deadline:
                raise AssertionError("expired runtime cleanup was not confirmed")
            time.sleep(0.1)
        self.expiry_cleanup_seconds = round(max(0, time.time() - expires), 3)
        self.launch("api")
        record = self.request("GET", f"/v1/sandboxes/{identity}")
        assert record["state"] == "terminated" and record["cleanup"] == "complete", record

    def failed_provision_and_repeat_delete_confirm_cleanup(self):
        failed = self.create(image="goldenhoop-does-not-exist:" + uuid.uuid4().hex)
        self.wait_operation(failed["operation"]["id"], expected="failed")
        record = self.request("GET", f"/v1/sandboxes/{failed['sandbox']['id']}")
        assert record["state"] == "failed" and record["cleanup"] == "complete", record
        for _ in range(2):
            operation = self.request("DELETE", f"/v1/sandboxes/{self.primary}", key=str(uuid.uuid4()))
            self.wait_operation(operation["id"])
        assert self.request("GET", f"/v1/sandboxes/{self.primary}")["cleanup"] == "complete"
        assert not docker("ps", "-a", "--filter", f"label=dev.goldenhoop.sandbox={self.primary}", "--format", "{{.ID}}")

    def actual_sdk_and_cli_contracts(self):
        root = Path(__file__).resolve().parents[1]
        environment = dict(os.environ)
        environment.update({"GOLDENHOOP_ENDPOINT": self.base, "GOLDENHOOP_API_TOKEN": self.token,
                            "GOLDENHOOP_TEST_PROFILE": "local-gvisor" if self.args.runtime == "runsc" else "local-runc-dev",
                            "GOLDENHOOP_TEST_IMAGE": self.args.image,
                            "GOLDENHOOP_TEST_DIRECTORY": str(self.root),
                            "PYTHONPATH": str(root / "sdk" / "python" / "src")})
        self.sdk_results = []
        for command in ([str(Path(self.args.rust_client).resolve())],
                        [sys.executable, "-B", str(root / "tests" / "client_contract.py"), "--cli", str(Path(self.args.cli).resolve())]):
            result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                                    env=environment, timeout=180,
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            assert result.returncode == 0, (command, result.stdout, result.stderr)
            self.sdk_results.append(json.loads(result.stdout))

    def diagnostics_use_actual_samples_and_distinguish_absence(self):
        created = self.create(ttl=90, memory=1073741824)
        sid = created["sandbox"]["id"]
        self.wait_operation(created["operation"]["id"])
        self.diagnostic_samples = []
        original = self.primary
        try:
            self.primary = sid
            before = self.request("GET", f"/v1/sandboxes/{sid}/diagnostics")
            self.diagnostic_samples.append(before)
            runtime = before["runtime"]
            assert runtime["running"] is True and runtime["exit_code"] is None and runtime["usage_error"] is None, before
            assert runtime["usage"]["memory_bytes"] > 0 and runtime["usage"]["host_tasks"] > 0, before
            command = self.execute(["python3", "-c", "import time;data=bytearray(b'x'*(32*1024*1024));print('allocated',flush=True);end=time.monotonic()+15\nwhile time.monotonic()<end: pass"], timeout=20)
            assert self.output(self.events(command["id"], first_output=True)) == b"allocated\n"
            busy = self.request("GET", f"/v1/sandboxes/{sid}/diagnostics")
            self.diagnostic_samples.append(busy)
            assert busy["runtime"]["usage"]["cpu_time_ns"] > runtime["usage"]["cpu_time_ns"], busy
            assert busy["runtime"]["usage"]["memory_bytes"] - runtime["usage"]["memory_bytes"] >= 16 * 1024 * 1024, self.diagnostic_samples
            pause = self.request("POST", f"/v1/sandboxes/{sid}/pause", key=str(uuid.uuid4()))
            self.wait_operation(pause["id"])
            paused = self.request("GET", f"/v1/sandboxes/{sid}/diagnostics")
            self.diagnostic_samples.append(paused)
            assert paused["runtime"]["paused"] is True and paused["runtime"]["usage"] is None, paused
            resume = self.request("POST", f"/v1/sandboxes/{sid}/resume", key=str(uuid.uuid4()))
            self.wait_operation(resume["id"])
            self.request("POST", f"/v1/executions/{command['id']}/cancel")
            assert self.wait_execution(command["id"])["state"] == "cancelled"
        finally:
            self.primary = original
            operation = self.request("DELETE", f"/v1/sandboxes/{sid}", key=str(uuid.uuid4()))
            self.wait_operation(operation["id"])
        removed = self.request("GET", f"/v1/sandboxes/{sid}/diagnostics")
        self.diagnostic_samples.append(removed)
        assert removed["runtime"] is None and removed["sandbox"]["cleanup"] == "complete", removed

    def pid_pressure_is_bounded_and_cleanup_is_confirmed(self):
        created = self.create(ttl=90, memory=1073741824)
        identity = created["sandbox"]["id"]
        self.wait_operation(created["operation"]["id"])
        container = self.container(identity)
        config = json.loads(docker("inspect", container))[0]["HostConfig"]
        assert config["PidsLimit"] == 128 and config["Memory"] == 1073741824
        self.pid_pressure = {"sandbox_id": identity, "memory_bytes": config["Memory"],
                             "pids_cgroup_limit": config["PidsLimit"]}
        started = datetime.now(timezone.utc).isoformat()
        original = self.primary
        try:
            self.primary = identity
            code = """import os,time
for i in range(256):
    try: child=os.fork()
    except OSError: break
    if child==0:
        time.sleep(30)
        os._exit(0)
print('bounded PID saturation started',flush=True)
time.sleep(30)
"""
            command = self.execute(["python3", "-c", code], timeout=40)
        finally:
            self.primary = original
        time.sleep(1)
        # The worker may have observed a runtime crash and already removed it.
        remaining = docker("ps", "-a", "--filter", f"id={container}", "--format", "{{.ID}}")
        observed = json.loads(docker("inspect", container))[0] if remaining else None
        self.pid_pressure["before_cancel_state"] = observed["State"] if observed else "absent"
        self.pid_pressure["before_cancel_execution"] = self.request("GET", f"/v1/executions/{command['id']}")
        if observed and observed["State"]["Running"]:
            self.pid_pressure["before_cancel_stats"] = json.loads(docker("stats", "--no-stream", "--format", "{{json .}}", container))
        if self.args.runtime == "runc":
            assert int(self.pid_pressure["before_cancel_stats"]["PIDs"]) >= 120, self.pid_pressure
        self.request("POST", f"/v1/executions/{command['id']}/cancel")
        terminal = self.wait_execution(command["id"], limit=40)
        self.pid_pressure["terminal_execution"] = terminal
        record = self.request("GET", f"/v1/sandboxes/{identity}")
        self.pid_pressure["terminal_sandbox"] = record
        events = docker("events", "--since", started, "--until", datetime.now(timezone.utc).isoformat(),
                        "--filter", f"container={container}", "--format", "{{json .}}")
        self.pid_pressure["runtime_events"] = [event for line in events.splitlines()
                                               if (event := json.loads(line)).get("Action") in ("oom", "die", "kill", "destroy")]
        if terminal["state"] == "failed":
            # A runtime crash under its host task quota is a failure, never a
            # successful command cancellation. Require observed exit + removal.
            self.pid_pressure["outcome"] = "runtime_failed_and_removed"
            assert "runtime exited" in (record.get("reason") or ""), self.pid_pressure
            assert any(event.get("Action") == "die" for event in self.pid_pressure["runtime_events"]), self.pid_pressure
            assert record["state"] == "failed" and record["cleanup"] == "complete", self.pid_pressure
        else:
            self.pid_pressure["outcome"] = "cancelled_with_confirmed_cleanup"
            assert terminal["state"] == "cancelled", self.pid_pressure
        if record["state"] in ("terminated", "failed"):
            assert record["cleanup"] == "complete"
            assert not docker("ps", "-a", "--filter", f"id={container}", "--format", "{{.ID}}")
        else:
            code = """from pathlib import Path
alive=[]
for p in Path('/proc').glob('[0-9]*/status'):
    try: text=p.read_text()
    except FileNotFoundError: continue
    lines=text.splitlines()
    uid=next((v.split()[1] for v in lines if v.startswith('Uid:')),None)
    state=next((v.split()[1] for v in lines if v.startswith('State:')),None)
    if uid=='1000' and state not in ('Z','X'): alive.append(str(p))
assert not alive,alive
"""
            docker("exec", "--user", "0", container, "python3", "-c", code)

    def cleanup(self):
        for role in list(self.processes):
            self.stop(role)
        if not self.installation and self.database.exists():
            with closing(sqlite3.connect(self.database)) as connection:
                row = connection.execute("SELECT value FROM meta WHERE key='installation_id'").fetchone()
                self.installation = row[0] if row else None
        if self.installation:
            installation = str(uuid.UUID(self.installation))
            ids = docker("ps", "-a", "--no-trunc", "--filter",
                         f"label=dev.goldenhoop.installation={installation}", "--format", "{{.ID}}")
            for identity in ids.splitlines():
                labels = json.loads(docker("inspect", "--format", "{{json .Config.Labels}}", identity))
                assert labels["dev.goldenhoop.installation"] == installation
                assert labels["dev.goldenhoop.role"] in ("sandbox", "bootstrap")
                docker("rm", "-f", identity)
            volumes = docker("volume", "ls", "--filter", f"label=dev.goldenhoop.installation={installation}", "--format", "{{.Name}}")
            for name in volumes.splitlines():
                labels = json.loads(docker("volume", "inspect", "--format", "{{json .Labels}}", name))
                assert labels["dev.goldenhoop.installation"] == installation
                assert labels["dev.goldenhoop.role"] == "agent-bundle"
                docker("volume", "rm", name)
            assert not docker("ps", "-a", "--filter", f"label=dev.goldenhoop.installation={installation}", "--format", "{{.ID}}")
            assert not docker("volume", "ls", "--filter", f"label=dev.goldenhoop.installation={installation}", "--format", "{{.Name}}")
        for handle in self.log_handles:
            handle.close()

    def run(self):
        evidence = {"suite": "api-worker-contract", "runtime": self.args.runtime,
                    "cases": self.results, "timestamp": datetime.now(timezone.utc).isoformat(),
                    "result": "failed", "cleanup": "unknown"}
        failure = None
        try:
            self.launch("api")
            self.launch("worker")
            cases = ("authentication_and_profile_refusal", "lifecycle_commands_files_and_events",
                         "observer_disconnect_and_resume", "command_failure_timeout_cancel_and_idempotency",
                         "worker_restart_retains_runtime_and_executes_once",
                         "api_restart_keeps_results_and_private_worker_route_is_restricted",
                         "paused_expiry_continues_while_api_is_down",
                         "pid_pressure_is_bounded_and_cleanup_is_confirmed",
                         "failed_provision_and_repeat_delete_confirm_cleanup",
                         "diagnostics_use_actual_samples_and_distinguish_absence")
            for name in (() if self.args.clients_only else cases):
                self.check(name, getattr(self, name))
            if self.args.rust_client and self.args.cli:
                self.check("actual_sdk_and_cli_contracts", self.actual_sdk_and_cli_contracts)
            root = Path(__file__).resolve().parents[1]
            sources = [root / "Cargo.toml", root / "Cargo.lock", Path(__file__).resolve()]
            sources.extend((root / "crates").rglob("*.rs"))
            sources.extend((root / "crates").rglob("*.sql"))
            sources.extend((root / "crates").rglob("Cargo.toml"))
            if self.args.rust_client:
                sources.extend((root / "sdk").rglob("*.py"))
                sources.extend((root / "sdk").rglob("pyproject.toml"))
                sources.append(root / "tests" / "client_contract.py")
                evidence["client_binary_sha256"] = {name: hashlib.sha256(Path(path).read_bytes()).hexdigest()
                                                     for name, path in (("rust", self.args.rust_client), ("cli", self.args.cli))}
            evidence["source_files_sha256"] = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(sources)}
            with Path(self.args.binary).open("rb") as binary:
                evidence["binary_sha256"] = hashlib.file_digest(binary, "sha256").hexdigest()
            evidence["agent_image_id"] = docker("image", "inspect", "--format", "{{.Id}}", self.args.image)
            evidence["docker"] = json.loads(docker("version", "--format", "{{json .Server}}"))
            evidence["result"] = "passed"
        except BaseException as error:
            failure = error
            evidence["error"] = str(error)
        finally:
            try:
                self.cleanup()
                evidence["cleanup"] = "complete"
            except BaseException as error:
                evidence["cleanup_error"] = str(error)
                failure = failure or error
                evidence["result"] = "failed"
            evidence["installation_id"] = self.installation
            if failure:
                evidence["service_logs"] = {p.name: p.read_text(encoding="utf-8", errors="replace")[-20000:] for p in self.logs}
            assert self.root.is_relative_to(self.work)
            try:
                self.temporary.cleanup()
                evidence["temporary_files_removed"] = not self.root.exists()
            except BaseException as error:
                evidence["temporary_files_removed"] = False
                evidence["cleanup_error"] = str(error)
                evidence["result"] = "failed"
                failure = failure or error
            evidence["expiry_cleanup_seconds"] = getattr(self, "expiry_cleanup_seconds", None)
            evidence["pid_pressure"] = getattr(self, "pid_pressure", None)
            evidence["sdk_results"] = getattr(self, "sdk_results", None)
            evidence["diagnostic_samples"] = getattr(self, "diagnostic_samples", None)
            rendered = json.dumps(evidence, indent=2)
            print(rendered, flush=True)
            if self.args.output:
                Path(self.args.output).parent.mkdir(parents=True, exist_ok=True)
                Path(self.args.output).write_text(rendered + "\n", encoding="utf-8")
        if failure:
            raise failure


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--image", default="goldenhoop-agent:test")
    parser.add_argument("--runtime", choices=("runc", "runsc"), default="runc")
    parser.add_argument("--work-dir", default=".test-work")
    parser.add_argument("--output")
    parser.add_argument("--rust-client")
    parser.add_argument("--cli")
    parser.add_argument("--clients-only", action="store_true")
    arguments = parser.parse_args()
    if bool(arguments.rust_client) != bool(arguments.cli):
        parser.error("--rust-client and --cli must be supplied together")
    if arguments.clients_only and not arguments.rust_client:
        parser.error("--clients-only requires --rust-client and --cli")
    Contract(arguments).run()
