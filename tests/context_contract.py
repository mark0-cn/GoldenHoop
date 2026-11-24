"""Actual sandbox-agent code contexts. Never runs workloads on the host."""
import argparse
import base64
import hashlib
import json
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agent_contract import Contract, AgentError, docker, logs, source_fingerprint


class ContextContract(Contract):
    def __init__(self, image, runtime):
        super().__init__(image, runtime)
        self.cursors, self.history = {}, {}
        self.observations = []
        self.attempt = str(uuid.uuid4())

    def start(self):
        self.container = "goldenhoop-context-" + uuid.uuid4().hex[:12]
        args = ["run", "-d", "--name", self.container, "--runtime", self.runtime,
                "--label", "dev.goldenhoop.test=agent-contract", "--label", "dev.goldenhoop.context-test=" + self.attempt,
                "--network", "none", "--read-only", "--init", "--cap-drop", "ALL"]
        for cap in ["SETUID", "SETGID", "KILL", "CHOWN", "FOWNER", "DAC_OVERRIDE"]:
            args.extend(["--cap-add", cap])
        args.extend(["--security-opt", "no-new-privileges", "--memory", "1g", "--cpus", "1", "--pids-limit", "256",
                     "--tmpfs", "/workspace:rw,nosuid,nodev,size=128m,uid=1000,gid=1000,mode=2770",
                     "--tmpfs", "/tmp:rw,nosuid,nodev,size=32m,mode=1777",
                     "--tmpfs", "/run/goldenhoop:rw,nosuid,nodev,size=32m,mode=700",
                     "--entrypoint", "/usr/local/bin/goldenhoop-agent", self.image, "serve"])
        self.container = docker(*args)
        for _ in range(50):
            try:
                self.rpc({"method": "ping"})
                return
            except (RuntimeError, ValueError):
                time.sleep(.1)
        raise AssertionError("context agent did not start: " + logs(self.container))

    def context(self, identity):
        return self.rpc({"method": "code_context_get", "id": identity})["value"]

    def code_run(self, context, identity):
        return self.rpc({"method": "code_run_get", "context_id": context, "id": identity})["value"]

    def drain(self, context):
        events = self.rpc({"method": "code_context_events", "id": context, "after": self.cursors.get(context, 0)})["value"]
        for event in events:
            assert event["sequence"] == self.cursors.get(context, 0) + 1, event
            self.cursors[context] = event["sequence"]
        self.history.setdefault(context, []).extend(events)
        return self.history[context]

    def wait_context(self, identity, target="ready", timeout=35):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            record = self.context(identity)
            self.drain(identity)
            if record["state"] == target:
                if target != "ready":
                    assert record["cleanup"] == "complete" and record["finished_at"], record
                return record
            assert record["state"] not in ("failed", "closed", "unknown"), record
            time.sleep(.05)
        raise AssertionError(("context wait timed out", record, target))

    def new_context(self, wait=True):
        identity = str(uuid.uuid4())
        self.rpc({"method": "code_context_create", "id": identity, "spec": {}})
        if wait:
            self.wait_context(identity)
        return identity

    def start_code(self, context, code, timeout=10, output_limit=1024 * 1024, identity=None):
        identity = identity or str(uuid.uuid4())
        request = {"method": "code_run_start", "context_id": context, "id": identity,
                   "spec": {"code": code, "timeout_seconds": timeout, "max_output_bytes": output_limit}}
        self.rpc(request)
        return identity, request

    def wait_code(self, context, identity, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            record = self.code_run(context, identity)
            events = self.drain(context)
            if record["finished_at"]:
                events = self.drain(context)
                selected = [event for event in events if event["run_id"] == identity]
                assert sum(event["kind"] == "run_completed" for event in selected) == 1, selected
                self.observations.append({"context_id": context, "run": record, "events": selected})
                return record, selected
            time.sleep(.05)
        raise AssertionError(("code wait timed out", record))

    def code(self, context, code, **kwargs):
        identity, _ = self.start_code(context, code, **kwargs)
        return self.wait_code(context, identity)

    def close(self, context):
        self.rpc({"method": "code_context_close", "id": context})
        return self.wait_context(context, "closed")

    @staticmethod
    def text(events, kind="stdout"):
        return "".join(event["data"]["content"]["text"] for event in events if event["kind"] == kind)

    def no_retired_context_processes_or_private_files(self):
        report = json.loads(docker("exec", "--user", "0", self.container, "python3", "-c",
            "import pathlib,json; alive=[]; "
            "exec(\"for p in pathlib.Path('/proc').glob('[0-9]*/status'):\\n try:\\n  s=p.read_text();uid=int(s.split('Uid:')[1].split()[0]);state=s.split('State:')[1].strip()[0]\\n  if 20000<=uid<20004 and state not in 'ZX':alive.append(str(p))\\n except FileNotFoundError:pass\"); "
            "print(json.dumps({'alive':alive,'directories':[str(q) for p in pathlib.Path('/tmp').glob('ghctx-*') for q in p.iterdir()]}))"))
        assert report == {"alive": [], "directories": []}, report

    def state_results_identity_and_replay(self):
        context = self.new_context()
        create = {"method": "code_context_create", "id": context, "spec": {}}
        assert self.rpc(create)["value"]["id"] == context
        self.reject({**create, "spec": {"cwd": "."}}, ("conflict",))
        self.reject({"method": "code_context_events", "id": context, "after": 1000000}, ("invalid_request",))
        self.rpc({"method": "write_file", "path": "shared/data.txt", "data_base64": base64.b64encode(b"one").decode()})
        code = ("import os,sys,stat,pathlib\nassert 20000<=os.getuid()<20004 and os.getgid()==1000 and os.getgroups()==[]\n"
                "status=open('/proc/self/status').read()\nassert 'CapEff:\\t0000000000000000' in status and 'NoNewPrivs:\\t1' in status\n"
                "private=pathlib.Path(os.environ['HOME'])\nassert private.stat().st_uid==os.getuid() and stat.S_IMODE(private.stat().st_mode) in (0o700,0o1700)\n"
                "assert stat.S_IMODE((private/'connection.json').stat().st_mode)==0o600\nassert private.parent.stat().st_uid==0 and stat.S_IMODE(private.parent.stat().st_mode)==0o711\n"
                "assert 'GOLDENHOOP_API_TOKEN' not in os.environ\n"
                "with open('shared/data.txt','a') as f:f.write('x')\nshared=40\nprint('first')\nprint('err',file=sys.stderr)")
        identity, request = self.start_code(context, code)
        self.rpc(request)
        record, events = self.wait_code(context, identity)
        assert record["state"] == "kernel_succeeded" and record["kernel_status"] == "ok", record
        assert self.text(events) == "first\n" and self.text(events, "stderr") == "err\n"
        assert self.rpc(request)["value"]["finished_at"] == record["finished_at"]
        self.reject({**request, "spec": {"code": "print('different')"}}, ("conflict",))
        record, events = self.code(context, "assert open('shared/data.txt').read()=='onex'\nprint(shared+2)\nshared+2")
        assert record["state"] == "kernel_succeeded" and self.text(events) == "42\n", record
        assert any(event["kind"] == "result" and event["data"]["content"]["data"]["text/plain"] == "42" for event in events)
        record, events = self.code(context, "raise ValueError('expected')")
        assert record["state"] == "kernel_failed" and record["kernel_status"] == "error", record
        assert any(event["kind"] == "kernel_error" and event["data"]["content"]["ename"] == "ValueError" for event in events)
        background, _ = self.start_code(context, "import threading,time\ndef later():\n time.sleep(.5)\n print('late-background',flush=True)\nthreading.Thread(target=later).start()")
        before, _ = self.wait_code(context, background)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            events = self.drain(context)
            if any(event["kind"] == "stdout" and event["data"]["late"] and "late-background" in event["data"]["content"]["text"] for event in events):
                break
            time.sleep(.05)
        else:
            raise AssertionError("late background output was not recorded separately")
        assert self.code_run(context, background) == before
        assert self.code(context, "assert shared==40")[0]["state"] == "kernel_succeeded"
        self.close(context)
        self.no_retired_context_processes_or_private_files()

    def independent_contexts_and_command_coexistence(self):
        first, second = self.new_context(False), self.new_context(False)
        self.wait_context(first)
        self.wait_context(second)
        a, _ = self.start_code(first, "import time\ntoken='a'\ntime.sleep(4)\ntoken")
        b, _ = self.start_code(second, "assert 'token' not in globals()\ntoken='b'\nprint(token)")
        (command, _), _ = self.execute(["python3", "-c", "import os; assert os.getuid()==1000; print('command')"])
        assert command["state"] == "succeeded", command
        rb, events = self.wait_code(second, b)
        ra, _ = self.wait_code(first, a)
        assert ra["state"] == rb["state"] == "kernel_succeeded" and self.text(events) == "b\n"
        assert rb["finished_at"] < ra["finished_at"], (ra, rb)
        self.close(first)
        assert self.code(second, "assert token=='b'")[0]["state"] == "kernel_succeeded"
        self.close(second)
        self.no_retired_context_processes_or_private_files()

    def escaped_code(self, marker):
        child = f"import os,time;os.setsid();open('/workspace/{marker}','w').write(str(os.getpid()));time.sleep(30)"
        return f"import subprocess,time\np=subprocess.Popen(['python3','-c',{child!r}])\nprint('ready',flush=True)\ntime.sleep(30)"

    def cancellation_collects_setsid_and_queued_run(self):
        context = self.new_context()
        identity, _ = self.start_code(context, self.escaped_code("cancel-child"), timeout=30)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                self.rpc({"method": "read_file", "path": "cancel-child", "max_bytes": 128})
                break
            except AgentError:
                time.sleep(.05)
        else:
            raise AssertionError("escaped descendant never became observable")
        queued, _ = self.start_code(context, "open('/workspace/must-not-run','w').write('bad')")
        self.rpc({"method": "code_run_cancel", "context_id": context, "id": identity})
        assert self.wait_code(context, identity)[0]["state"] == "cancelled"
        assert self.wait_code(context, queued)[0]["state"] == "cancelled"
        self.wait_context(context, "closed")
        self.reject({"method": "read_file", "path": "must-not-run", "max_bytes": 128}, ("not_found",))
        self.no_retired_context_processes_or_private_files()

    def timeout_collects_setsid(self):
        context = self.new_context()
        record, _ = self.code(context, self.escaped_code("timeout-child"), timeout=2)
        assert record["state"] == "timed_out" and record["kernel_status"] is None, record
        self.wait_context(context, "closed")
        self.no_retired_context_processes_or_private_files()

    def crash_epoch_change_and_no_relaunch(self):
        for code in ["import os\nos._exit(7)", "get_ipython().kernel.session.session = 'changed-epoch'"]:
            context = self.new_context()
            identity, request = self.start_code(context, code)
            record, _ = self.wait_code(context, identity)
            assert record["state"] == "unknown" and record["kernel_status"] is None, record
            failed = self.wait_context(context, "failed")
            if "session.session" in code:
                assert "session changed" in failed["reason"], failed
            assert self.rpc(request)["value"]["finished_at"] == record["finished_at"]
            assert self.rpc({"method": "code_context_create", "id": context, "spec": {}})["value"]["state"] == "failed"
            self.reject({"method": "code_run_start", "context_id": context, "id": str(uuid.uuid4()), "spec": {"code": "print(1)"}}, ("invalid_state",))
            self.no_retired_context_processes_or_private_files()

    def bounded_output_and_oversized_wire_refusal(self):
        context = self.new_context()
        record, events = self.code(context, "print('x'*10000)", output_limit=512)
        assert record["state"] == "kernel_succeeded" and record["output_truncated"], record
        assert sum(event["kind"] == "output_truncated" for event in events) == 1
        self.close(context)
        context = self.new_context()
        code = "k=get_ipython().kernel\nk.session.send(k.iopub_socket,'display_data',content={'data':{'text/plain':'x'*(3*1024*1024)},'metadata':{}},parent=k.get_parent())"
        record, _ = self.code(context, code)
        assert record["state"] == "unknown", record
        failed = self.wait_context(context, "failed")
        assert "receive limits" in failed["reason"], failed
        self.no_retired_context_processes_or_private_files()

    def bounded_uid_pool_releases_only_after_cleanup(self):
        contexts = [self.new_context(False) for _ in range(4)]
        for context in contexts:
            self.wait_context(context)
        self.reject({"method": "code_context_create", "id": str(uuid.uuid4()), "spec": {}}, ("quota_exceeded",))
        self.close(contexts.pop())
        contexts.append(self.new_context())
        for context in contexts:
            assert self.code(context, "print('still-alive')")[0]["state"] == "kernel_succeeded"
            self.close(context)
        self.no_retired_context_processes_or_private_files()

    def close_during_startup_does_not_publish_late_ready(self):
        context = self.new_context(False)
        self.close(context)
        assert self.rpc({"method": "code_context_create", "id": context, "spec": {}})["value"]["state"] == "closed"
        self.no_retired_context_processes_or_private_files()

    def missing_kernel_does_not_relaunch(self):
        docker("exec", "--user", "0", self.container, "python3", "-I", "-c",
               "import importlib.util;assert importlib.util.find_spec('ipykernel_launcher') is None")
        context = self.new_context(False)
        record = self.wait_context(context, "failed")
        assert record["ready_at"] is None and record["kernel_info"] is None and "kernel startup failed" in record["reason"], record
        assert self.rpc({"method": "code_context_create", "id": context, "spec": {}})["value"] == record
        self.reject({"method": "code_run_start", "context_id": context, "id": str(uuid.uuid4()), "spec": {"code": "print(1)"}}, ("invalid_state",))
        self.observations.append({"context": record})
        self.no_retired_context_processes_or_private_files()

    def unimplemented_language_never_allocates_or_falls_back_to_python(self):
        for language in ("java", "go", "typescript", "bash", "javascript"):
            identity = str(uuid.uuid4())
            self.reject({"method": "code_context_create", "id": identity, "spec": {"language": language}}, ("unsupported_capability",))
            self.reject({"method": "code_context_get", "id": identity}, ("not_found",))
        self.no_retired_context_processes_or_private_files()

    def run_contexts(self, output, remove_image, missing_kernel=False):
        evidence = {"suite": "agent-code-context-contract", "timestamp": datetime.now(timezone.utc).isoformat(),
                    "runtime": self.runtime, "attempt": self.attempt, "result": "failed", "cleanup": "unknown", "cases": self.results,
                    "observations": self.observations, "source_files_sha256": source_fingerprint()}
        root = Path(__file__).resolve().parents[1]
        for path in [Path(__file__).resolve(), root / "images/kernel/Dockerfile"]:
            evidence["source_files_sha256"][path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        failure = None
        try:
            self.start()
            inspected = json.loads(docker("inspect", self.container))[0]
            evidence["image_id"], evidence["host_config"] = inspected["Image"], inspected["HostConfig"]
            assert inspected["HostConfig"]["Runtime"] == self.runtime and inspected["HostConfig"]["Memory"] == 1073741824
            assert inspected["HostConfig"]["PidsLimit"] == 256 and inspected["HostConfig"]["NetworkMode"] == "none"
            assert inspected["HostConfig"]["ReadonlyRootfs"] and "ALL" in inspected["HostConfig"]["CapDrop"]
            evidence["docker"] = json.loads(docker("version", "--format", "{{json .Server}}"))
            if self.runtime == "runsc":
                evidence["runsc_version"] = subprocess.run(["runsc", "--version"], capture_output=True, text=True, check=True, timeout=10).stdout.strip()
            names = ["state_results_identity_and_replay", "independent_contexts_and_command_coexistence",
                         "cancellation_collects_setsid_and_queued_run", "timeout_collects_setsid", "crash_epoch_change_and_no_relaunch",
                         "bounded_output_and_oversized_wire_refusal", "bounded_uid_pool_releases_only_after_cleanup",
                         "close_during_startup_does_not_publish_late_ready"]
            if missing_kernel:
                names = ["missing_kernel_does_not_relaunch"]
            names.insert(0, "unimplemented_language_never_allocates_or_falls_back_to_python")
            for name in names:
                self.check(name, getattr(self, name))
            evidence["result"] = "passed"
        except BaseException as error:
            failure = error
            evidence["error"] = str(error)
            if self.container:
                evidence["logs"] = logs(self.container)[-65536:]
        finally:
            try:
                self.cleanup()
                if remove_image:
                    info = json.loads(docker("image", "inspect", self.image))[0]
                    assert info["Config"]["Labels"].get("dev.goldenhoop.fixture") == "kernel-interop"
                    assert not docker("ps", "-a", "--filter", "ancestor=" + self.image, "--format", "{{.ID}}")
                    docker("image", "rm", self.image)
                    assert subprocess.run(["docker", "image", "inspect", self.image], capture_output=True, timeout=10).returncode != 0
                    evidence["fixture_image_removed"] = True
                evidence["cleanup"] = "complete"
            except BaseException as error:
                evidence["cleanup_error"] = str(error)
                evidence["result"] = "failed"
                failure = failure or error
            if output:
                Path(output).parent.mkdir(parents=True, exist_ok=True)
                Path(output).write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
            print(json.dumps({key: evidence.get(key) for key in ["suite", "runtime", "result", "cleanup", "cases", "error"]}))
        if failure:
            raise failure


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", default="goldenhoop-kernel-fixture:test")
    parser.add_argument("--runtime", choices=["runc", "runsc"], default="runc")
    parser.add_argument("--output")
    parser.add_argument("--remove-image", action="store_true")
    parser.add_argument("--missing-kernel", action="store_true", help="exercise explicit failure on the minimal agent image")
    args = parser.parse_args()
    ContextContract(args.image, args.runtime).run_contexts(args.output, args.remove_image, args.missing_kernel)
