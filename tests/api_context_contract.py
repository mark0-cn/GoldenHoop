"""Public context tests use the real independent API, worker and selected runtime."""
import base64
import json
import sqlite3
import subprocess
import time
import urllib.parse
import urllib.request
import uuid
from contextlib import closing


def docker(*args):
    result = subprocess.run(["docker", *args], capture_output=True, text=True,
                            encoding="utf-8", timeout=20)
    if result.returncode:
        raise RuntimeError(f"Docker {args[0]} failed: {result.stderr.strip()}")
    return result.stdout.strip()


class ContextCases:
    context_cases = (
        "code_state_replays_and_actual_service_restarts",
        "code_cancel_and_timeout_collect_escaped_descendants",
        "code_kernel_failure_limits_and_missing_dependencies",
        "code_runtime_loss_never_replays_queued_work",
        "code_missing_dispatched_context_requires_whole_runtime_removal",
        "code_paused_expiry_is_collected_while_api_is_down",
    )

    def code_box(self, ttl=180, image=None):
        profile = "local-gvisor" if self.args.runtime == "runsc" else "local-runc-dev"
        observed = next(p for p in self.request("GET", "/v1/profiles") if p["id"] == profile)
        assert "code_contexts" in observed["capabilities"], observed
        assert "python" in observed["code_languages"], observed
        assert set(observed["code_languages"]) == set(self.args.code_languages), observed
        value = self.request("POST", "/v1/sandboxes", {
            "profile": profile, "image": image or self.args.kernel_image,
            "ttl_seconds": ttl, "required_capabilities": ["code_contexts", "artifacts"],
            "resources": {"cpu_millis": 1000, "memory_bytes": 1073741824, "pids": 256},
        }, str(uuid.uuid4()))
        self.wait_operation(value["operation"]["id"])
        return value["sandbox"]["id"]

    def new_code_context(self, sandbox, wait=True, key=None):
        value = self.request("POST", f"/v1/sandboxes/{sandbox}/code-contexts", {}, key or str(uuid.uuid4()))
        if wait:
            return self.wait_context(value["id"])
        return value

    def wait_context(self, identity, target="ready", timeout=40):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = self.request("GET", f"/v1/code-contexts/{identity}")
            if value["state"] == target and (target == "ready" or value["cleanup"] == "complete"):
                return value
            if target == "ready":
                assert value["state"] not in ("closed", "failed", "unknown"), value
            time.sleep(.1)
        raise AssertionError(("context did not reach expected state", value, target))

    def close_context(self, identity):
        self.request("DELETE", f"/v1/code-contexts/{identity}", key=str(uuid.uuid4()))
        return self.wait_context(identity, "closed")

    def start_code(self, context, code, timeout=15, output_limit=1024*1024, key=None):
        return self.request("POST", f"/v1/code-contexts/{context}/runs", {
            "code": code, "timeout_seconds": timeout, "max_output_bytes": output_limit,
        }, key or str(uuid.uuid4()))

    def wait_code(self, accepted, timeout=35):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = self.request("GET", f"/v1/code-runs/{accepted['id']}")
            if value["finished_at"]:
                events = self.code_events(accepted["context_id"], accepted["events_after"], until_run=value["id"])
                selected = [event for event in events if event["run_id"] == value["id"]]
                assert sum(event["kind"] == "run_completed" for event in selected) == 1, selected
                if not hasattr(self, "context_observations"):
                    self.context_observations = []
                self.context_observations.append({"run": value, "events": selected})
                return value, selected
            time.sleep(.1)
        raise AssertionError(("code result was not collected", value))

    def code(self, context, code, **kwargs):
        return self.wait_code(self.start_code(context, code, **kwargs))

    def code_events(self, context, after=0, until_run=None, first_output=False):
        headers = {"authorization": "Bearer " + self.token, "last-event-id": f"{context}:{after}"}
        request = urllib.request.Request(self.base + f"/v1/code-contexts/{context}/events", headers=headers)
        values, data, event_id, kind, cursor = [], [], None, None, after
        with self.client.open(request, timeout=35) as response:
            for raw in response:
                assert len(raw) <= 2*1024*1024+16384, "oversized public context event"
                line = raw.decode().rstrip("\r\n")
                if line.startswith("id:"):
                    event_id = line[3:].strip()
                elif line.startswith("event:"):
                    kind = line[6:].strip()
                elif line.startswith("data:"):
                    data.append(line[5:].lstrip())
                elif not line and data:
                    value = json.loads("\n".join(data))
                    assert kind == "code_context", (kind, value)
                    assert value["context_id"] == context and value["sequence"] == cursor+1, value
                    assert event_id == f"{context}:{value['sequence']}", event_id
                    cursor = value["sequence"]
                    values.append(value)
                    data, event_id, kind = [], None, None
                    if until_run == value["run_id"] and value["kind"] == "run_completed":
                        return values
                    if first_output and value["kind"] == "stdout":
                        return values
        assert values and values[-1]["kind"] == "closed", values
        return values

    @staticmethod
    def code_stdout(events):
        return "".join(event["data"]["content"]["text"] for event in events if event["kind"] == "stdout")

    def code_file(self, sandbox, path):
        value = self.request("GET", f"/v1/sandboxes/{sandbox}/files?"+urllib.parse.urlencode({"path": path, "max_bytes": 4096}))
        return base64.b64decode(value["data_base64"])

    def wait_code_file(self, sandbox, path):
        deadline = time.monotonic()+10
        while time.monotonic() < deadline:
            try:
                return self.code_file(sandbox, path)
            except RuntimeError as error:
                if not hasattr(error, "status") or error.status != 404:
                    raise
            time.sleep(.1)
        raise AssertionError(f"kernel marker was never observed: {path}")

    def no_context_processes(self, sandbox):
        code = """from pathlib import Path
alive=[]
for path in Path('/proc').glob('[0-9]*/status'):
    try: lines=path.read_text().splitlines()
    except FileNotFoundError: continue
    uid=next((line.split()[1] for line in lines if line.startswith('Uid:')),None)
    state=next((line.split()[1] for line in lines if line.startswith('State:')),None)
    if uid and 20000<=int(uid)<20004 and state not in ('Z','X'): alive.append(str(path))
assert not alive,alive
assert not [child for parent in Path('/tmp').glob('ghctx-*') for child in parent.iterdir()]
"""
        docker("exec", "--user", "0", self.container(sandbox), "python3", "-c", code)

    def stop_code_box(self, sandbox):
        value = self.request("DELETE", f"/v1/sandboxes/{sandbox}", key=str(uuid.uuid4()))
        self.wait_operation(value["id"])

    def code_advertised_languages_retain_state_across_service_restarts(self):
        from language_samples import SAMPLES
        sandbox = self.code_box(ttl=600)
        container = self.container(sandbox)
        try:
            languages = self.args.code_languages
            # Stay within four simultaneous contexts and the shared 1-GiB budget.
            for offset in range(0,len(languages),3):
                retained=[]
                for language in languages[offset:offset+3]:
                    key=str(uuid.uuid4())
                    spec={"language":language}
                    context=self.request("POST",f"/v1/sandboxes/{sandbox}/code-contexts",spec,key)
                    ready=self.wait_context(context['id'])
                    assert ready['spec']['language']==language and ready['kernel_info']['language_info']['name']==language
                    first,second,error=SAMPLES[language]
                    run_key=str(uuid.uuid4())
                    accepted=self.start_code(context['id'],first,timeout=30,key=run_key)
                    result,events=self.wait_code(accepted,timeout=45)
                    output=self.code_stdout(events)
                    assert result['state']=='kernel_succeeded' and output.endswith('kernel-start\n') and output.count('kernel-start\n')==1, (result,events)
                    retained.append((language,key,spec,context,run_key,first,second,error,result))
                self.stop('worker')
                self.stop('api')
                self.launch('api')
                self.launch('worker')
                assert self.container(sandbox)==container
                for language,key,spec,context,run_key,first,second,error,result in retained:
                    replay=self.request('POST',f'/v1/sandboxes/{sandbox}/code-contexts',spec,key)
                    assert replay['id']==context['id']
                    assert self.start_code(context['id'],first,timeout=30,key=run_key)==result
                    assert self.code_file(sandbox,'lang-replay-'+language)==b'x'
                    result,events=self.code(context['id'],second)
                    assert result['state']=='kernel_succeeded' and self.code_stdout(events)=='42\n', (result,events)
                    result,events=self.code(context['id'],error)
                    assert result['state']=='kernel_failed' and result['kernel_status']=='error', (result,events)
                    assert self.wait_context(context['id'])['state']=='ready'
                    self.close_context(context['id'])
            self.no_context_processes(sandbox)
        finally:
            self.stop_code_box(sandbox)

    def code_state_replays_and_actual_service_restarts(self):
        sandbox = self.code_box()
        for language in ("java", "go", "typescript", "bash", "javascript"):
            if language in self.args.code_languages:
                continue
            self.reject("POST", f"/v1/sandboxes/{sandbox}/code-contexts", 422, "unsupported_capability",
                        body={"language": language}, key=str(uuid.uuid4()))
        assert not self.request("GET", f"/v1/code-contexts?sandbox_id={sandbox}")["items"]
        container = self.container(sandbox)
        context = self.new_code_context(sandbox, key="retained-context")
        record, _ = self.code(context["id"], "import os\nassert 20000<=os.getuid()<20004 and os.getgid()==1000 and os.getgroups()==[]\nassert 'CapEff:\\t0000000000000000' in open('/proc/self/status').read()\ncounter=40")
        assert record["state"] == "kernel_succeeded", record
        snippet = "import time\ncounter+=1\nopen('/workspace/context-once','a').write('x')\ntime.sleep(2)\nprint(counter)\ncounter"
        accepted = self.start_code(context["id"], snippet, key="increment-once")
        self.wait_code_file(sandbox, "context-once")
        self.stop("worker")
        self.stop("api")
        self.launch("api")
        self.launch("worker")
        assert self.container(sandbox) == container
        assert self.new_code_context(sandbox, key="retained-context")["id"] == context["id"]
        replay = self.start_code(context["id"], snippet, key="increment-once")
        assert (replay["id"], replay["events_after"]) == (accepted["id"], accepted["events_after"])
        record, events = self.wait_code(replay)
        assert record["state"] == "kernel_succeeded" and self.code_stdout(events) == "41\n", (record, events)
        assert self.code_file(sandbox, "context-once") == b"x"
        record, events = self.code(context["id"], "counter+=1\nprint(counter)\ncounter")
        assert record["state"] == "kernel_succeeded" and self.code_stdout(events) == "42\n"
        assert any(event["kind"] == "result" and event["data"]["content"]["data"]["text/plain"] == "42" for event in events)
        second = self.new_code_context(sandbox)
        assert self.code_stdout(self.code(second["id"], "print('counter' in globals())")[1]) == "False\n"
        other = self.request("POST", f"/v1/sandboxes/{sandbox}/commands", {"argv":["python3","-c","import os;print(os.getuid())"]},str(uuid.uuid4()))
        assert self.wait_execution(other["id"])["state"] == "succeeded"
        assert self.output(self.events(other["id"])) == b"1000\n"
        self.close_context(second["id"])
        self.close_context(context["id"])
        events = self.code_events(context["id"], accepted["events_after"])
        assert events[-1]["kind"] == "closed"
        self.no_context_processes(sandbox)
        self.stop_code_box(sandbox)

    @staticmethod
    def escaped_code(marker):
        child = f"import os,time;os.setsid();open('/workspace/{marker}','w').write(str(os.getpid()));time.sleep(90)"
        return f"import subprocess,sys,time\nsubprocess.Popen([sys.executable,'-c',{child!r}])\nprint('armed',flush=True)\ntime.sleep(90)"

    def code_cancel_and_timeout_collect_escaped_descendants(self):
        sandbox = self.code_box()
        context = self.new_code_context(sandbox)["id"]
        active = self.start_code(context, self.escaped_code("cancel-child"), timeout=90)
        self.wait_code_file(sandbox,"cancel-child")
        queued = self.start_code(context,"open('/workspace/must-not-run','w').write('bad')")
        self.request("POST",f"/v1/code-runs/{active['id']}/cancel")
        self.wait_context(context,"closed")
        for accepted in [active,queued]:
            assert self.wait_code(accepted)[0]["state"] == "cancelled"
        self.reject("GET",f"/v1/sandboxes/{sandbox}/files?path=must-not-run",404,"not_found")
        self.no_context_processes(sandbox)
        context=self.new_code_context(sandbox)["id"]
        result,_=self.code(context,self.escaped_code("timeout-child"),timeout=2)
        assert result["state"]=="timed_out" and result["kernel_status"] is None,result
        self.wait_context(context,"closed")
        self.no_context_processes(sandbox)
        self.stop_code_box(sandbox)

    def code_kernel_failure_limits_and_missing_dependencies(self):
        sandbox=self.code_box()
        context=self.new_code_context(sandbox)["id"]
        result,events=self.code(context,"raise ValueError('expected public exception')")
        assert result["state"]=="kernel_failed" and any(event["kind"]=="kernel_error" for event in events)
        result,events=self.code(context,"print('x'*10000)",output_limit=512)
        assert result["state"]=="kernel_succeeded" and result["output_truncated"],result
        self.close_context(context)
        for snippet in ["import os;os._exit(7)","get_ipython().kernel.session.session='changed-epoch'", "k=get_ipython().kernel\nk.session.send(k.iopub_socket,'display_data',content={'data':{'text/plain':'x'*(3*1024*1024)},'metadata':{}},parent=k.get_parent())"]:
            context=self.new_code_context(sandbox)["id"]
            accepted=self.start_code(context,snippet,key="failure-once")
            result,_=self.wait_code(accepted)
            assert result["state"]=="unknown" and result["kernel_status"] is None,result
            self.wait_context(context,"failed")
            assert self.start_code(context,snippet,key="failure-once")["finished_at"]==result["finished_at"]
            self.no_context_processes(sandbox)
        self.stop_code_box(sandbox)
        sandbox=self.code_box(image=self.args.image)
        context=self.new_code_context(sandbox,wait=False)["id"]
        failed=self.wait_context(context,"failed")
        assert failed["ready_at"] is None and "kernel startup failed" in failed["reason"],failed
        assert self.request("GET",f"/v1/sandboxes/{sandbox}")["state"]=="running"
        self.no_context_processes(sandbox)
        self.stop_code_box(sandbox)

    def code_runtime_loss_never_replays_queued_work(self):
        sandbox=self.code_box()
        context=self.new_code_context(sandbox)["id"]
        active=self.start_code(context,"import time\nopen('/workspace/started','w').write('x')\ntime.sleep(90)",timeout=90)
        self.wait_code_file(sandbox,"started")
        self.stop("worker")
        queued=self.start_code(context,"open('/workspace/never','w').write('bad')")
        container=self.container(sandbox)
        labels=json.loads(docker("inspect","--format","{{json .Config.Labels}}",container))
        assert labels["dev.goldenhoop.installation"]==self.installation and labels["dev.goldenhoop.sandbox"]==sandbox
        docker("rm","-f",container)
        self.launch("worker")
        failed=self.wait_context(context,"failed")
        assert failed["cleanup"]=="complete"
        assert self.wait_code(active)[0]["state"]=="unknown"
        assert self.wait_code(queued)[0]["state"]=="cancelled"
        assert not docker("ps","-a","--filter",f"label=dev.goldenhoop.sandbox={sandbox}","--format","{{.ID}}")

    def code_missing_dispatched_context_requires_whole_runtime_removal(self):
        sandbox=self.code_box()
        self.stop("worker")
        context=self.new_code_context(sandbox,wait=False)["id"]
        # Simulate a host crash immediately after its dispatch marker commits,
        # before any native create RPC. A restart must inspect, never resend.
        with closing(sqlite3.connect(self.database)) as connection:
            with connection:
                connection.execute("UPDATE code_contexts SET dispatched=1 WHERE id=?",(context,))
        self.launch("worker")
        value=self.wait_context(context,"failed")
        assert "refusing to recreate" in value["reason"],value
        assert self.request("GET",f"/v1/sandboxes/{sandbox}")["cleanup"]=="complete"
        assert not docker("ps","-a","--filter",f"label=dev.goldenhoop.sandbox={sandbox}","--format","{{.ID}}")

    def code_paused_expiry_is_collected_while_api_is_down(self):
        sandbox=self.code_box(ttl=15)
        context=self.new_code_context(sandbox)["id"]
        accepted=self.start_code(context,"import time\nopen('/workspace/paused','w').write('x')\ntime.sleep(90)",timeout=90)
        self.wait_code_file(sandbox,"paused")
        operation=self.request("POST",f"/v1/sandboxes/{sandbox}/pause",key=str(uuid.uuid4()))
        self.wait_operation(operation["id"])
        container=self.container(sandbox)
        self.stop("api")
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            if not docker("ps","-a","--filter",f"id={container}","--format","{{.ID}}"):break
            time.sleep(.2)
        else: raise AssertionError("paused code sandbox did not expire with API offline")
        self.launch("api")
        self.wait_context(context,"closed")
        result,_=self.wait_code(accepted)
        assert result["state"]=="timed_out" and result["kernel_status"] is None,result
