"""Actual child runtimes behind the public API; the outer harness owns cleanup."""
import base64
import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor


def limits(cpu=250, mib=256, pids=128):
    return {"cpu_millis": cpu, "memory_bytes": mib * 1024 * 1024, "pids": pids}


class IsolatedCases:
    isolated_cases = (
        "isolated_allocations_are_atomic_and_runtime_limits_are_not_double_counted",
        "isolated_feature_ceilings_and_failed_provision_release_only_collected_allocations",
        "isolated_deep_pause_restarts_retained_state_and_cascade_collection",
        "isolated_unexpected_parent_loss_closes_descendants_without_recreation",
        "isolated_paused_deadlines_collect_the_tree_while_api_is_down",
    )

    def is_wait(self, function, predicate, timeout=30):
        deadline = time.monotonic() + timeout
        value = None
        while time.monotonic() < deadline:
            value = function()
            if predicate(value):
                return value
            time.sleep(.1)
        raise AssertionError(f"isolated observation did not settle: {value}")

    def is_root(self, *, budget=None, ttl=300):
        profile = "local-gvisor" if self.args.runtime == "runsc" else "local-runc-dev"
        observed = next(p for p in self.request("GET", "/v1/profiles") if p["id"] == profile)
        assert "isolated_sessions" in observed["capabilities"], observed
        request = {"profile": profile, "image": self.args.kernel_image or self.args.image,
                   "resources": limits(1000), "ttl_seconds": ttl,
                   "child_budget": budget or limits(1000, 1024, 512)}
        value = self.request("POST", "/v1/sandboxes", request, str(uuid.uuid4()))
        self.wait_operation(value["operation"]["id"])
        return value["sandbox"]["id"]

    def is_child(self, parent, spec=None, *, key=None, wait=True):
        value = self.request("POST", f"/v1/sandboxes/{parent}/isolated-sessions",
                             spec or {"resources": limits()}, key or str(uuid.uuid4()))
        assert value["scope"]["sandbox_id"] == value["sandbox"]["id"]
        assert value["scope"]["parent_id"] == parent
        if wait:
            self.wait_operation(value["operation"]["id"])
        return value

    def is_scope(self, sid):
        return self.request("GET", f"/v1/sandboxes/{sid}/scope")

    def is_command(self, sid, code, *, key=None, timeout=10, wait=True):
        value = self.request("POST", f"/v1/sandboxes/{sid}/commands",
                             {"argv": ["python3", "-c", code], "timeout_seconds": timeout},
                             key or str(uuid.uuid4()))
        if wait:
            result = self.wait_execution(value["id"])
            assert result["state"] == "succeeded", (result, self.events(value["id"]))
        return value

    def is_file(self, sid, path, data=None):
        route = f"/v1/sandboxes/{sid}/files"
        if data is not None:
            return self.request("PUT", route, {"path": path, "data_base64": base64.b64encode(data).decode()})
        return base64.b64decode(self.request("GET", route + "?path=" + path)["data_base64"])

    def is_close(self, sid, descendants=()):
        from api_contract import docker
        value = self.request("DELETE", f"/v1/sandboxes/{sid}", key=str(uuid.uuid4()))
        self.wait_operation(value["id"])
        for identity in (sid, *descendants):
            record = self.request("GET", f"/v1/sandboxes/{identity}")
            assert record["cleanup"] == "complete", record
            assert not docker("ps", "-a", "--filter", f"label=dev.goldenhoop.installation={self.installation}",
                              "--filter", f"label=dev.goldenhoop.sandbox={identity}", "--format", "{{.ID}}")

    def isolated_allocations_are_atomic_and_runtime_limits_are_not_double_counted(self):
        from api_contract import docker
        parent = self.is_root()
        spec = {"resources": limits(500), "child_budget": limits(200), "ttl_seconds": 86400}
        keys = [str(uuid.uuid4()), str(uuid.uuid4())]
        def submit(key):
            try:
                return self.is_child(parent, spec, key=key, wait=False)
            except Exception as error:
                assert getattr(error, "status", None) == 429 and error.error["code"] == "quota_exceeded", str(error)
                return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            values = list(pool.map(submit, keys))
        assert sum(value is not None for value in values) == 1, values
        accepted = next(index for index, value in enumerate(values) if value is not None)
        value = values[accepted]
        child = value["sandbox"]["id"]
        self.wait_operation(value["operation"]["id"])
        replay = self.is_child(parent, spec, key=keys[accepted])
        assert replay["sandbox"]["id"] == child and replay["operation"]["id"] == value["operation"]["id"]
        changed = dict(spec, resources=limits(499))
        self.reject("POST", f"/v1/sandboxes/{parent}/isolated-sessions", 409, "conflict", body=changed, key=keys[accepted])
        grand = self.is_child(child, {"resources": limits(200)})["sandbox"]["id"]
        assert self.is_scope(parent)["allocated_to_children"] == limits(700, 512, 256)
        assert self.is_scope(child)["allocated_to_children"] == limits(200)
        deadline = self.request("GET", f"/v1/sandboxes/{parent}")["expires_at"]
        assert self.request("GET", f"/v1/sandboxes/{child}")["expires_at"] == deadline
        self.is_file(parent, "private", b"parent")
        self.reject("GET", f"/v1/sandboxes/{child}/files?path=private", 404, "not_found")
        self.is_file(child, "private", b"child")
        self.is_file(grand, "private", b"grand")
        for sid, expected, allocation in [(parent, b"parent", limits(1000)), (child, b"child", limits(500)), (grand, b"grand", limits(200))]:
            assert self.is_file(sid, "private") == expected
            self.is_command(sid, "import os;assert os.getuid()==1000;assert not any(k.startswith('GOLDENHOOP_') for k in os.environ)")
            host = json.loads(docker("inspect", "--format", "{{json .HostConfig}}", self.container(sid)))
            assert host["NanoCpus"] == allocation["cpu_millis"] * 1000000 and host["Memory"] == allocation["memory_bytes"] and host["PidsLimit"] == allocation["pids"], host
            assert host["NetworkMode"] == "none" and host["IpcMode"] == "private"
        page = self.request("GET", f"/v1/sandboxes/{parent}/isolated-sessions?limit=1")
        assert [item["id"] for item in page["items"]] == [child]
        self.is_close(child, [grand])
        assert self.is_scope(parent)["allocated_to_children"] == limits(0, 0, 0)
        retry = self.is_child(parent, spec, key=keys[1-accepted])["sandbox"]["id"]
        assert retry != child
        self.is_command(parent, "assert open('/workspace/private','rb').read()==b'parent'")
        self.is_close(parent, [retry])

    def isolated_feature_ceilings_and_failed_provision_release_only_collected_allocations(self):
        parent = self.is_root()
        child = self.is_child(parent, {"resources": limits(), "feature_limit": ["commands"]})["sandbox"]["id"]
        self.is_command(child, "print('allowed')")
        for method, suffix, body in [("GET", "files?path=file", None), ("PUT", "files", {"path": "file", "data_base64": ""}),
                                     ("GET", "directories?path=.", None), ("DELETE", "files?path=file", None), ("GET", "diagnostics", None),
                                     ("POST", "pause", None), ("POST", "sessions", {"command": {"argv": ["/bin/sh"]}}),
                                     ("POST", "artifacts", {"path": "file", "name": "file"}), ("POST", "isolated-sessions", {"resources": limits()})]:
            self.reject(method, f"/v1/sandboxes/{child}/{suffix}", 403, "forbidden", body=body, key=str(uuid.uuid4()))
        self.reject("POST", f"/v1/sandboxes/{child}/code-contexts", 403 if self.args.kernel_image else 422,
                    "forbidden" if self.args.kernel_image else "unsupported_capability", body={}, key=str(uuid.uuid4()))
        self.reject("POST", f"/v1/sandboxes/{parent}/isolated-sessions", 403, "forbidden",
                    body={"resources": limits(), "network": {"default_action": "allow", "rules": []}}, key=str(uuid.uuid4()))
        self.reject("POST", f"/v1/sandboxes/{parent}/isolated-sessions", 400, "invalid_request",
                    body={"resources": limits(), "profile": "other"}, key=str(uuid.uuid4()))
        before = self.is_scope(parent)["allocated_to_children"]
        failed = self.is_child(parent, {"resources": limits(), "image": f"goldenhoop-absent-{uuid.uuid4().hex}:test"}, wait=False)
        self.wait_operation(failed["operation"]["id"], expected="failed")
        observed = self.request("GET", f"/v1/sandboxes/{failed['sandbox']['id']}")
        assert observed["state"] == "failed" and observed["cleanup"] == "complete", observed
        assert self.is_scope(parent)["allocated_to_children"] == before
        self.is_close(child)
        self.is_close(parent)

    def isolated_deep_pause_restarts_retained_state_and_cascade_collection(self):
        from api_contract import docker
        parent = self.is_root(ttl=300)
        ids, keys, specs = [parent], [], []
        for depth in range(1, 5):
            spec = {"resources": limits(), "ttl_seconds": 86400}
            if depth < 4:
                spec["child_budget"] = limits((4-depth)*250, (4-depth)*256, (4-depth)*128)
            key = str(uuid.uuid4())
            value = self.is_child(ids[-1], spec, key=key)
            ids.append(value["sandbox"]["id"]); keys.append(key); specs.append(spec)
            assert value["scope"]["root_id"] == parent and value["scope"]["depth"] == depth
        leaf = ids[-1]
        self.reject("POST", f"/v1/sandboxes/{leaf}/isolated-sessions", 429, "quota_exceeded", body={"resources": limits()}, key=str(uuid.uuid4()))
        containers = [self.container(sid) for sid in ids]
        run = self.is_command(leaf, "import time;open('/workspace/once','a').write('1');print('armed',flush=True);time.sleep(3);print('done')", timeout=120, wait=False)
        self.events(run["id"], first_output=True)
        paused = self.request("POST", f"/v1/sandboxes/{parent}/pause", key=str(uuid.uuid4()))
        self.wait_operation(paused["id"])
        for sid, container in zip(ids, containers):
            assert json.loads(docker("inspect", "--format", "{{json .State.Paused}}", container)) is True
            self.reject("POST", f"/v1/sandboxes/{sid}/commands", 409, "invalid_state", body={"argv": ["true"]}, key=str(uuid.uuid4()))
            self.reject("GET", f"/v1/sandboxes/{sid}/files?path=once", 409, "invalid_state")
        self.stop("worker"); self.launch("worker")
        self.stop("api"); self.launch("api")
        assert [self.container(sid) for sid in ids] == containers
        assert self.is_child(parent, specs[0], key=keys[0])["sandbox"]["id"] == ids[1]
        # A child's own pause survives ancestor resume.
        own = self.request("POST", f"/v1/sandboxes/{leaf}/pause", key=str(uuid.uuid4()))
        self.wait_operation(own["id"])
        resumed = self.request("POST", f"/v1/sandboxes/{parent}/resume", key=str(uuid.uuid4()))
        self.wait_operation(resumed["id"])
        assert self.request("GET", f"/v1/sandboxes/{leaf}")["state"] == "paused"
        resumed = self.request("POST", f"/v1/sandboxes/{leaf}/resume", key=str(uuid.uuid4()))
        self.wait_operation(resumed["id"])
        assert self.wait_execution(run["id"])["state"] == "succeeded"
        assert self.is_file(leaf, "once") == b"1"
        self.is_close(parent, ids[1:])

    def isolated_unexpected_parent_loss_closes_descendants_without_recreation(self):
        from api_contract import docker
        parent = self.is_root()
        child = self.is_child(parent)["sandbox"]["id"]
        run = self.is_command(child, "import time;print('armed',flush=True);time.sleep(60)", timeout=120, wait=False)
        self.events(run["id"], first_output=True)
        container = self.container(parent)
        docker("rm", "-f", container)
        observed = self.is_wait(lambda:self.request("GET", f"/v1/sandboxes/{parent}"), lambda v:v["cleanup"] == "complete")
        assert observed["state"] == "failed", observed
        descendant = self.request("GET", f"/v1/sandboxes/{child}")
        assert descendant["cleanup"] == "complete" and descendant["desired_state"] == "terminated", descendant
        assert self.wait_execution(run["id"])["state"] == "cancelled"
        self.stop("worker"); self.launch("worker")
        for sid in (parent, child):
            assert self.request("GET", f"/v1/sandboxes/{sid}")["cleanup"] == "complete"
            assert not docker("ps", "-a", "--filter", f"label=dev.goldenhoop.installation={self.installation}", "--filter", f"label=dev.goldenhoop.sandbox={sid}", "--format", "{{.ID}}")
        self.is_close(parent, [child])

    def isolated_paused_deadlines_collect_the_tree_while_api_is_down(self):
        from api_contract import docker
        parent = self.is_root(ttl=15)
        child = self.is_child(parent, {"resources": limits(), "ttl_seconds": 86400})["sandbox"]["id"]
        root = self.request("GET", f"/v1/sandboxes/{parent}")
        assert self.request("GET", f"/v1/sandboxes/{child}")["expires_at"] == root["expires_at"]
        paused = self.request("POST", f"/v1/sandboxes/{parent}/pause", key=str(uuid.uuid4()))
        self.wait_operation(paused["id"])
        self.stop("api")
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            alive = [docker("ps", "-a", "--filter", f"label=dev.goldenhoop.installation={self.installation}", "--filter", f"label=dev.goldenhoop.sandbox={sid}", "--format", "{{.ID}}") for sid in (parent,child)]
            if not any(alive):break
            time.sleep(.2)
        assert not any(alive), alive
        self.launch("api")
        for sid in (parent,child):
            record = self.is_wait(lambda:self.request("GET", f"/v1/sandboxes/{sid}"), lambda v:v["cleanup"] == "complete")
            assert record["desired_state"] == "terminated", record
        self.is_close(parent, [child])
