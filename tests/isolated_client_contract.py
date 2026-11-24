"""Real child loops for both Python transports and the CLI."""
import asyncio
import json
import os
import subprocess
import tempfile
from pathlib import Path
from uuid import uuid4
from goldenhoop import AsyncClient, Client, Command, CreateSandbox, CreateIsolatedSession, ApiError

ENDPOINT = os.environ["GOLDENHOOP_ENDPOINT"]
TOKEN = os.environ["GOLDENHOOP_API_TOKEN"]
PROFILE = os.environ["GOLDENHOOP_TEST_PROFILE"]
IMAGE = os.environ["GOLDENHOOP_TEST_IMAGE"]
BUDGET = {"cpu_millis": 2000, "memory_bytes": 2147483648, "pids": 512}
ZERO = dict.fromkeys(BUDGET, 0)
CODE = "open('/workspace/once','a').write('1');print('child')"


def request():
    return CreateSandbox(PROFILE, IMAGE, ttl_seconds=300, child_budget=BUDGET, required_capabilities=["isolated_sessions"])


def sync_isolated_contract():
    with Client(ENDPOINT, TOKEN) as client:
        with client.lease(request()) as parent:
            key, spec = str(uuid4()), CreateIsolatedSession()
            created = client.create_isolated_session(parent.id, spec, key)
            child = created["sandbox"]["id"]
            client.wait_operation(created["operation"]["id"])
            assert client.create_isolated_session(parent.id, spec, key)["sandbox"]["id"] == child
            scope = client.sandbox_scope(child)
            assert (scope["parent_id"], scope["root_id"], scope["depth"]) == (parent.id, parent.id, 1)
            assert client.isolated_sessions(parent.id, limit=1)["items"][0]["id"] == child
            client.write_file(parent.id, "private", b"parent")
            try: client.read_file(child, "private")
            except ApiError as error: assert error.code == "not_found"
            else: raise AssertionError("child read its parent's workspace")
            client.write_file(child, "private", b"child")
            key = str(uuid4())
            first = client.run(child, Command(["python3", "-c", CODE]), key)
            replay = client.run(child, Command(["python3", "-c", CODE]), key)
            assert replay.execution["id"] == first.execution["id"] and replay.stdout == b"child\n"
            assert client.read_file(child, "once") == b"1" and client.read_file(parent.id, "private") == b"parent"
            with client.isolated_lease(parent.id, CreateIsolatedSession(feature_limit=["commands", "files"])) as extra:
                assert client.run(extra.id, Command(["true"])).execution["state"] == "succeeded"
            assert client.sandbox(extra.id)["cleanup"] == "complete"
            client.wait_operation(client.terminate(child, str(uuid4()))["id"])
            assert client.sandbox_scope(parent.id)["allocated_to_children"] == ZERO
            assert client.sandbox(parent.id)["state"] == "running"
    return {"result": "passed", "cleanup": "complete", "cases": ["create_replay", "scope_pages", "workspace_isolation", "command_replay_once", "narrowed_child_lease", "confirmed_tree_cleanup"]}


async def async_isolated_contract():
    async with AsyncClient(ENDPOINT, TOKEN) as client:
        async with client.lease(request()) as parent:
            key, spec = str(uuid4()), CreateIsolatedSession()
            created = await client.create_isolated_session(parent.id, spec, key)
            child = created["sandbox"]["id"]
            await client.wait_operation(created["operation"]["id"])
            assert (await client.create_isolated_session(parent.id, spec, key))["sandbox"]["id"] == child
            assert (await client.sandbox_scope(child))["parent_id"] == parent.id
            assert (await client.isolated_sessions(parent.id, limit=1))["items"][0]["id"] == child
            await client.write_file(parent.id, "private", b"parent")
            await client.write_file(child, "private", b"child")
            key = str(uuid4())
            first = await client.run(child, Command(["python3", "-c", CODE]), key)
            replay = await client.run(child, Command(["python3", "-c", CODE]), key)
            assert replay.execution["id"] == first.execution["id"] and replay.stdout == b"child\n"
            assert await client.read_file(child, "once") == b"1" and await client.read_file(parent.id, "private") == b"parent"
            async with client.isolated_lease(parent.id, CreateIsolatedSession(feature_limit=["commands", "files"])) as extra:
                accepted = await client.start(extra.id, Command(["python3", "-c", "import time;open('/workspace/observer','a').write('1');time.sleep(1)"]), str(uuid4()))
                observer = asyncio.create_task(client.wait_execution(accepted["id"]))
                await asyncio.sleep(.05)
                observer.cancel()
                try: await observer
                except asyncio.CancelledError: pass
                assert (await client.wait_execution(accepted["id"]))["state"] == "succeeded"
                assert await client.read_file(extra.id, "observer") == b"1"
            assert (await client.sandbox(extra.id))["cleanup"] == "complete"
            await client.wait_operation((await client.terminate(child, str(uuid4())))["id"])
            assert (await client.sandbox_scope(parent.id))["allocated_to_children"] == ZERO
            assert (await client.sandbox(parent.id))["state"] == "running"
    return {"result": "passed", "cleanup": "complete", "cases": ["create_replay", "scope_pages", "workspace_isolation", "command_replay_once", "narrowed_child_lease", "observer_cancel_keeps_child_execution", "confirmed_tree_cleanup"]}


def cli_isolated_contract(cli):
    def invoke(*args):
        result = subprocess.run([str(cli), "--endpoint", ENDPOINT, *args], capture_output=True, text=True, encoding="utf-8", timeout=70)
        assert result.returncode == 0, (args, result.stdout, result.stderr)
        return result.stdout
    parent = json.loads(invoke("create", "--profile", PROFILE, "--image", IMAGE, "--ttl", "300",
                               "--child-cpu-millis", "2000", "--child-memory-bytes", "2147483648", "--child-pids", "512"))["sandbox"]["id"]
    child = None
    try:
        key = str(uuid4())
        args = ("isolated-create", parent, "--feature-limit", "commands,files", "--idempotency-key", key)
        created = json.loads(invoke(*args))
        child = created["sandbox"]["id"]
        assert json.loads(invoke(*args))["sandbox"]["id"] == child
        assert json.loads(invoke("scope", child))["parent_id"] == parent
        assert json.loads(invoke("isolated-list", parent))["items"][0]["id"] == child
        assert invoke("exec", child, "--", "python3", "-c", CODE) == "child\n"
        with tempfile.TemporaryDirectory(prefix="goldenhoop-isolated-cli-", dir=os.environ["GOLDENHOOP_TEST_DIRECTORY"]) as directory:
            root = Path(directory)
            source, destination = root / "source.bin", root / "child.bin"
            source.write_bytes(b"child-bytes")
            invoke("file-put", child, str(source), "private")
            invoke("file-get", child, "private", str(destination))
            assert destination.read_bytes() == b"child-bytes"
        assert not root.exists()
    finally:
        invoke("delete", parent)
    assert json.loads(invoke("get", parent))["cleanup"] == "complete"
    assert child is not None and json.loads(invoke("get", child))["cleanup"] == "complete"
    return {"result": "passed", "cleanup": "complete", "cases": ["root_reservation_flags", "create_replay", "scope_pages", "feature_ceiling_flags", "commands_files", "parent_cascade", "temporary_files_removed"]}
