"""Actual Python SDK / Rust CLI loop against the outer harness's installation."""
import argparse
import asyncio
import base64
import json
import os
import subprocess
import tempfile
from contextlib import aclosing, closing
from pathlib import Path, PurePosixPath
from uuid import uuid4

import httpx
from goldenhoop import ApiError, AsyncClient, Client, Command, CreateSandbox, CreateArtifact, WaitTimeout, SessionSpec, SessionControl

ENDPOINT = os.environ["GOLDENHOOP_ENDPOINT"]
TOKEN = os.environ["GOLDENHOOP_API_TOKEN"]
REQUEST = CreateSandbox(os.environ["GOLDENHOOP_TEST_PROFILE"], os.environ["GOLDENHOOP_TEST_IMAGE"], ttl_seconds=120)
BINARY = b"\x00\xff\x80hello\n"


PTY_CODE = (
    "import os,sys,tty,termios; assert all(os.isatty(fd) for fd in (0,1,2)); "
    "tty.setraw(0); print('READY',flush=True); data=sys.stdin.buffer.read(3); "
    "assert data==b'\\x00\\xff\\n'; assert termios.tcgetwinsize(0)==(40,100); print('BIN:'+data.hex(),flush=True)"
)


def sync_sessions(client, sid):
    shell = client.create_session(sid, SessionSpec(), str(uuid4()))
    eid = shell["execution"]["id"]
    first = SessionControl.write(1, b"v=sync; printf 'READY\\n'\n")
    client.session_control(eid, first)
    assert client.wait_session_control(eid, 1)["state"] == "applied"
    with closing(client.events(eid)) as stream:
        cursor = next(event["sequence"] for event in stream if event["kind"] == "stdout")
    second = SessionControl.write(2, b"printf '%s' \"$v\" >> /workspace/sync-session\n")
    client.session_control(eid, second)
    assert client.wait_session_control(eid, 2)["state"] == "applied"
    assert client.session_control(eid, second)["state"] == "applied"
    client.session_control(eid, SessionControl.close_input(3))
    assert client.wait_execution(eid)["state"] == "succeeded"
    assert client.read_file(sid, "sync-session") == b"sync"
    with closing(client.events(eid, cursor)) as stream:
        events = list(stream)
    assert events[0]["sequence"] == cursor + 1 and events[-1]["kind"] == "completed"
    spec = SessionSpec(Command(["python3", "-c", PTY_CODE]), {"rows": 24, "columns": 80})
    eid = client.create_session(sid, spec, str(uuid4()))["execution"]["id"]
    with closing(client.events(eid)) as stream:
        next(event for event in stream if event["kind"] == "stdout")
    client.session_control(eid, SessionControl.resize(1, 40, 100))
    assert client.wait_session_control(eid, 1)["state"] == "applied"
    client.session_control(eid, SessionControl.write(2, b"\x00\xff\n"))
    assert client.wait_execution(eid)["state"] == "succeeded"
    with closing(client.events(eid)) as stream:
        events = list(stream)
    assert b"BIN:00ff0a\n" in b"".join(base64.b64decode(event["data"]["data"]) for event in events if event["kind"] == "stdout")
    assert client.session(eid)["execution"]["state"] == "succeeded"
    assert any(item["execution"]["id"] == eid for item in client.list_sessions(sid)["items"])


async def async_sessions(client, sid):
    eid = (await client.create_session(sid, SessionSpec(), str(uuid4())))["execution"]["id"]
    await client.session_control(eid, SessionControl.write(1, b"v=async; printf 'READY\\n'\n"))
    assert (await client.wait_session_control(eid, 1))["state"] == "applied"
    async with aclosing(client.events(eid)) as stream:
        async for event in stream:
            if event["kind"] == "stdout":
                cursor = event["sequence"]
                break
    second = SessionControl.write(2, b"printf '%s' \"$v\" >> /workspace/async-session\n")
    await client.session_control(eid, second)
    assert (await client.wait_session_control(eid, 2))["state"] == "applied"
    assert (await client.session_control(eid, second))["state"] == "applied"
    await client.session_control(eid, SessionControl.close_input(3))
    assert (await client.wait_execution(eid))["state"] == "succeeded"
    assert await client.read_file(sid, "async-session") == b"async"
    async with aclosing(client.events(eid, cursor)) as stream:
        events = [event async for event in stream]
    assert events[0]["sequence"] == cursor + 1 and events[-1]["kind"] == "completed"
    spec = SessionSpec(Command(["python3", "-c", PTY_CODE]), {"rows": 24, "columns": 80})
    eid = (await client.create_session(sid, spec, str(uuid4())))["execution"]["id"]
    async with aclosing(client.events(eid)) as stream:
        async for event in stream:
            if event["kind"] == "stdout":
                break
    await client.session_control(eid, SessionControl.resize(1, 40, 100))
    assert (await client.wait_session_control(eid, 1))["state"] == "applied"
    await client.session_control(eid, SessionControl.write(2, b"\x00\xff\n"))
    assert (await client.wait_execution(eid))["state"] == "succeeded"
    async with aclosing(client.events(eid)) as stream:
        events = [event async for event in stream]
    assert b"BIN:00ff0a\n" in b"".join(base64.b64decode(event["data"]["data"]) for event in events if event["kind"] == "stdout")
    assert (await client.session(eid))["execution"]["state"] == "succeeded"
    assert any(item["execution"]["id"] == eid for item in (await client.list_sessions(sid))["items"])


def sync_contract():
    with Client(ENDPOINT, TOKEN) as client:
        assert any(p["id"] == REQUEST.profile and p["availability"] == "available" for p in client.profiles())
        with client.lease(REQUEST) as sandbox:
            sid = sandbox.id
            assert client.diagnostics(sid)["runtime"]["usage"]["memory_bytes"] > 0
            assert any(v["id"] == sid for v in client.list()["items"])
            client.write_file(sid, "python.bin", BINARY)
            assert client.read_file(sid, "python.bin") == BINARY
            assert any(PurePosixPath(v["path"]).name == "python.bin" for v in client.list_files(sid))
            try:
                client.read_file(sid, "../etc/passwd")
            except ApiError as error:
                assert error.code == "forbidden"
            else:
                raise AssertionError("file traversal succeeded")
            result = client.run(sid, Command(["printf", "%s", "$HOME; echo literal"]))
            assert result.stdout == b"$HOME; echo literal" and result.execution["state"] == "succeeded"
            result = client.run(sid, Command(["python3", "-c", "import os;os.write(1,b'\\x00\\xff');os.write(2,b'err');raise SystemExit(23)"]))
            assert result.stdout == b"\x00\xff" and result.stderr == b"err" and result.execution["exit_code"] == 23
            command = Command(["python3", "-c", "with open('once','ab') as f:f.write(b'1')\nprint('once')"])
            key = str(uuid4())
            assert client.run(sid, command, key).execution["id"] == client.run(sid, command, key).execution["id"]
            assert client.read_file(sid, "once") == b"1"
            assert client.run(sid, Command(["sleep", "30"], timeout_seconds=1)).execution["state"] == "timed_out"
            execution = client.start(sid, Command(["sleep", "30"]), str(uuid4()))
            try:
                client.wait_execution(execution["id"], timeout=0.01)
            except WaitTimeout:
                pass
            else:
                raise AssertionError("wait timeout was not enforced")
            assert client.execution(execution["id"])["state"] not in ("cancelled", "timed_out", "failed")
            client.cancel(execution["id"])
            assert client.wait_execution(execution["id"])["state"] == "cancelled"
            execution = client.start(sid, Command(["python3", "-c", "import time;print('a',flush=True);time.sleep(0.5);print('b',flush=True)"]), str(uuid4()))
            with closing(client.events(execution["id"])) as stream:
                cursor = next(event["sequence"] for event in stream if event["kind"] == "stdout")
            with closing(client.events(execution["id"], cursor)) as stream:
                events = list(stream)
            assert events and events[0]["sequence"] == cursor + 1 and events[-1]["kind"] == "completed"
            for action in (client.pause, client.resume):
                client.wait_operation(action(sid, str(uuid4()))["id"])
            sync_sessions(client, sid)
            artifact = client.capture_artifact(sid, CreateArtifact("python.bin", "python-sdk.bin"))
            assert any(item["id"] == artifact["id"] for item in client.list_artifacts(sid)["items"])
            client.remove_file(sid, "python.bin")
        assert client.sandbox(sid)["cleanup"] == "complete"
        assert client.diagnostics(sid)["runtime"] is None
        try:
            assert client.artifact_bytes(artifact["id"]) == BINARY
        finally:
            client.wait_operation(client.delete_artifact(artifact["id"], str(uuid4()))["id"])
        assert client.artifact(artifact["id"])["cleanup"] == "complete"
        # Exceptions in caller code must also receive confirmed context cleanup.
        failed_id = None
        try:
            with client.lease(REQUEST) as sandbox:
                failed_id = sandbox.id
                raise ValueError("intentional caller failure")
        except ValueError:
            pass
        assert failed_id and client.sandbox(failed_id)["cleanup"] == "complete"
    return {"client": "python-sync", "result": "passed", "cleanup": "complete"}


async def async_contract():
    async with AsyncClient(ENDPOINT, TOKEN) as client:
        async with client.lease(REQUEST) as sandbox:
            sid = sandbox.id
            assert (await client.diagnostics(sid))["runtime"]["usage"]["memory_bytes"] > 0
            await client.write_file(sid, "async.bin", BINARY)
            assert await client.read_file(sid, "async.bin") == BINARY
            result = await client.run(sid, Command(["printf", "%s", "async literal"]))
            assert result.stdout == b"async literal" and result.execution["state"] == "succeeded"
            execution = await client.start(sid, Command(["python3", "-c", "import time;print('a',flush=True);time.sleep(0.5);print('b',flush=True)"]), str(uuid4()))
            async with aclosing(client.events(execution["id"])) as stream:
                async for event in stream:
                    if event["kind"] == "stdout":
                        cursor = event["sequence"]
                        break
            async with aclosing(client.events(execution["id"], cursor)) as stream:
                events = [event async for event in stream]
            assert events[0]["sequence"] == cursor + 1 and events[-1]["kind"] == "completed"
            execution = await client.start(sid, Command(["sleep", "30"]), str(uuid4()))
            await client.cancel(execution["id"])
            assert (await client.wait_execution(execution["id"]))["state"] == "cancelled"
            await async_sessions(client, sid)
            artifact = await client.capture_artifact(sid, CreateArtifact("async.bin", "async-sdk.bin"))
            assert any(item["id"] == artifact["id"] for item in (await client.list_artifacts(sid))["items"])
        assert (await client.sandbox(sid))["cleanup"] == "complete"
        assert (await client.diagnostics(sid))["runtime"] is None
        try:
            assert await client.artifact_bytes(artifact["id"]) == BINARY
        finally:
            await client.wait_operation((await client.delete_artifact(artifact["id"], str(uuid4())))["id"])
        assert (await client.artifact(artifact["id"]))["cleanup"] == "complete"
        # Cancellation of the lease's owner still runs explicit cleanup.
        created = asyncio.Event()
        cancellation_id = None
        async def owner():
            nonlocal cancellation_id
            async with client.lease(REQUEST) as sandbox:
                cancellation_id = sandbox.id
                created.set()
                await asyncio.sleep(60)
        task = asyncio.create_task(owner())
        await asyncio.wait_for(created.wait(), 20)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        assert cancellation_id and (await client.sandbox(cancellation_id))["cleanup"] == "complete"
    return {"client": "python-async", "result": "passed", "cleanup": "complete"}


def cli_contract(binary):
    def invoke(*args, expected=0):
        result = subprocess.run([str(Path(binary).resolve()), *args], capture_output=True, timeout=80,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        assert result.returncode == expected, (args, result.returncode, result.stderr.decode("utf-8", errors="replace"))
        return result.stdout
    assert any(v["id"] == REQUEST.profile for v in json.loads(invoke("profiles")))
    created = json.loads(invoke("create", "--profile", REQUEST.profile, "--image", REQUEST.image, "--ttl", "120"))
    sid = created["sandbox"]["id"]
    try:
        assert json.loads(invoke("get", sid))["state"] == "running"
        assert json.loads(invoke("diagnostics", sid))["runtime"]["usage"]["memory_bytes"] > 0
        assert invoke("exec", sid, "--", "printf", "%s", "$HOME; echo literal") == b"$HOME; echo literal"
        result = json.loads(invoke("exec", sid, "--json", "--", "python3", "-c", "import os;os.write(1,b'\\x00\\xff');raise SystemExit(23)", expected=23))
        assert base64.b64decode(result["stdout_base64"]) == b"\x00\xff"
        invoke("exec", sid, "--timeout", "1", "--", "sleep", "30", expected=124)
        work = Path(os.environ["GOLDENHOOP_TEST_DIRECTORY"]).resolve()
        with tempfile.TemporaryDirectory(prefix="goldenhoop-cli-", dir=work) as directory:
            directory = Path(directory).resolve()
            assert directory.is_relative_to(work)
            source, destination = directory / "source.bin", directory / "download.bin"
            source.write_bytes(BINARY)
            invoke("file-put", sid, str(source), "cli.bin")
            invoke("file-get", sid, "cli.bin", str(destination))
            assert destination.read_bytes() == BINARY
            shell = json.loads(invoke("session-create", sid))
            shell_id = shell["execution"]["id"]
            session_input = directory / "session-input.bin"
            session_input.write_bytes(b"v=cli; printf 'READY\\n'\n")
            assert json.loads(invoke("session-write", shell_id, "1", str(session_input)))["state"] == "applied"
            session_input.write_bytes(b"printf '%s' \"$v\" >> /workspace/cli-session\n")
            invoke("session-write", shell_id, "2", str(session_input))
            invoke("session-write", shell_id, "2", str(session_input))
            rejected = json.loads(invoke("session-resize", shell_id, "3", "40", "100", expected=125))
            assert rejected["state"] == "rejected" and rejected["error"]["code"] == "unsupported_capability"
            invoke("session-close-input", shell_id, "4")
            events = [json.loads(line) for line in invoke("session-events", shell_id).splitlines()]
            assert events[-1]["kind"] == "completed" and events[-1]["data"]["cleanup"] == "complete"
            assert json.loads(invoke("session-get", shell_id))["execution"]["state"] == "succeeded"
            assert json.loads(invoke("session-receipt", shell_id, "3"))["state"] == "rejected"
            assert any(item["execution"]["id"] == shell_id for item in json.loads(invoke("session-list", "--sandbox", sid))["items"])
            retained = directory / "retained-shell.bin"
            invoke("file-get", sid, "cli-session", str(retained))
            assert retained.read_bytes() == b"cli"
            terminal = json.loads(invoke("session-create", sid, "--pty", "--timeout", "30", "--", "python3", "-c", PTY_CODE))
            terminal_id = terminal["execution"]["id"]
            # Observe readiness before sending bytes: tty.setraw flushes earlier input.
            with Client(ENDPOINT, TOKEN) as observer:
                with closing(observer.events(terminal_id)) as stream:
                    next(event for event in stream if event["kind"] == "stdout")
            invoke("session-resize", terminal_id, "1", "40", "100")
            rejected = json.loads(invoke("session-close-input", terminal_id, "2", expected=125))
            assert rejected["state"] == "rejected"
            session_input.write_bytes(b"\x00\xff\n")
            invoke("session-write", terminal_id, "3", str(session_input))
            events = [json.loads(line) for line in invoke("session-events", terminal_id).splitlines()]
            assert events[-1]["kind"] == "completed" and events[-1]["data"]["state"] == "succeeded"
            assert b"BIN:00ff0a\n" in b"".join(base64.b64decode(event["data"]["data"]) for event in events if event["kind"] == "stdout")
            invoke("file-get", sid, "cli.bin", str(destination), expected=125)
            assert destination.read_bytes() == BINARY
            artifact = json.loads(invoke("artifact-capture", sid, "cli.bin", "--name", "cli-artifact.bin"))
            artifact_path = directory / "artifact.bin"
            try:
                invoke("artifact-download", artifact["id"], str(artifact_path))
                assert artifact_path.read_bytes() == BINARY
                assert json.loads(invoke("artifact-get", artifact["id"]))["state"] == "available"
                assert any(item["id"] == artifact["id"] for item in json.loads(invoke("artifact-list", "--sandbox", sid))["items"])
            finally:
                deleted = json.loads(invoke("artifact-delete", artifact["id"]))
                assert deleted["state"] == "deleted" and deleted["cleanup"] == "complete"
            invoke("file-remove", sid, "cli.bin")
        assert not directory.exists()
        invoke("pause", sid)
        invoke("resume", sid)
    finally:
        invoke("delete", sid)
    assert json.loads(invoke("get", sid))["cleanup"] == "complete"
    return {"client": "rust-cli", "result": "passed", "cleanup": "complete"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli", required=True)
    args = parser.parse_args()
    results = [sync_contract(), asyncio.run(async_contract()), cli_contract(args.cli)]
    if os.environ.get("GOLDENHOOP_TEST_KERNEL_IMAGE"):
        from code_client_contract import sync_code_contract, async_code_contract, cli_code_contract
        for result,code in zip(results,[sync_code_contract(),asyncio.run(async_code_contract()),cli_code_contract(args.cli)],strict=True):
            result["code_contexts"]=code
    print(json.dumps({"clients": results, "httpx": httpx.__version__, "result": "passed"}))
