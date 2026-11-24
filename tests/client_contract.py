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
from goldenhoop import ApiError, AsyncClient, Client, Command, CreateSandbox, WaitTimeout

ENDPOINT = os.environ["GOLDENHOOP_ENDPOINT"]
TOKEN = os.environ["GOLDENHOOP_API_TOKEN"]
REQUEST = CreateSandbox(os.environ["GOLDENHOOP_TEST_PROFILE"], os.environ["GOLDENHOOP_TEST_IMAGE"], ttl_seconds=120)
BINARY = b"\x00\xff\x80hello\n"


def sync_contract():
    with Client(ENDPOINT, TOKEN) as client:
        assert any(p["id"] == REQUEST.profile and p["availability"] == "available" for p in client.profiles())
        with client.lease(REQUEST) as sandbox:
            sid = sandbox.id
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
            client.remove_file(sid, "python.bin")
        assert client.sandbox(sid)["cleanup"] == "complete"
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
        assert (await client.sandbox(sid))["cleanup"] == "complete"
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
            invoke("file-get", sid, "cli.bin", str(destination), expected=125)
            assert destination.read_bytes() == BINARY
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
    print(json.dumps({"clients": results, "httpx": httpx.__version__, "result": "passed"}))
