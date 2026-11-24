"""Actual SDK/CLI context loops; the outer API harness owns the installation."""
import asyncio
import json
import os
import subprocess
from contextlib import aclosing, closing
from pathlib import Path
from uuid import uuid4
from goldenhoop import AsyncClient, Client, CreateSandbox, CodeContextSpec, CodeRunSpec, CodeObservationError

ENDPOINT=os.environ["GOLDENHOOP_ENDPOINT"]
TOKEN=os.environ["GOLDENHOOP_API_TOKEN"]


def request():
    return CreateSandbox(os.environ["GOLDENHOOP_TEST_PROFILE"],os.environ["GOLDENHOOP_TEST_KERNEL_IMAGE"],ttl_seconds=180,required_capabilities=["code_contexts","artifacts"])


def sync_code_contract():
    with Client(ENDPOINT,TOKEN) as client:
        with client.lease(request()) as lease:
            sid=lease.id
            key=str(uuid4())
            cid=client.create_code_context(sid,CodeContextSpec(),key)["id"]
            assert client.create_code_context(sid,CodeContextSpec(),key)["id"]==cid
            client.wait_code_context_ready(cid)
            assert client.run_code(cid,CodeRunSpec("value=40")).run["state"]=="kernel_succeeded"
            spec=CodeRunSpec("value+=1\nopen('/workspace/sync-code-once','a').write('1')\nprint(value)\nvalue")
            key=str(uuid4())
            first=client.run_code(cid,spec,key)
            replay=client.run_code(cid,spec,key)
            assert replay.run["id"]==first.run["id"] and replay.run["events_after"]==first.run["events_after"]
            assert replay.stdout=="41\n" and client.read_file(sid,"sync-code-once")==b"1"
            result=client.run_code(cid,CodeRunSpec("print(value+1)\nvalue+1"))
            assert result.stdout=="42\n" and any(item["data"]["text/plain"]=="42" for item in result.results)
            failed=client.run_code(cid,CodeRunSpec("raise ValueError('expected sync exception')"))
            assert failed.run["state"]=="kernel_failed" and failed.errors[0]["ename"]=="ValueError"
            active=client.start_code(cid,CodeRunSpec("import time\nprint('armed',flush=True)\ntime.sleep(60)"),str(uuid4()))
            with closing(client.code_context_events(cid,active["events_after"])) as events:
                cursor=next(event["sequence"] for event in events if event["kind"]=="stdout" and event["run_id"]==active["id"])
            assert client.code_context(cid)["state"]=="ready"
            queued=client.start_code(cid,CodeRunSpec("print('must not run')"),str(uuid4()))
            client.cancel_code_run(active["id"])
            assert client.wait_code_context_closed(cid)["cleanup"]=="complete"
            assert client.code_run(active["id"])["state"]=="cancelled" and client.code_run(queued["id"])["state"]=="cancelled"
            with closing(client.code_context_events(cid,cursor)) as events:history=list(events)
            assert history[0]["sequence"]==cursor+1 and history[-1]["kind"]=="closed"
            assert any(item["id"]==cid for item in client.list_code_contexts(sid)["items"])
            assert any(item["id"]==active["id"] for item in client.list_code_runs(cid)["items"])
            timeout=client.create_code_context(sid,CodeContextSpec(),str(uuid4()))["id"]
            client.wait_code_context_ready(timeout)
            assert client.run_code(timeout,CodeRunSpec("import time;time.sleep(60)",timeout_seconds=1)).run["state"]=="timed_out"
            assert client.wait_code_context_closed(timeout)["cleanup"]=="complete"
            crashed=client.create_code_context(sid,CodeContextSpec(),str(uuid4()))["id"]
            client.wait_code_context_ready(crashed)
            try:client.run_code(crashed,CodeRunSpec("import os;os._exit(7)"))
            except CodeObservationError as error:assert client.code_run(error.run_id)["state"]=="unknown"
            else:raise AssertionError("kernel crash became a successful SDK result")
            assert client.wait_code_context_closed(crashed)["state"]=="failed"
    return {"result":"passed","cleanup":"complete","cases":["retained_state","replay_cursor","rich_result","kernel_exception","sse_resume","cancel_queue","timeout","unknown_crash","metadata_pages"]}


async def async_code_contract():
    async with AsyncClient(ENDPOINT,TOKEN) as client:
        async with client.lease(request()) as lease:
            sid=lease.id
            key=str(uuid4())
            cid=(await client.create_code_context(sid,CodeContextSpec(),key))["id"]
            assert (await client.create_code_context(sid,CodeContextSpec(),key))["id"]==cid
            await client.wait_code_context_ready(cid)
            assert (await client.run_code(cid,CodeRunSpec("value=40"))).run["state"]=="kernel_succeeded"
            spec=CodeRunSpec("value+=1\nopen('/workspace/async-code-once','a').write('1')\nprint(value)\nvalue")
            key=str(uuid4())
            first=await client.run_code(cid,spec,key)
            replay=await client.run_code(cid,spec,key)
            assert replay.run["id"]==first.run["id"] and replay.run["events_after"]==first.run["events_after"]
            assert replay.stdout=="41\n" and await client.read_file(sid,"async-code-once")==b"1"
            result=await client.run_code(cid,CodeRunSpec("print(value+1)\nvalue+1"))
            assert result.stdout=="42\n" and result.results[0]["data"]["text/plain"]=="42"
            failed=await client.run_code(cid,CodeRunSpec("raise ValueError('expected async exception')"))
            assert failed.run["state"]=="kernel_failed" and failed.errors[0]["ename"]=="ValueError"
            spec=CodeRunSpec("import time\nopen('/workspace/async-observer-once','a').write('1')\nprint('begin',flush=True)\ntime.sleep(2)\nprint('end',flush=True)")
            key=str(uuid4())
            accepted=await client.start_code(cid,spec,key)
            observer=asyncio.create_task(client.run_code(cid,spec,key))
            try:
                async with aclosing(client.code_context_events(cid,accepted["events_after"])) as events:
                    async for event in events:
                        if event["kind"]=="stdout" and event["run_id"]==accepted["id"]:break
            finally:
                observer.cancel()
                try:await observer
                except asyncio.CancelledError:pass
            assert (await client.code_context(cid))["state"]=="ready"
            completed=await client.run_code(cid,spec,key)
            assert completed.stdout=="begin\nend\n" and await client.read_file(sid,"async-observer-once")==b"1"
            active=await client.start_code(cid,CodeRunSpec("print('armed',flush=True)\ntime.sleep(60)"),str(uuid4()))
            async with aclosing(client.code_context_events(cid,active["events_after"])) as events:
                async for event in events:
                    if event["kind"]=="stdout" and event["run_id"]==active["id"]:cursor=event["sequence"];break
            queued=await client.start_code(cid,CodeRunSpec("print('must not run')"),str(uuid4()))
            await client.cancel_code_run(active["id"])
            await client.wait_code_context_closed(cid)
            assert (await client.code_run(active["id"]))["state"]=="cancelled" and (await client.code_run(queued["id"]))["state"]=="cancelled"
            async with aclosing(client.code_context_events(cid,cursor)) as events:history=[event async for event in events]
            assert history[0]["sequence"]==cursor+1 and history[-1]["kind"]=="closed"
            assert any(item["id"]==cid for item in (await client.list_code_contexts(sid))["items"])
            assert any(item["id"]==active["id"] for item in (await client.list_code_runs(cid))["items"])
            timeout=(await client.create_code_context(sid,CodeContextSpec(),str(uuid4())))["id"]
            await client.wait_code_context_ready(timeout)
            assert (await client.run_code(timeout,CodeRunSpec("import time;time.sleep(60)",timeout_seconds=1))).run["state"]=="timed_out"
            assert (await client.wait_code_context_closed(timeout))["cleanup"]=="complete"
            crashed=(await client.create_code_context(sid,CodeContextSpec(),str(uuid4())))["id"]
            await client.wait_code_context_ready(crashed)
            try:await client.run_code(crashed,CodeRunSpec("import os;os._exit(7)"))
            except CodeObservationError as error:assert (await client.code_run(error.run_id))["state"]=="unknown"
            else:raise AssertionError("kernel crash became a successful async result")
            assert (await client.wait_code_context_closed(crashed))["state"]=="failed"
    return {"result":"passed","cleanup":"complete","cases":["retained_state","replay_cursor","rich_result","kernel_exception","cancel_observer_without_cancelling_code","sse_resume","cancel_queue","timeout","unknown_crash","metadata_pages"]}


def cli_code_contract(binary):
    def invoke(*args,source=None,expected=0,lines=False,empty=False):
        result=subprocess.run([str(Path(binary).resolve()),*args],input=None if source is None else source.encode(),capture_output=True,timeout=80,creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
        assert result.returncode==expected,(args,result.returncode,result.stdout.decode(errors="replace"),result.stderr.decode(errors="replace"))
        if empty:return result
        return [json.loads(line) for line in result.stdout.splitlines()] if lines else json.loads(result.stdout)
    created=invoke("create","--profile",request().profile,"--image",request().image,"--ttl","180")
    sid=created["sandbox"]["id"]
    try:
        key=str(uuid4())
        cid=invoke("context-create",sid,"--idempotency-key",key)["id"]
        assert invoke("context-create",sid,"--idempotency-key",key)["id"]==cid
        assert invoke("code-run",cid,"-",source="value=40")["run"]["state"]=="kernel_succeeded"
        snippet="value+=1\nopen('/workspace/cli-code-once','a').write('1')\nprint(value)\nvalue"
        key=str(uuid4())
        first=invoke("code-run",cid,"-","--idempotency-key",key,source=snippet)
        replay=invoke("code-run",cid,"-","--idempotency-key",key,source=snippet)
        assert first["run"]["id"]==replay["run"]["id"] and replay["stdout"]=="41\n"
        result=invoke("code-run",cid,"-",source="print(value+1)\nvalue+1")
        assert result["stdout"]=="42\n" and result["results"][0]["data"]["text/plain"]=="42"
        failure=invoke("code-run",cid,"-",source="raise ValueError('expected CLI exception')",expected=1)
        assert failure["run"]["state"]=="kernel_failed" and failure["errors"][0]["ename"]=="ValueError"
        active=invoke("code-run",cid,"-","--no-wait",source="import time\nprint('armed',flush=True)\ntime.sleep(60)")
        with Client(ENDPOINT,TOKEN) as observer:
            assert observer.read_file(sid,"cli-code-once")==b"1"
            with closing(observer.code_context_events(cid,active["events_after"])) as events:
                cursor=next(event["sequence"] for event in events if event["kind"]=="stdout" and event["run_id"]==active["id"])
        queued=invoke("code-run",cid,"-","--no-wait",source="print('must not run')")
        assert invoke("code-cancel",active["id"])["state"]=="cancelled"
        assert invoke("code-get",queued["id"])["state"]=="cancelled"
        assert invoke("context-get",cid)["cleanup"]=="complete"
        events=invoke("context-events",cid,"--after",str(cursor),lines=True)
        assert events[0]["sequence"]==cursor+1 and events[-1]["kind"]=="closed"
        assert any(item["id"]==cid for item in invoke("context-list","--sandbox",sid)["items"])
        assert any(item["id"]==active["id"] for item in invoke("code-list",cid)["items"])
        timeout=invoke("context-create",sid)["id"]
        assert invoke("code-run",timeout,"-","--timeout","1",source="import time;time.sleep(60)",expected=124)["run"]["state"]=="timed_out"
        assert invoke("context-close",timeout)["cleanup"]=="complete"
        crashed=invoke("context-create",sid)["id"]
        key=str(uuid4())
        invoke("code-run",crashed,"-","--idempotency-key",key,source="import os;os._exit(7)",expected=125,empty=True)
        replay=invoke("code-run",crashed,"-","--idempotency-key",key,"--no-wait",source="import os;os._exit(7)")
        assert replay["state"]=="unknown" and invoke("context-get",crashed)["cleanup"]=="complete"
    finally:
        invoke("delete",sid)
    assert invoke("get",sid)["cleanup"]=="complete"
    return {"result":"passed","cleanup":"complete","cases":["retained_state","replay_cursor","rich_result","kernel_exception_exit_1","no_wait","cancel_queue","event_resume","timeout_exit_124","unknown_exit_125","metadata_pages"]}
