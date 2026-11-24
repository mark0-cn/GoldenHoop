import asyncio
import json
import unittest
from uuid import uuid4
import httpx
from goldenhoop import AsyncClient, Client, CodeContextSpec, CodeRunSpec, CodeObservationError, ProtocolError, WaitTimeout
from goldenhoop._code import CodeCollector, context_decoder, context_spec, run_spec

TOKEN = "code-test-credential-0000000000000000000000"
STAMP = "2026-01-01T00:00:00Z"


def context(cid, sid):
    return {"id":cid,"sandbox_id":sid,"spec":{"language":"python","cwd":"/workspace"},"state":"ready","desired_state":"open","cleanup":"pending","created_at":STAMP,"ready_at":STAMP,"finished_at":None,"kernel_info":{},"reason":None}


def run(cid, rid, state="pending"):
    return {"id":rid,"context_id":cid,"events_after":4,"state":state,"created_at":STAMP,"started_at":STAMP if state!="pending" else None,"finished_at":STAMP if state not in {"pending","running"} else None,"output_truncated":False,"kernel_status":"ok" if state=="kernel_succeeded" else "error" if state=="kernel_failed" else None,"reason":None}


def frame(cid, rid, sequence, kind, data):
    value={"context_id":cid,"run_id":rid,"sequence":sequence,"kind":kind,"timestamp":STAMP,"data":data}
    return f"id: {cid}:{sequence}\nevent: code_context\ndata: {json.dumps(value)}\n\n".encode()


class CodeProtocolTests(unittest.TestCase):
    def test_utf8_source_budget_and_context_specification_are_checked(self):
        self.assertEqual(context_spec(CodeContextSpec())["language"],"python")
        for value in [CodeRunSpec("中"*22000),CodeRunSpec("x\0"),{"code":"x","timeout_seconds":True},{"code":"x","max_output_bytes":True}]:
            with self.assertRaises(ProtocolError):run_spec(value)
        for language in ("python", "java", "go", "typescript", "bash", "javascript"):
            self.assertEqual(context_spec(CodeContextSpec(language=language))["language"], language)
        for language in ("ruby", "JavaScript", [], None):
            with self.assertRaises(ProtocolError): context_spec({"language":language})

    def test_context_framing_refuses_wrong_scope_boolean_cursor_and_oversized_lines(self):
        cid,rid=str(uuid4()),str(uuid4())
        for value in [frame(cid,rid,True,"stdout",{}),frame(str(uuid4()),rid,1,"stdout",{}),b"x"*(2*1024*1024+16385)]:
            decoder=context_decoder(cid,0)
            with self.assertRaises(ProtocolError):list(decoder.feed(value))
            self.assertLessEqual(len(decoder.pending),2*1024*1024+16384+65536)

    def test_kernel_exception_and_unknown_have_distinct_results_and_late_output_is_excluded(self):
        cid,rid=str(uuid4()),str(uuid4())
        accepted=run(cid,rid)
        collector=CodeCollector(accepted,1024)
        collector.accept({"sequence":5,"run_id":rid,"kind":"stdout","data":{"late":True,"content":{"text":"background"}}})
        result=collector.accept({"sequence":6,"run_id":rid,"kind":"run_completed","data":run(cid,rid,"kernel_failed")})
        self.assertEqual((result.run["state"],result.stdout),("kernel_failed",""))
        with self.assertRaises(ProtocolError):CodeCollector(accepted,1024).accept({"sequence":5,"run_id":rid,"kind":"run_completed","data":run(cid,rid,"unknown")})

    def test_old_key_and_partial_eof_resume_from_acceptance_then_whole_event_cursor(self):
        cid,sid,rid=str(uuid4()),str(uuid4()),str(uuid4())
        seen=[]
        def handler(request):
            if request.method=="POST":return httpx.Response(202,json=run(cid,rid,"kernel_succeeded"))
            if request.url.path.endswith("/events"):
                cursor=request.headers["last-event-id"];seen.append(cursor)
                data=frame(cid,rid,5,"stdout",{"late":False,"content":{"text":"once"}})+b"data: {partial" if cursor.endswith(":4") else frame(cid,rid,6,"run_completed",run(cid,rid,"kernel_succeeded"))
                return httpx.Response(200,headers={"content-type":"text/event-stream"},content=data)
            return httpx.Response(200,json=context(cid,sid))
        with Client("http://127.0.0.1",TOKEN) as client:
            client.close();client._http=httpx.Client(base_url="http://127.0.0.1/",transport=httpx.MockTransport(handler))
            result=client.run_code(cid,CodeRunSpec("do_not_repeat()"),"old-key")
        self.assertEqual(result.stdout,"once")
        self.assertEqual(seen,[f"{cid}:4",f"{cid}:5"])

    def test_clean_eof_and_cancel_without_collection_are_observation_errors(self):
        for cancellation in [False,True]:
            cid,sid,rid=str(uuid4()),str(uuid4()),str(uuid4())
            def handler(request):
                if request.method=="POST":return httpx.Response(202,json=run(cid,rid))
                if request.url.path.endswith("/events"):
                    content=frame(cid,rid,5,"run_completed",run(cid,rid,"cancelled")) if cancellation else b": heartbeat\n\n"
                    return httpx.Response(200,headers={"content-type":"text/event-stream"},content=content)
                return httpx.Response(200,json=context(cid,sid))
            with Client("http://127.0.0.1",TOKEN) as client:
                client.close();client._http=httpx.Client(base_url="http://127.0.0.1/",transport=httpx.MockTransport(handler))
                with self.assertRaises(CodeObservationError) as error:client.run_code(cid,CodeRunSpec("maybe()"))
                self.assertEqual(error.exception.run_id,rid)


class AsyncCodeProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_clean_eof_is_not_a_kernel_result(self):
        cid,sid,rid=str(uuid4()),str(uuid4()),str(uuid4())
        def handler(request):
            if request.method=="POST":return httpx.Response(202,json=run(cid,rid))
            if request.url.path.endswith("/events"):return httpx.Response(200,headers={"content-type":"text/event-stream"},content=b": heartbeat\n\n")
            return httpx.Response(200,json=context(cid,sid))
        async with AsyncClient("http://127.0.0.1",TOKEN) as client:
            await client.close();client._http=httpx.AsyncClient(base_url="http://127.0.0.1/",transport=httpx.MockTransport(handler))
            with self.assertRaises(CodeObservationError) as error:await client.run_code(cid,CodeRunSpec("maybe()"))
            self.assertEqual(error.exception.run_id,rid)

    async def test_async_wait_deadline_bounds_stalled_context_http(self):
        async def handler(request):
            await asyncio.sleep(60)
            return httpx.Response(200,json={})
        async with AsyncClient("http://127.0.0.1",TOKEN) as client:
            await client.close();client._http=httpx.AsyncClient(base_url="http://127.0.0.1/",transport=httpx.MockTransport(handler))
            for method in [client.wait_code_context_ready,client.wait_code_context_closed]:
                with self.assertRaises(WaitTimeout):await method(str(uuid4()),timeout=.03)

    async def test_cancelled_submission_preserves_explicit_code_key(self):
        started=asyncio.Event()
        async def handler(request):
            started.set();await asyncio.sleep(60);return httpx.Response(200,json={})
        async with AsyncClient("http://127.0.0.1",TOKEN) as client:
            await client.close();client._http=httpx.AsyncClient(base_url="http://127.0.0.1/",transport=httpx.MockTransport(handler))
            task=asyncio.create_task(client.run_code(str(uuid4()),CodeRunSpec("maybe()"),"same-code-key"))
            await asyncio.wait_for(started.wait(),1);task.cancel()
            with self.assertRaises(asyncio.CancelledError) as error:await task
            self.assertTrue(any("same-code-key" in note for note in error.exception.__notes__))
