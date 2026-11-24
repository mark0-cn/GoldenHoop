import asyncio
import json
import unittest
from uuid import uuid4

import httpx

from goldenhoop import AsyncClient, Client, Command, ObservationError, ProtocolError, WaitTimeout
from goldenhoop._protocol import SseDecoder, TransportError
from goldenhoop import SessionControl, SessionSpec
from goldenhoop._protocol import body, check_session, check_session_receipt

TOKEN = "test-credential-0000000000000000000000000"


def execution(sid, eid, terminal=False):
    return {"id": eid, "sandbox_id": sid, "state": "succeeded" if terminal else "pending",
            "exit_code": 0 if terminal else None, "cleanup": "complete" if terminal else "pending"}


def frame(eid, sequence, kind, data):
    value = {"execution_id": eid, "sequence": sequence, "kind": kind, "data": data}
    return f"id: {eid}:{sequence}\nevent: execution\ndata: {json.dumps(value)}\n\n".encode()


class ProtocolTests(unittest.TestCase):
    def test_session_receipts_and_nested_spec_identity_are_validated(self):
        sid, eid = str(uuid4()), str(uuid4())
        spec = body(SessionSpec())
        record = {"execution": execution(sid, eid), "spec": spec}
        check_session(record, execution_id=eid, sandbox_id=sid, request=spec)
        self.assertEqual(body(SessionControl.write(1, b"\x00\xff"))["action"]["data_base64"], "AP8=")
        receipt = {"execution_id": eid, "sequence": 1, "state": "applied", "error": None}
        check_session_receipt(receipt, eid, 1)
        for change in ({"execution_id": sid}, {"sequence": True}, {"state": "unknown"}, {"state": "unexpected"}):
            with self.assertRaises(ProtocolError):
                check_session_receipt(receipt | change, eid, 1)
        altered = {"command": {"argv": ["different"]}, "terminal": None}
        with self.assertRaises(ProtocolError):
            check_session(record, sandbox_id=sid, request=altered)

    def test_partial_frames_commit_only_complete_cursor(self):
        eid = str(uuid4())
        raw = frame(eid, 1, "stdout", {"encoding": "base64", "data": "AP8="})
        decoder, found = SseDecoder(eid), []
        for byte in raw:
            found.extend(decoder.feed(bytes([byte])))
        self.assertEqual([event["sequence"] for event in found], [1])
        self.assertEqual(decoder.cursor, 1)
        list(decoder.feed(b"data: {"))
        with self.assertRaises(TransportError):
            decoder.finish()

    def test_wrong_cursor_and_oversized_line_are_rejected(self):
        eid = str(uuid4())
        for raw in (frame(eid, 2, "stdout", {}), b"x" * (2 * 1024 * 1024 + 1)):
            with self.assertRaises(ProtocolError):
                list(SseDecoder(eid).feed(raw))

    def test_remote_plaintext_embedded_credentials_and_bad_ipv6_are_rejected(self):
        for url in ("http://example.com", "https://user:secret@example.com", "https://example.com/?token=secret", "http://[invalid"):
            with self.assertRaises(ProtocolError):
                Client(url, TOKEN)

    def test_sync_clean_eof_is_not_success(self):
        sid, eid = str(uuid4()), str(uuid4())
        def handler(request):
            if request.method == "POST":
                return httpx.Response(202, json=execution(sid, eid))
            return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=b":heartbeat\n\n")
        with Client("http://127.0.0.1", TOKEN) as client:
            client._http.close()
            client._http = httpx.Client(base_url="http://127.0.0.1/", transport=httpx.MockTransport(handler))
            with self.assertRaises(ObservationError) as failure:
                client.run(sid, Command(["true"]))
            self.assertEqual(failure.exception.execution_id, eid)

    def test_artifact_download_refuses_digest_mismatch(self):
        aid = str(uuid4())
        def handler(request):
            if request.url.path.endswith("/content"):
                return httpx.Response(200, content=b"abc", headers={"content-type": "application/octet-stream"})
            return httpx.Response(200, json={"id": aid, "state": "available", "desired_state": "available", "size_bytes": 3, "sha256": "0" * 64})
        with Client("http://127.0.0.1", TOKEN) as client:
            client._http.close()
            client._http = httpx.Client(base_url="http://127.0.0.1/", transport=httpx.MockTransport(handler))
            with self.assertRaises(ProtocolError):
                client.artifact_bytes(aid)

    def test_sync_partial_eof_reconnects_without_duplicate_output(self):
        sid, eid = str(uuid4()), str(uuid4())
        seen = []
        def handler(request):
            if request.method == "POST":
                return httpx.Response(202, json=execution(sid, eid))
            cursor = request.headers["last-event-id"]
            seen.append(cursor)
            data = (frame(eid, 1, "stdout", {"encoding": "base64", "data": "AP8="}) + b"data: {") if cursor.endswith(":0") else frame(eid, 2, "completed", execution(sid, eid, True))
            return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=data)
        with Client("http://127.0.0.1", TOKEN) as client:
            client._http.close()
            client._http = httpx.Client(base_url="http://127.0.0.1/", transport=httpx.MockTransport(handler))
            self.assertEqual(client.run(sid, Command(["true"])).stdout, b"\x00\xff")
        self.assertEqual(seen, [f"{eid}:0", f"{eid}:1"])


class AsyncProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancelled_session_submission_preserves_recovery_sequence(self):
        eid, seen = str(uuid4()), asyncio.Event()
        async def handler(request):
            seen.set()
            await asyncio.sleep(60)
            return httpx.Response(202, json={})
        async with AsyncClient("http://127.0.0.1", TOKEN) as client:
            await client._http.aclose()
            client._http = httpx.AsyncClient(base_url="http://127.0.0.1/", transport=httpx.MockTransport(handler))
            task = asyncio.create_task(client.session_control(eid, SessionControl.write(1, b"echo once\n")))
            await asyncio.wait_for(seen.wait(), 2)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError) as failure:
                await task
            notes = " ".join(failure.exception.__notes__)
            self.assertIn(eid, notes)
            self.assertIn("control 1", notes)
            self.assertIn("same sequence and content", notes)

    async def test_async_clean_eof_is_not_success(self):
        sid, eid = str(uuid4()), str(uuid4())
        def handler(request):
            return (httpx.Response(202, json=execution(sid, eid)) if request.method == "POST" else
                    httpx.Response(200, headers={"content-type": "text/event-stream"}, content=b""))
        async with AsyncClient("http://127.0.0.1", TOKEN) as client:
            await client._http.aclose()
            client._http = httpx.AsyncClient(base_url="http://127.0.0.1/", transport=httpx.MockTransport(handler))
            with self.assertRaises(ObservationError) as failure:
                await client.run(sid, Command(["true"]))
            self.assertEqual(failure.exception.execution_id, eid)

    async def test_async_wait_deadline_bounds_stalled_http(self):
        eid = str(uuid4())
        async def handler(request):
            await asyncio.sleep(60)
            return httpx.Response(200, json={})
        async with AsyncClient("http://127.0.0.1", TOKEN) as client:
            await client._http.aclose()
            client._http = httpx.AsyncClient(base_url="http://127.0.0.1/", transport=httpx.MockTransport(handler))
            with self.assertRaises(WaitTimeout) as failure:
                await client.wait_execution(eid, timeout=0.05)
            self.assertEqual(failure.exception.identity, eid)


if __name__ == "__main__":
    unittest.main()
