import asyncio
import json
import unittest
from uuid import uuid4

import httpx

from goldenhoop import AsyncClient, Client, Command, ObservationError, ProtocolError, WaitTimeout
from goldenhoop._protocol import SseDecoder, TransportError

TOKEN = "test-credential-0000000000000000000000000"


def execution(sid, eid, terminal=False):
    return {"id": eid, "sandbox_id": sid, "state": "succeeded" if terminal else "pending",
            "exit_code": 0 if terminal else None, "cleanup": "complete" if terminal else "pending"}


def frame(eid, sequence, kind, data):
    value = {"execution_id": eid, "sequence": sequence, "kind": kind, "data": data}
    return f"id: {eid}:{sequence}\nevent: execution\ndata: {json.dumps(value)}\n\n".encode()


class ProtocolTests(unittest.TestCase):
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
