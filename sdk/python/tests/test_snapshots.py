import asyncio
import copy
import json
import unittest
from uuid import uuid4

import httpx
from goldenhoop import AsyncClient, Client, CreateSnapshot, ProtocolError
from goldenhoop import _snapshots

BASE = "http://127.0.0.1:8080/"
TOKEN = "snapshot-client-fixture-0123456789abcdef"


def fixtures():
    sid, source, op = str(uuid4()), str(uuid4()), str(uuid4())
    snapshot = {"id": sid, "source_sandbox_id": source, "kind": "memory_and_disk",
                "state": "ready", "cleanup": "pending", "created_at": "2026-01-01T00:00:00Z",
                "observed_at": None, "error": None,
                "manifest": {"format_version": 1, "id": sid, "source_sandbox_id": source,
                             "kind": "memory_and_disk", "driver": "fixture", "architecture": "x86_64",
                             "image_digest": "sha256:fixture", "runtime_version": "fixture",
                             "created_at": "2026-01-01T00:00:00Z",
                             "objects": {k: "sha256:" + c * 64 for k, c in zip(("state", "memory", "disk"), "abc")}}}
    operation = {"id": op, "resource_id": sid, "state": "succeeded",
                 "created_at": "2026-01-01T00:00:00Z", "finished_at": None, "error": None}
    return source, {"snapshot": snapshot, "operation": operation}


class SnapshotProtocolTests(unittest.TestCase):
    def test_foreign_manifest_operation_and_incomplete_collection_are_rejected(self):
        source, original = fixtures()
        _snapshots.created(original, source, "memory_and_disk")
        for variant in range(9):
            changed = copy.deepcopy(original)
            if variant == 0:
                changed["snapshot"]["source_sandbox_id"] = str(uuid4())
            elif variant == 1:
                changed["operation"]["resource_id"] = str(uuid4())
            elif variant == 2:
                changed["snapshot"]["manifest"] = None
            elif variant == 3:
                changed["snapshot"].update(state="collected", cleanup="unknown")
            elif variant == 4:
                changed["snapshot"]["manifest"]["source_sandbox_id"] = str(uuid4())
            elif variant == 5:
                changed["snapshot"]["manifest"]["objects"]["state"] = "sha256:invalid"
            elif variant == 6:
                changed["snapshot"]["manifest"]["format_version"] = True
            elif variant == 7:
                changed["snapshot"]["kind"] = "rootfs"
            else:
                changed["snapshot"]["id"] = "00000000-0000-0000-0000-000000000000"
            with self.subTest(variant=variant), self.assertRaises(ProtocolError):
                _snapshots.created(changed, source, "memory_and_disk")

    def test_invalid_requests_and_page_authority_do_not_become_success(self):
        source, value = fixtures()
        for request in ({"kind": []}, {"kind": "unknown"}, {"kind": "memory_and_disk", "host_path": "/forbidden"}):
            with self.assertRaises(ProtocolError):
                _snapshots.request(request)
        snap = value["snapshot"]
        pages = [{"items": [snap], "next_cursor": str(uuid4())},
                 {"items": [snap, snap], "next_cursor": None},
                 {"items": [dict(snap, source_sandbox_id=str(uuid4()))], "next_cursor": None}]
        for page in pages:
            with self.assertRaises(ProtocolError):
                _snapshots.page(page, source, None, 2 if len(page["items"]) == 2 else 1)

    def test_sync_retry_keeps_explicit_key_and_delete_does_not_remove_source(self):
        source, created = fixtures()
        sid = created["snapshot"]["id"]
        seen = []
        accepted = False
        def handler(request):
            nonlocal accepted
            seen.append((request.method, request.url.path, request.headers.get("idempotency-key")))
            if request.method == "POST":
                self.assertEqual(json.loads(request.content), {"kind": "memory_and_disk"})
                if not accepted:
                    accepted = True
                    raise httpx.ReadError("lost reply after admission", request=request)
                return httpx.Response(202, json=created)
            if request.method == "DELETE":
                return httpx.Response(202, json=dict(created["operation"], id=str(uuid4()), state="pending"))
            if request.url.path == "/v1/snapshots":
                self.assertEqual(request.url.params["sandbox_id"], source)
                return httpx.Response(200, json={"items": [created["snapshot"]], "next_cursor": None})
            return httpx.Response(200, json=created["snapshot"])
        with Client(BASE, TOKEN) as client:
            client._http.close()
            client._http = httpx.Client(base_url=BASE, transport=httpx.MockTransport(handler))
            self.assertEqual(client.create_snapshot(source, CreateSnapshot("memory_and_disk"), "capture")["snapshot"]["id"], sid)
            self.assertEqual(client.snapshot(sid)["id"], sid)
            self.assertEqual(len(client.list_snapshots(source)["items"]), 1)
            self.assertEqual(client.delete_snapshot(sid, "delete")["state"], "pending")
        self.assertEqual([item[2] for item in seen if item[0] == "POST"], ["capture", "capture"])
        self.assertEqual([item[1] for item in seen if item[0] == "DELETE"], [f"/v1/snapshots/{sid}"])


class AsyncSnapshotTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancelled_acceptance_preserves_recovery_key_without_source_deletion(self):
        source, created = fixtures()
        accepted = asyncio.Event()
        seen = []
        async def handler(request):
            seen.append((request.method, request.url.path, request.headers.get("idempotency-key")))
            if request.method == "POST" and len(seen) == 1:
                accepted.set()
                await asyncio.Future()
            if request.method == "POST":
                return httpx.Response(202, json=created)
            if request.method == "DELETE":
                return httpx.Response(202, json=dict(created["operation"], state="pending"))
            if request.url.path == "/v1/snapshots":
                return httpx.Response(200, json={"items": [created["snapshot"]], "next_cursor": None})
            return httpx.Response(200, json=created["snapshot"])
        async with AsyncClient(BASE, TOKEN) as client:
            await client._http.aclose()
            client._http = httpx.AsyncClient(base_url=BASE, transport=httpx.MockTransport(handler))
            task = asyncio.create_task(client.create_snapshot(source, CreateSnapshot("memory_and_disk"), "stable-key"))
            await asyncio.wait_for(accepted.wait(), 5)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertFalse(any(item[0] == "DELETE" for item in seen))
            result = await client.create_snapshot(source, CreateSnapshot("memory_and_disk"), "stable-key")
            self.assertEqual(result["snapshot"]["id"], created["snapshot"]["id"])
            self.assertEqual((await client.snapshot(created["snapshot"]["id"]))["kind"], "memory_and_disk")
            self.assertEqual(len((await client.list_snapshots(source))["items"]), 1)
            self.assertEqual((await client.delete_snapshot(created["snapshot"]["id"], "delete"))["state"], "pending")
        self.assertEqual([item[2] for item in seen if item[0] == "POST"], ["stable-key", "stable-key"])
        self.assertEqual([item[1] for item in seen if item[0] == "DELETE"], [f"/v1/snapshots/{created['snapshot']['id']}"])
