import asyncio
import copy
import unittest
from uuid import uuid4

import httpx
from goldenhoop import AsyncClient, Client, CreateSandbox, RestoreSnapshot, ProtocolError
from goldenhoop import _snapshots
from goldenhoop._protocol import TransportError

BASE = "http://127.0.0.1:8080/"
TOKEN = "restore-client-synthetic-token-0123456789abcdef"


def fixture():
    snapshot, target, operation, old, new = [str(uuid4()) for _ in range(5)]
    intent = RestoreSnapshot(CreateSandbox("fixture", "fixture-image"))
    request = _snapshots.restore_request(intent)
    value = {"snapshot_id": snapshot, "sandbox": {"id": target, "profile": "fixture", "image": "fixture-image", "resources": request["target"]["resources"]},
             "operation": {"id": operation, "resource_id": target, "state": "pending"},
             "executions": [{"source_execution_id": old, "execution": {"id": new, "sandbox_id": target}}]}
    return intent, request, value


class RestorationTests(unittest.TestCase):
    def test_foreign_targets_reused_source_ids_and_duplicate_bindings_are_rejected(self):
        _, request, original = fixture()
        _snapshots.restored(original, snapshot_id=original["snapshot_id"], request=request)
        for variant in range(8):
            value = copy.deepcopy(original)
            if variant == 0:
                value["snapshot_id"] = str(uuid4())
            elif variant == 1:
                value["operation"]["resource_id"] = str(uuid4())
            elif variant == 2:
                value["executions"][0]["execution"]["sandbox_id"] = str(uuid4())
            elif variant == 3:
                value["executions"][0]["execution"]["id"] = value["executions"][0]["source_execution_id"]
            elif variant == 4:
                value["executions"].append(copy.deepcopy(value["executions"][0]))
            elif variant == 5:
                value["sandbox"]["profile"] = "foreign"
            elif variant == 6:
                value["sandbox"]["id"] = "00000000-0000-0000-0000-000000000000"
            else:
                value["executions"][0]["source_execution_id"] = "00000000-0000-0000-0000-000000000000"
            with self.subTest(variant=variant), self.assertRaises(ProtocolError):
                _snapshots.restored(value, snapshot_id=original["snapshot_id"], request=request)
        for invalid in ({"target": {}}, {"target": request["target"], "host_path": "forbidden"}, {"target": dict(request["target"], host_path="forbidden")}):
            with self.assertRaises(ProtocolError):
                _snapshots.restore_request(invalid)

    def test_transport_loss_preserves_the_explicit_key_and_one_target(self):
        intent, request, value = fixture()
        seen = []
        def handler(call):
            seen.append((call.method, call.url.path, call.headers.get("idempotency-key")))
            if len(seen) <= 3:
                raise httpx.ReadError("synthetic reply loss")
            return httpx.Response(202 if call.method == "POST" else 200, json=value)
        with Client(BASE, TOKEN) as client:
            client._http.close()
            client._http = httpx.Client(base_url=BASE, transport=httpx.MockTransport(handler))
            with self.assertRaises(TransportError):
                client.restore_snapshot(value["snapshot_id"], intent, "stable")
            self.assertEqual([key for method, _, key in seen if method == "POST"], ["stable"] * 3)
            self.assertEqual(client.restore_snapshot(value["snapshot_id"], intent, "stable"), value)
            self.assertEqual(client.snapshot_restoration(value["sandbox"]["id"]), value)
        self.assertEqual([key for method, _, key in seen if method == "POST"], ["stable"] * 4)
        self.assertFalse(any(method == "DELETE" for method, _, _ in seen))


class AsyncRestorationTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancelled_acceptance_retains_the_same_recovery_key_and_execution_mapping(self):
        intent, _, value = fixture()
        accepted, seen = asyncio.Event(), []
        async def handler(call):
            seen.append((call.method, call.headers.get("idempotency-key")))
            if len(seen) == 1:
                accepted.set()
                await asyncio.Future()
            return httpx.Response(202 if call.method == "POST" else 200, json=value)
        async with AsyncClient(BASE, TOKEN) as client:
            await client._http.aclose()
            client._http = httpx.AsyncClient(base_url=BASE, transport=httpx.MockTransport(handler))
            task = asyncio.create_task(client.restore_snapshot(value["snapshot_id"], intent, "stable"))
            await asyncio.wait_for(accepted.wait(), 5)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertEqual(await client.restore_snapshot(value["snapshot_id"], intent, "stable"), value)
            self.assertEqual(await client.snapshot_restoration(value["sandbox"]["id"]), value)
        self.assertEqual([key for method, key in seen if method == "POST"], ["stable", "stable"])
        self.assertFalse(any(method == "DELETE" for method, _ in seen))
