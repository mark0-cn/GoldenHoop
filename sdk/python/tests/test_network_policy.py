import copy
import json
import unittest
from uuid import uuid4
import httpx
from goldenhoop import Client, AsyncClient, ProtocolError
from goldenhoop._network import policy_state, policy_request, policy_change

BASE = "http://127.0.0.1:8080/"
TOKEN = "network-policy-test-credential-0000000000"
POLICY = {"default_action": "deny", "rules": []}


class NetworkPolicyProtocolTests(unittest.TestCase):
    def test_revision_identity_defaults_and_changed_content_are_checked(self):
        sid = str(uuid4())
        request = policy_request(0, {"default_action": "deny"})
        self.assertEqual(request["policy"], POLICY)
        self.assertEqual(policy_request(0, {"default_action": "deny", "rules": [{"destination": "*", "action": "deny"}]})["policy"]["rules"][0]["ports"], [])
        state = {"sandbox_id": sid, "revision": 1, "policy": copy.deepcopy(POLICY)}
        changed = {"policy": state, "operation": {"id": str(uuid4()), "resource_id": sid, "state": "pending"}}
        policy_change(changed, sid, request)
        for field, value in [("sandbox_id", str(uuid4())), ("revision", True), ("revision", -1), ("policy", None)]:
            with self.subTest(field=field), self.assertRaises(ProtocolError):
                policy_state(dict(state, **{field: value}), sid)
        for change in [{"revision": 0}, {"policy": {"default_action": "allow", "rules": []}}]:
            mutated = copy.deepcopy(changed)
            mutated["policy"].update(change)
            with self.assertRaises(ProtocolError):
                policy_change(mutated, sid, request)
        mutated = copy.deepcopy(changed)
        mutated["operation"]["resource_id"] = str(uuid4())
        with self.assertRaises(ProtocolError):
            policy_change(mutated, sid, request)
        for revision in [True, -1, 2**63 - 1, 0.5]:
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                policy_request(revision, POLICY)

    def test_sync_requests_preserve_put_cas_key_and_pending_is_not_application(self):
        sid, oid = str(uuid4()), str(uuid4())
        calls = []
        def handler(request):
            calls.append((request.method, request.url.path, request.headers.get("idempotency-key")))
            if request.method == "GET":
                return httpx.Response(200, json={"sandbox_id": sid, "revision": 0, "policy": POLICY})
            self.assertEqual(json.loads(request.content), {"expected_revision": 0, "policy": POLICY})
            return httpx.Response(202, json={"policy": {"sandbox_id": sid, "revision": 1, "policy": POLICY}, "operation": {"id": oid, "resource_id": sid, "state": "pending"}})
        client = Client(BASE, TOKEN)
        client._http.close()
        client._http = httpx.Client(base_url=BASE, transport=httpx.MockTransport(handler))
        try:
            self.assertEqual(client.network_policy(sid)["revision"], 0)
            changed = client.set_network_policy(sid, {"default_action": "deny"}, 0, "same-request")
            self.assertEqual(changed["operation"]["state"], "pending")
            self.assertEqual(calls, [("GET", f"/v1/sandboxes/{sid}/network-policy", None), ("PUT", f"/v1/sandboxes/{sid}/network-policy", "same-request")])
        finally:
            client.close()


class NetworkPolicyAsyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_requests_preserve_the_same_versioned_contract(self):
        sid, oid = str(uuid4()), str(uuid4())
        calls = []
        def handler(request):
            calls.append((request.method, request.headers.get("idempotency-key")))
            if request.method == "GET":
                return httpx.Response(200, json={"sandbox_id": sid, "revision": 0, "policy": POLICY})
            self.assertEqual(json.loads(request.content), {"expected_revision": 0, "policy": POLICY})
            return httpx.Response(202, json={"policy": {"sandbox_id": sid, "revision": 1, "policy": POLICY}, "operation": {"id": oid, "resource_id": sid, "state": "pending"}})
        client = AsyncClient(BASE, TOKEN)
        await client._http.aclose()
        client._http = httpx.AsyncClient(base_url=BASE, transport=httpx.MockTransport(handler))
        try:
            self.assertEqual((await client.network_policy(sid))["revision"], 0)
            changed = await client.set_network_policy(sid, POLICY, 0, "async-request")
            self.assertEqual(changed["operation"]["state"], "pending")
            self.assertEqual(calls, [("GET", None), ("PUT", "async-request")])
        finally:
            await client.close()
