import asyncio
import copy
import json
import unittest
from uuid import uuid4
import httpx
from goldenhoop import AsyncClient, Client, CreateSandbox, CreateIsolatedSession, ProtocolError
from goldenhoop._protocol import body
from goldenhoop._isolated import check_scope, check_isolated_created

BASE = "http://127.0.0.1:8080/"
TOKEN = "isolated-test-credential-000000000000000000"
LIMITS = {"cpu_millis": 1000, "memory_bytes": 1073741824, "pids": 256}
ZERO = dict.fromkeys(LIMITS, 0)


def fixtures():
    parent_id, child_id = str(uuid4()), str(uuid4())
    parent = {"id": parent_id, "profile": "local-runc-dev", "image": "fixture",
              "created_at": "2026-01-01T00:00:00Z", "expires_at": "2026-01-01T00:05:00Z"}
    scope = {"sandbox_id": parent_id, "parent_id": None, "root_id": parent_id, "depth": 0,
             "child_budget": {k: v*2 for k,v in LIMITS.items()}, "envelope": {k:v*3 for k,v in LIMITS.items()},
             "allocated_to_children": dict(LIMITS), "feature_limit": None}
    child = {"sandbox": dict(parent, id=child_id, resources=dict(LIMITS), created_at="2026-01-01T00:00:01Z"),
             "operation": {"id": str(uuid4()), "resource_id": child_id},
             "scope": {"sandbox_id": child_id, "parent_id": parent_id, "root_id": parent_id, "depth": 1,
                       "child_budget": None, "envelope": dict(LIMITS), "allocated_to_children": dict(ZERO),
                       "feature_limit": ["commands", "files"]}}
    return parent, scope, child


class IsolatedProtocolTests(unittest.TestCase):
    def test_default_optional_fields_preserve_the_existing_create_wire(self):
        request = body(CreateSandbox("local-runc-dev", "fixture"))
        self.assertNotIn("child_budget", request)
        self.assertNotIn("feature_limit", request)
        child = body(CreateIsolatedSession(feature_limit=[]))
        self.assertEqual(child["feature_limit"], [])
        self.assertNotIn("ttl_seconds", child)
        self.assertNotIn("image", child)

    def test_scope_refuses_foreign_identity_invalid_depth_and_unreserved_allocations(self):
        _, _, created = fixtures()
        original = created["scope"]
        check_scope(original, original["sandbox_id"])
        changes = [{"depth": True}, {"depth": 5}, {"parent_id": original["sandbox_id"]},
                   {"root_id": original["sandbox_id"]}, {"feature_limit": None},
                   {"allocated_to_children": dict(LIMITS)}, {"envelope": dict(LIMITS, pids=True)},
                   {"child_budget": dict(ZERO)}]
        for changed in changes:
            with self.subTest(changed=changed), self.assertRaises(ProtocolError):
                check_scope(dict(original, **changed), original["sandbox_id"])

    def test_create_refuses_broader_features_wrong_parent_resources_and_extended_expiry(self):
        parent, scope, original = fixtures()
        request = body(CreateIsolatedSession(feature_limit=["commands", "files"]))
        check_isolated_created(original, request, parent, scope)
        for section, field, value in [("scope", "root_id", str(uuid4())), ("scope", "parent_id", str(uuid4())),
                                      ("scope", "feature_limit", ["commands", "files", "gpu"]),
                                      ("sandbox", "profile", "other"), ("sandbox", "resources", dict(LIMITS, pids=257)),
                                      ("sandbox", "expires_at", "2026-01-01T00:05:01Z")]:
            changed = copy.deepcopy(original)
            changed[section][field] = value
            with self.subTest(field=field), self.assertRaises(ProtocolError):
                check_isolated_created(changed, request, parent, scope)

    def test_sync_child_submission_binds_parent_scope_and_explicit_key(self):
        parent, scope, child = fixtures()
        posts = []
        def handler(request):
            if request.method == "POST":
                posts.append(request)
                return httpx.Response(202, json=child)
            return httpx.Response(200, json=scope if request.url.path.endswith("/scope") else parent)
        with Client(BASE, TOKEN) as client:
            client._http.close()
            client._http = httpx.Client(base_url=BASE, transport=httpx.MockTransport(handler))
            value = client.create_isolated_session(parent["id"], CreateIsolatedSession(), "stable-child-key")
        self.assertEqual(value["sandbox"]["id"], child["sandbox"]["id"])
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0].headers["idempotency-key"], "stable-child-key")
        self.assertNotIn("image", json.loads(posts[0].content))


class AsyncIsolatedProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancelled_child_lease_acceptance_keeps_the_recovery_key(self):
        parent, scope, _ = fixtures()
        posted = asyncio.Event()
        keys = []
        async def handler(request):
            if request.method == "POST":
                keys.append(request.headers["idempotency-key"])
                posted.set()
                await asyncio.Future()
            return httpx.Response(200, json=scope if request.url.path.endswith("/scope") else parent)
        async with AsyncClient(BASE, TOKEN) as client:
            await client._http.aclose()
            client._http = httpx.AsyncClient(base_url=BASE, transport=httpx.MockTransport(handler))
            lease = client.isolated_lease(parent["id"], CreateIsolatedSession())
            owner = asyncio.create_task(lease.__aenter__())
            await asyncio.wait_for(posted.wait(), 2)
            owner.cancel()
            with self.assertRaises(asyncio.CancelledError) as caught:
                await owner
        self.assertEqual(len(keys), 1)
        self.assertTrue(any(keys[0] in note for note in caught.exception.__notes__))
