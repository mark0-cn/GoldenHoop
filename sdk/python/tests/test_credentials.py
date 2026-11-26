import copy
import unittest
from uuid import uuid4
import httpx
from goldenhoop import Client, AsyncClient, ProtocolError, TransportError
from goldenhoop._credentials import record, records, ca

BASE = 'http://127.0.0.1:8080/'
TOKEN = 'credential-contract-administrator-token'


def metadata(sid, bid):
    return dict(id=bid, sandbox_id=sid, revision=1, applied_revision=None, state='pending', binding={})


class Credentials(unittest.TestCase):
    def test_cross_sandbox_identity_unapplied_active_duplicate_and_private_fields_are_refused(self):
        sid, bid = str(uuid4()), str(uuid4())
        value = metadata(sid, bid)
        self.assertEqual(record(value, sid, bid)['state'], 'pending')
        for update in [dict(sandbox_id=str(uuid4())), dict(state='active'), dict(revision=True), dict(secret='forbidden')]:
            with self.assertRaises(ProtocolError):
                record({**value, **update}, sid, bid)
        with self.assertRaises(ProtocolError):
            records([value, value], sid)
        with self.assertRaises(ProtocolError):
            ca(dict(sandbox_id=sid, certificate_pem='-----BEGIN CERTIFICATE-----PRIVATE KEY'), sid)

    def test_sync_transport_does_not_retry_uncertain_private_writes(self):
        sid, bid = str(uuid4()), str(uuid4())
        calls = []
        def handler(request):
            calls.append(request.method)
            raise httpx.ReadError('lost response', request=request)
        with Client(BASE, TOKEN) as client:
            client._http.close()
            client._http = httpx.Client(base_url=BASE, transport=httpx.MockTransport(handler))
            with self.assertRaises(TransportError):
                client.put_credential(sid, bid, dict(expected_revision=0))
        self.assertEqual(calls, ['PUT'])


class AsyncCredentials(unittest.IsolatedAsyncioTestCase):
    async def test_async_transport_refuses_a_credential_from_another_sandbox(self):
        sid, bid = str(uuid4()), str(uuid4())
        value = metadata(str(uuid4()), bid)
        def handler(request):
            return httpx.Response(200, json=copy.deepcopy(value))
        async with AsyncClient(BASE, TOKEN) as client:
            await client._http.aclose()
            client._http = httpx.AsyncClient(base_url=BASE, transport=httpx.MockTransport(handler))
            with self.assertRaises(ProtocolError):
                await client.credential(sid, bid)
