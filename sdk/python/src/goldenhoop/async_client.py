"""Native asyncio API; cancellation of observation does not cancel execution."""
from __future__ import annotations

import asyncio
import base64
from collections.abc import AsyncIterator
from contextlib import aclosing
from uuid import uuid4

import httpx

from ._protocol import (
    ApiError, CleanupError, Collector, Command, CreateSandbox, Error, Json,
    MAX_BODY, MAX_FILE, ObservationError, ProtocolError, RunOutput, SseDecoder,
    TransportError, UncertainRequest, WaitTimeout, binary, body,
    check_created, check_record, decode_json, endpoint, identity, key_headers,
)
from ._protocol import ArtifactError, CreateArtifact, check_artifact_bytes, check_artifact_created
from ._protocol import SessionSpec, SessionControl, SessionControlError, check_session, check_session_receipt
from ._code_async import AsyncCodeClientMixin
from ._protocol import CreateIsolatedSession
from ._isolated import check_scope, check_isolated_created
from ._network import policy_state, policy_request, policy_change


class AsyncClient(AsyncCodeClientMixin):
    def __init__(self, base_url: str, token: str):
        self._http = httpx.AsyncClient(base_url=endpoint(base_url, token),
                                       headers={"authorization": "Bearer " + token},
                                       trust_env=False, follow_redirects=False,
                                       timeout=httpx.Timeout(30, connect=5, pool=5))

    async def close(self):
        await self._http.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    async def _read(self, response: httpx.Response, maximum: int = MAX_BODY) -> bytes:
        maximum = maximum if 200 <= response.status_code < 300 else 64 * 1024
        data = bytearray()
        async for chunk in response.aiter_bytes():
            data.extend(chunk)
            if len(data) > maximum:
                raise ProtocolError("response exceeds size limit")
        return bytes(data)

    async def _request(self, method: str, path: str, value=None, *, key=None, params=None):
        headers = key_headers(key)
        for attempt in range(3 if key else 1):
            try:
                async def send_once():
                    request = self._http.build_request(method, path, json=value, params=params, headers=headers)
                    async with aclosing(await self._http.send(request, stream=True)) as response:
                        return decode_json(response.status_code, await self._read(response))
                return await asyncio.wait_for(send_once(), 30)
            except (httpx.RequestError, TimeoutError):
                if key and attempt < 2:
                    await asyncio.sleep(0.1 * 2 ** attempt)
                else:
                    raise TransportError() from None

    async def issue_api_key(self, request: Json) -> Json:
        return await self._request("POST", "v1/api-keys", request)

    async def api_key(self, key_id: str) -> Json:
        return await self._request("GET", f"v1/api-keys/{identity(key_id)}")

    async def revoke_api_key(self, key_id: str) -> Json:
        return await self._request("DELETE", f"v1/api-keys/{identity(key_id)}")

    async def audit(self, after: int = 0, limit: int = 100, through: int | None = None) -> Json:
        return await self._request("GET", "v1/audit", params={"after": after, "limit": limit, **({"through": through} if through is not None else {})})

    async def profiles(self) -> list[Json]:
        return await self._request("GET", "v1/profiles")

    async def create(self, request: CreateSandbox | Json, key: str) -> Json:
        request = body(request)
        return check_created(await self._request("POST", "v1/sandboxes", request, key=key), request)

    async def sandbox(self, sandbox_id: str) -> Json:
        sid = identity(sandbox_id)
        return check_record(await self._request("GET", f"v1/sandboxes/{sid}"), sid)

    async def create_isolated_session(self, parent_id: str, request: CreateIsolatedSession | Json, key: str) -> Json:
        parent_id, request = identity(parent_id), body(request)
        parent, scope = await self.sandbox(parent_id), await self.sandbox_scope(parent_id)
        value = await self._request("POST", f"v1/sandboxes/{parent_id}/isolated-sessions", request, key=key)
        return check_isolated_created(value, request, parent, scope)

    async def sandbox_scope(self, sandbox_id: str) -> Json:
        sid = identity(sandbox_id)
        return check_scope(await self._request("GET", f"v1/sandboxes/{sid}/scope"), sid)

    async def isolated_sessions(self, parent_id: str, after: str | None = None, limit: int = 100) -> Json:
        params = {"limit": limit}
        if after is not None:
            params["after"] = identity(after)
        return await self._request("GET", f"v1/sandboxes/{identity(parent_id)}/isolated-sessions", params=params)

    def isolated_lease(self, parent_id: str, request: CreateIsolatedSession | Json) -> AsyncSandboxLease:
        return AsyncSandboxLease(self, request, parent_id=identity(parent_id))

    async def diagnostics(self, sandbox_id: str) -> Json:
        sid = identity(sandbox_id)
        value = await self._request("GET", f"v1/sandboxes/{sid}/diagnostics")
        check_record(value.get("sandbox"), sid)
        if value.get("runtime") is not None:
            check_record(value["runtime"], sid, "sandbox_id")
        return value

    async def network_policy(self, sandbox_id: str) -> Json:
        sid = identity(sandbox_id)
        return policy_state(await self._request("GET", f"v1/sandboxes/{sid}/network-policy"), sid)

    async def set_network_policy(self, sandbox_id: str, policy: Json, expected_revision: int, key: str) -> Json:
        sid = identity(sandbox_id)
        request = policy_request(expected_revision, policy)
        value = await self._request("PUT", f"v1/sandboxes/{sid}/network-policy", request, key=key)
        return policy_change(value, sid, request)

    async def list(self, after: str | None = None, limit: int = 100) -> Json:
        params = {"limit": limit}
        if after is not None:
            params["after"] = identity(after)
        return await self._request("GET", "v1/sandboxes", params=params)

    async def operation(self, operation_id: str) -> Json:
        oid = identity(operation_id)
        return check_record(await self._request("GET", f"v1/operations/{oid}"), oid)

    async def _change(self, sandbox_id: str, action: str, key: str) -> Json:
        sid = identity(sandbox_id)
        method, path = ("DELETE", f"v1/sandboxes/{sid}") if action == "terminate" else ("POST", f"v1/sandboxes/{sid}/{action}")
        return check_record(await self._request(method, path, key=key), sid, "resource_id")

    async def terminate(self, sandbox_id: str, key: str) -> Json:
        return await self._change(sandbox_id, "terminate", key)

    async def pause(self, sandbox_id: str, key: str) -> Json:
        return await self._change(sandbox_id, "pause", key)

    async def resume(self, sandbox_id: str, key: str) -> Json:
        return await self._change(sandbox_id, "resume", key)

    async def _wait_inner(self, rid: str, kind: str) -> Json:
        while True:
            value = check_record(await self._request("GET", f"v1/{kind}/{rid}"), rid)
            if value.get("state") in ("succeeded", "failed", "cancelled", "timed_out"):
                if kind == "operations" and value["state"] != "succeeded":
                    raise ApiError(409, value.get("error") or {"code": "invalid_state", "message": "operation did not succeed"})
                if kind == "executions" and value.get("cleanup") != "complete":
                    raise ProtocolError("terminal result has unconfirmed cleanup")
                return value
            await asyncio.sleep(0.1)

    async def _wait(self, rid: str, kind: str, timeout: float) -> Json:
        rid = identity(rid)
        try:
            return await asyncio.wait_for(self._wait_inner(rid, kind), timeout)
        except TimeoutError:
            raise WaitTimeout(rid) from None

    async def wait_operation(self, operation_id: str, timeout: float = 60) -> Json:
        return await self._wait(operation_id, "operations", timeout)

    async def start(self, sandbox_id: str, command: Command | Json, key: str) -> Json:
        sid = identity(sandbox_id)
        value = check_record(await self._request("POST", f"v1/sandboxes/{sid}/commands", body(command), key=key), sid, "sandbox_id")
        identity(value.get("id"))
        return value

    async def execution(self, execution_id: str) -> Json:
        eid = identity(execution_id)
        return check_record(await self._request("GET", f"v1/executions/{eid}"), eid)

    async def cancel(self, execution_id: str) -> Json:
        eid = identity(execution_id)
        return check_record(await self._request("POST", f"v1/executions/{eid}/cancel"), eid)

    async def wait_execution(self, execution_id: str, timeout: float = 60) -> Json:
        return await self._wait(execution_id, "executions", timeout)

    async def events(self, execution_id: str, after: int = 0) -> AsyncIterator[Json]:
        eid = identity(execution_id)
        if not isinstance(after, int) or not 0 <= after <= 2 ** 64 - 1:
            raise ProtocolError("invalid event cursor")
        headers = {"accept": "text/event-stream", "last-event-id": f"{eid}:{after}"}
        try:
            request = self._http.build_request("GET", f"v1/executions/{eid}/events", headers=headers)
            async with aclosing(await self._http.send(request, stream=True)) as response:
                if response.status_code != 200:
                    decode_json(response.status_code, await self._read(response))
                if not response.headers.get("content-type", "").startswith("text/event-stream"):
                    raise ProtocolError("expected an SSE response")
                decoder = SseDecoder(eid, after)
                async for chunk in response.aiter_bytes():
                    for event in decoder.feed(chunk):
                        yield event
                decoder.finish()
        except httpx.RequestError:
            raise TransportError() from None

    async def _collect(self, sid: str, eid: str, limit: int) -> RunOutput:
        collector = Collector(sid, eid, limit)
        for _ in range(3):
            async with aclosing(self.events(eid, collector.cursor)) as stream:
                try:
                    async for event in stream:
                        result = collector.accept(event)
                        if result is not None:
                            return result
                except TransportError:
                    await asyncio.sleep(0.1)
        raise ProtocolError("event stream ended before an explicit terminal result")

    async def run(self, sandbox_id: str, command: Command | Json, key: str | None = None) -> RunOutput:
        sid, command, key = identity(sandbox_id), body(command), key if key is not None else str(uuid4())
        try:
            execution = await self.start(sid, command, key)
        except asyncio.CancelledError as error:
            error.add_note(f"command acceptance may be uncertain; retry the same request with idempotency key {key}")
            raise
        except TransportError:
            raise UncertainRequest(key) from None
        except ApiError as error:
            if error.code == "backend_unavailable":
                raise UncertainRequest(key) from error
            raise
        eid = execution["id"]
        try:
            return await asyncio.wait_for(self._collect(sid, eid, command.get("max_output_bytes", 4 * 1024 * 1024)), command.get("timeout_seconds", 300) + 60)
        except TimeoutError:
            raise WaitTimeout(eid) from None
        except Error as error:
            raise ObservationError(eid, error) from error

    async def write_file(self, sandbox_id: str, path: str, data: bytes):
        if len(data) > MAX_FILE:
            raise ProtocolError("file exceeds 16 MiB transfer limit")
        await self._request("PUT", f"v1/sandboxes/{identity(sandbox_id)}/files", {"path": path, "data_base64": base64.b64encode(data).decode("ascii")})

    async def read_file(self, sandbox_id: str, path: str, max_bytes: int = MAX_FILE) -> bytes:
        if not 0 <= max_bytes <= MAX_FILE:
            raise ProtocolError("invalid file transfer limit")
        value = await self._request("GET", f"v1/sandboxes/{identity(sandbox_id)}/files", params={"path": path, "max_bytes": max_bytes})
        return binary(value.get("data_base64"), max_bytes)

    async def list_files(self, sandbox_id: str, path: str = ".") -> list[Json]:
        return await self._request("GET", f"v1/sandboxes/{identity(sandbox_id)}/directories", params={"path": path})

    async def remove_file(self, sandbox_id: str, path: str):
        await self._request("DELETE", f"v1/sandboxes/{identity(sandbox_id)}/files", params={"path": path})

    def lease(self, request: CreateSandbox | Json) -> AsyncSandboxLease:
        return AsyncSandboxLease(self, request)

    async def create_session(self, sandbox_id: str, request: SessionSpec | Json, key: str) -> Json:
        sid, request = identity(sandbox_id), body(request)
        return check_session(await self._request("POST", f"v1/sandboxes/{sid}/sessions", request, key=key), sandbox_id=sid, request=request)

    async def session(self, execution_id: str) -> Json:
        eid = identity(execution_id)
        return check_session(await self._request("GET", f"v1/sessions/{eid}"), execution_id=eid)

    async def list_sessions(self, sandbox_id: str | None = None, after: str | None = None, limit: int = 100) -> Json:
        params = {"limit": limit}
        if sandbox_id is not None:
            params["sandbox_id"] = identity(sandbox_id)
        if after is not None:
            params["after"] = identity(after)
        return await self._request("GET", "v1/sessions", params=params)

    async def session_control(self, execution_id: str, control: SessionControl | Json) -> Json:
        eid, request = identity(execution_id), body(control)
        sequence = request.get("sequence")
        try:
            return check_session_receipt(await self._request("POST", f"v1/sessions/{eid}/controls", request), eid, sequence)
        except asyncio.CancelledError as error:
            error.add_note(f"session {eid} control {sequence} may have been accepted; replay only the same sequence and content")
            raise
        except Error as error:
            raise SessionControlError(eid, sequence, error) from error

    async def session_control_status(self, execution_id: str, sequence: int) -> Json:
        eid = identity(execution_id)
        return check_session_receipt(await self._request("GET", f"v1/sessions/{eid}/controls/{sequence}"), eid, sequence)

    async def wait_session_control(self, execution_id: str, sequence: int, timeout: float = 30) -> Json:
        eid = identity(execution_id)
        async def poll():
            while True:
                value = await self.session_control_status(eid, sequence)
                if value["state"] != "pending":
                    return value
                await asyncio.sleep(.1)
        try:
            return await asyncio.wait_for(poll(), timeout)
        except asyncio.CancelledError as error:
            error.add_note(f"session {eid} control {sequence} was not cancelled; inspect its receipt")
            raise
        except TimeoutError:
            raise SessionControlError(eid, sequence, WaitTimeout(eid)) from None
        except Error as error:
            raise SessionControlError(eid, sequence, error) from error

    async def create_artifact(self, sandbox_id: str, request: CreateArtifact | Json, key: str) -> Json:
        sid, request = identity(sandbox_id), body(request)
        return check_artifact_created(await self._request("POST", f"v1/sandboxes/{sid}/artifacts", request, key=key), request, sid)

    async def artifact(self, artifact_id: str) -> Json:
        aid = identity(artifact_id)
        return check_record(await self._request("GET", f"v1/artifacts/{aid}"), aid)

    async def list_artifacts(self, sandbox_id: str | None = None, after: str | None = None, limit: int = 100) -> Json:
        params = {"limit": limit}
        if sandbox_id is not None:
            params["sandbox_id"] = identity(sandbox_id)
        if after is not None:
            params["after"] = identity(after)
        return await self._request("GET", "v1/artifacts", params=params)

    async def delete_artifact(self, artifact_id: str, key: str) -> Json:
        aid = identity(artifact_id)
        return check_record(await self._request("DELETE", f"v1/artifacts/{aid}", key=key), aid, "resource_id")

    async def artifact_bytes(self, artifact_id: str) -> bytes:
        aid = identity(artifact_id)
        metadata = await self.artifact(aid)
        if metadata.get("state") != "available" or metadata.get("desired_state") != "available":
            raise ApiError(409, {"code": "invalid_state", "message": "artifact content is not available"})
        async def fetch():
            try:
                request = self._http.build_request("GET", f"v1/artifacts/{aid}/content")
                async with aclosing(await self._http.send(request, stream=True)) as response:
                    raw = await self._read(response, maximum=MAX_FILE)
                    if response.status_code != 200:
                        decode_json(response.status_code, raw)
                    if not response.headers.get("content-type", "").startswith("application/octet-stream"):
                        raise ProtocolError("expected binary artifact content")
                return check_artifact_bytes(metadata, raw)
            except httpx.RequestError:
                raise TransportError() from None
        try:
            return await asyncio.wait_for(fetch(), 30)
        except TimeoutError:
            raise TransportError() from None

    async def capture_artifact(self, sandbox_id: str, request: CreateArtifact | Json, key: str | None = None) -> Json:
        key = key if key is not None else str(uuid4())
        try:
            created = await self.create_artifact(sandbox_id, request, key)
        except asyncio.CancelledError as error:
            error.add_note(f"artifact acceptance may be uncertain; retry the same request with idempotency key {key}")
            raise
        except TransportError:
            raise UncertainRequest(key) from None
        except ApiError as error:
            if error.code == "backend_unavailable":
                raise UncertainRequest(key) from error
            raise
        aid = created["artifact"]["id"]
        try:
            await self.wait_operation(created["operation"]["id"])
            artifact = await self.artifact(aid)
            if artifact.get("state") != "available":
                raise ProtocolError("artifact is not available after capture")
            return artifact
        except asyncio.CancelledError as error:
            error.add_note(f"artifact {aid} was not deleted; use explicit deletion to cancel retention")
            raise
        except Error as error:
            raise ArtifactError(aid, error) from error


class AsyncSandboxLease:
    def __init__(self, client: AsyncClient, request: CreateSandbox | CreateIsolatedSession | Json, *, parent_id: str | None = None):
        self.client, self.request = client, request
        self.parent_id = parent_id
        self._id: str | None = None
        self._delete_key = str(uuid4())
        self._closed = False

    @property
    def id(self) -> str:
        if self._id is None:
            raise ProtocolError("lease has not been entered")
        return self._id

    async def __aenter__(self):
        if self._id is not None:
            raise ProtocolError("lease cannot be entered twice")
        key = str(uuid4())
        try:
            created = await self.client.create(self.request, key) if self.parent_id is None else await self.client.create_isolated_session(self.parent_id, self.request, key)
        except asyncio.CancelledError as error:
            error.add_note(f"create acceptance may be uncertain; retry the same request with idempotency key {key}")
            raise
        except TransportError:
            raise UncertainRequest(key) from None
        except ApiError as error:
            if error.code == "backend_unavailable":
                raise UncertainRequest(key) from error
            raise
        self._id = created["sandbox"]["id"]
        try:
            await self.client.wait_operation(created["operation"]["id"])
            if (await self.client.sandbox(self.id)).get("state") != "running":
                raise ProtocolError("sandbox is not running after create")
            return self
        except BaseException as error:
            await self.__aexit__(type(error), error, error.__traceback__)
            raise

    async def close(self):
        if self._closed or self._id is None:
            return
        operation = await self.client.terminate(self.id, self._delete_key)
        await self.client.wait_operation(operation["id"])
        sandbox = await self.client.sandbox(self.id)
        if sandbox.get("cleanup") != "complete" or sandbox.get("state") not in ("terminated", "failed"):
            raise ProtocolError("sandbox cleanup is not confirmed")
        self._closed = True

    async def __aexit__(self, exc_type, exc, traceback):
        task = asyncio.create_task(self.close())
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            await task
            raise
        except BaseException as error:
            raise CleanupError(self.id, exc, error) from error
