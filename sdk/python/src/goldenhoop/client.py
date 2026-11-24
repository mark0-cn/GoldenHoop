"""Synchronous API. JSON responses preserve all server fields as dictionaries."""
from __future__ import annotations

import base64
import time
from collections.abc import Iterator
from contextlib import closing
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
from ._code_sync import CodeClientMixin
from ._protocol import CreateIsolatedSession
from ._isolated import check_scope, check_isolated_created


class Client(CodeClientMixin):
    def __init__(self, base_url: str, token: str):
        self._http = httpx.Client(base_url=endpoint(base_url, token),
                                  headers={"authorization": "Bearer " + token},
                                  trust_env=False, follow_redirects=False,
                                  timeout=httpx.Timeout(30, connect=5, pool=5))

    def close(self):
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _read(self, response: httpx.Response, timeout: float = 30, maximum: int = MAX_BODY) -> bytes:
        maximum = maximum if 200 <= response.status_code < 300 else 64 * 1024
        deadline = time.monotonic() + timeout
        data = bytearray()
        for chunk in response.iter_bytes():
            data.extend(chunk)
            if len(data) > maximum:
                raise ProtocolError("response exceeds size limit")
            if time.monotonic() > deadline:
                raise TransportError()
        return bytes(data)

    def _request(self, method: str, path: str, value=None, *, key=None, params=None, timeout=30):
        headers = key_headers(key)
        for attempt in range(3 if key else 1):
            try:
                request = self._http.build_request(method, path, json=value, params=params,
                                                   headers=headers, timeout=max(0.001, timeout))
                with closing(self._http.send(request, stream=True)) as response:
                    return decode_json(response.status_code, self._read(response, timeout))
            except httpx.RequestError:
                if key and attempt < 2:
                    time.sleep(0.1 * 2 ** attempt)
                else:
                    raise TransportError() from None

    def profiles(self) -> list[Json]:
        return self._request("GET", "v1/profiles")

    def create(self, request: CreateSandbox | Json, key: str) -> Json:
        request = body(request)
        return check_created(self._request("POST", "v1/sandboxes", request, key=key), request)

    def sandbox(self, sandbox_id: str) -> Json:
        sid = identity(sandbox_id)
        return check_record(self._request("GET", f"v1/sandboxes/{sid}"), sid)

    def create_isolated_session(self, parent_id: str, request: CreateIsolatedSession | Json, key: str) -> Json:
        parent_id, request = identity(parent_id), body(request)
        parent, scope = self.sandbox(parent_id), self.sandbox_scope(parent_id)
        return check_isolated_created(self._request("POST", f"v1/sandboxes/{parent_id}/isolated-sessions", request, key=key), request, parent, scope)

    def sandbox_scope(self, sandbox_id: str) -> Json:
        sid = identity(sandbox_id)
        return check_scope(self._request("GET", f"v1/sandboxes/{sid}/scope"), sid)

    def isolated_sessions(self, parent_id: str, after: str | None = None, limit: int = 100) -> Json:
        params = {"limit": limit}
        if after is not None:
            params["after"] = identity(after)
        return self._request("GET", f"v1/sandboxes/{identity(parent_id)}/isolated-sessions", params=params)

    def isolated_lease(self, parent_id: str, request: CreateIsolatedSession | Json) -> SandboxLease:
        return SandboxLease(self, request, parent_id=identity(parent_id))

    def diagnostics(self, sandbox_id: str) -> Json:
        sid = identity(sandbox_id)
        value = self._request("GET", f"v1/sandboxes/{sid}/diagnostics")
        check_record(value.get("sandbox"), sid)
        if value.get("runtime") is not None:
            check_record(value["runtime"], sid, "sandbox_id")
        return value

    def list(self, after: str | None = None, limit: int = 100) -> Json:
        params = {"limit": limit}
        if after is not None:
            params["after"] = identity(after)
        return self._request("GET", "v1/sandboxes", params=params)

    def operation(self, operation_id: str) -> Json:
        oid = identity(operation_id)
        return check_record(self._request("GET", f"v1/operations/{oid}"), oid)

    def _change(self, sandbox_id: str, action: str, key: str) -> Json:
        sid = identity(sandbox_id)
        method, path = ("DELETE", f"v1/sandboxes/{sid}") if action == "terminate" else ("POST", f"v1/sandboxes/{sid}/{action}")
        return check_record(self._request(method, path, key=key), sid, "resource_id")

    def terminate(self, sandbox_id: str, key: str) -> Json:
        return self._change(sandbox_id, "terminate", key)

    def pause(self, sandbox_id: str, key: str) -> Json:
        return self._change(sandbox_id, "pause", key)

    def resume(self, sandbox_id: str, key: str) -> Json:
        return self._change(sandbox_id, "resume", key)

    def _wait(self, rid: str, kind: str, timeout: float) -> Json:
        rid = identity(rid)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise WaitTimeout(rid)
            try:
                value = check_record(self._request("GET", f"v1/{kind}/{rid}", timeout=min(30, remaining)), rid)
            except TransportError:
                if time.monotonic() >= deadline:
                    raise WaitTimeout(rid) from None
                raise
            if value.get("state") in ("succeeded", "failed", "cancelled", "timed_out"):
                if kind == "operations" and value["state"] != "succeeded":
                    raise ApiError(409, value.get("error") or {"code": "invalid_state", "message": "operation did not succeed"})
                if kind == "executions" and value.get("cleanup") != "complete":
                    raise ProtocolError("terminal result has unconfirmed cleanup")
                return value
            time.sleep(min(0.1, max(0, deadline - time.monotonic())))

    def wait_operation(self, operation_id: str, timeout: float = 60) -> Json:
        return self._wait(operation_id, "operations", timeout)

    def start(self, sandbox_id: str, command: Command | Json, key: str) -> Json:
        sid = identity(sandbox_id)
        value = check_record(self._request("POST", f"v1/sandboxes/{sid}/commands", body(command), key=key), sid, "sandbox_id")
        identity(value.get("id"))
        return value

    def execution(self, execution_id: str) -> Json:
        eid = identity(execution_id)
        return check_record(self._request("GET", f"v1/executions/{eid}"), eid)

    def cancel(self, execution_id: str) -> Json:
        eid = identity(execution_id)
        return check_record(self._request("POST", f"v1/executions/{eid}/cancel"), eid)

    def wait_execution(self, execution_id: str, timeout: float = 60) -> Json:
        return self._wait(execution_id, "executions", timeout)

    def events(self, execution_id: str, after: int = 0, *, _deadline: float | None = None) -> Iterator[Json]:
        eid = identity(execution_id)
        if not isinstance(after, int) or not 0 <= after <= 2 ** 64 - 1:
            raise ProtocolError("invalid event cursor")
        headers = {"accept": "text/event-stream", "last-event-id": f"{eid}:{after}"}
        try:
            remaining = max(0.001, min(30, _deadline - time.monotonic())) if _deadline is not None else 30
            request = self._http.build_request("GET", f"v1/executions/{eid}/events", headers=headers, timeout=remaining)
            with closing(self._http.send(request, stream=True)) as response:
                if response.status_code != 200:
                    decode_json(response.status_code, self._read(response))
                if not response.headers.get("content-type", "").startswith("text/event-stream"):
                    raise ProtocolError("expected an SSE response")
                decoder = SseDecoder(eid, after)
                for chunk in response.iter_bytes():
                    if _deadline is not None and time.monotonic() > _deadline:
                        raise WaitTimeout(eid)
                    yield from decoder.feed(chunk)
                decoder.finish()
        except httpx.RequestError:
            raise TransportError() from None

    def run(self, sandbox_id: str, command: Command | Json, key: str | None = None) -> RunOutput:
        sid, command, key = identity(sandbox_id), body(command), key if key is not None else str(uuid4())
        try:
            execution = self.start(sid, command, key)
        except TransportError:
            raise UncertainRequest(key) from None
        except ApiError as error:
            if error.code == "backend_unavailable":
                raise UncertainRequest(key) from error
            raise
        eid = execution["id"]
        collector = Collector(sid, eid, command.get("max_output_bytes", 4 * 1024 * 1024))
        deadline = time.monotonic() + command.get("timeout_seconds", 300) + 60
        try:
            for _ in range(3):
                if time.monotonic() >= deadline:
                    raise WaitTimeout(eid)
                stream = self.events(eid, collector.cursor, _deadline=deadline)
                try:
                    for event in stream:
                        if time.monotonic() > deadline:
                            raise WaitTimeout(eid)
                        result = collector.accept(event)
                        if result is not None:
                            return result
                except TransportError:
                    time.sleep(0.1)
                finally:
                    stream.close()
            raise ProtocolError("event stream ended before an explicit terminal result")
        except WaitTimeout:
            raise
        except Error as error:
            raise ObservationError(eid, error) from error

    def write_file(self, sandbox_id: str, path: str, data: bytes):
        if len(data) > MAX_FILE:
            raise ProtocolError("file exceeds 16 MiB transfer limit")
        self._request("PUT", f"v1/sandboxes/{identity(sandbox_id)}/files", {"path": path, "data_base64": base64.b64encode(data).decode("ascii")})

    def read_file(self, sandbox_id: str, path: str, max_bytes: int = MAX_FILE) -> bytes:
        if not 0 <= max_bytes <= MAX_FILE:
            raise ProtocolError("invalid file transfer limit")
        value = self._request("GET", f"v1/sandboxes/{identity(sandbox_id)}/files", params={"path": path, "max_bytes": max_bytes})
        return binary(value.get("data_base64"), max_bytes)

    def list_files(self, sandbox_id: str, path: str = ".") -> list[Json]:
        return self._request("GET", f"v1/sandboxes/{identity(sandbox_id)}/directories", params={"path": path})

    def remove_file(self, sandbox_id: str, path: str):
        self._request("DELETE", f"v1/sandboxes/{identity(sandbox_id)}/files", params={"path": path})

    def lease(self, request: CreateSandbox | Json) -> SandboxLease:
        return SandboxLease(self, request)

    def create_session(self, sandbox_id: str, request: SessionSpec | Json, key: str) -> Json:
        sid, request = identity(sandbox_id), body(request)
        return check_session(self._request("POST", f"v1/sandboxes/{sid}/sessions", request, key=key), sandbox_id=sid, request=request)

    def session(self, execution_id: str) -> Json:
        eid = identity(execution_id)
        return check_session(self._request("GET", f"v1/sessions/{eid}"), execution_id=eid)

    def list_sessions(self, sandbox_id: str | None = None, after: str | None = None, limit: int = 100) -> Json:
        params = {"limit": limit}
        if sandbox_id is not None:
            params["sandbox_id"] = identity(sandbox_id)
        if after is not None:
            params["after"] = identity(after)
        return self._request("GET", "v1/sessions", params=params)

    def session_control(self, execution_id: str, control: SessionControl | Json) -> Json:
        eid, request = identity(execution_id), body(control)
        sequence = request.get("sequence")
        try:
            return check_session_receipt(self._request("POST", f"v1/sessions/{eid}/controls", request), eid, sequence)
        except Error as error:
            raise SessionControlError(eid, sequence, error) from error

    def session_control_status(self, execution_id: str, sequence: int) -> Json:
        eid = identity(execution_id)
        return check_session_receipt(self._request("GET", f"v1/sessions/{eid}/controls/{sequence}"), eid, sequence)

    def wait_session_control(self, execution_id: str, sequence: int, timeout: float = 30) -> Json:
        eid, deadline = identity(execution_id), time.monotonic() + timeout
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise WaitTimeout(eid)
                value = check_session_receipt(self._request("GET", f"v1/sessions/{eid}/controls/{sequence}", timeout=min(30, remaining)), eid, sequence)
                if value["state"] != "pending":
                    return value
                time.sleep(min(.1, max(0, deadline - time.monotonic())))
        except Error as error:
            raise SessionControlError(eid, sequence, error) from error

    def create_artifact(self, sandbox_id: str, request: CreateArtifact | Json, key: str) -> Json:
        sid, request = identity(sandbox_id), body(request)
        return check_artifact_created(self._request("POST", f"v1/sandboxes/{sid}/artifacts", request, key=key), request, sid)

    def artifact(self, artifact_id: str) -> Json:
        aid = identity(artifact_id)
        return check_record(self._request("GET", f"v1/artifacts/{aid}"), aid)

    def list_artifacts(self, sandbox_id: str | None = None, after: str | None = None, limit: int = 100) -> Json:
        params = {"limit": limit}
        if sandbox_id is not None:
            params["sandbox_id"] = identity(sandbox_id)
        if after is not None:
            params["after"] = identity(after)
        return self._request("GET", "v1/artifacts", params=params)

    def delete_artifact(self, artifact_id: str, key: str) -> Json:
        aid = identity(artifact_id)
        return check_record(self._request("DELETE", f"v1/artifacts/{aid}", key=key), aid, "resource_id")

    def artifact_bytes(self, artifact_id: str) -> bytes:
        aid = identity(artifact_id)
        metadata = self.artifact(aid)
        if metadata.get("state") != "available" or metadata.get("desired_state") != "available":
            raise ApiError(409, {"code": "invalid_state", "message": "artifact content is not available"})
        try:
            request = self._http.build_request("GET", f"v1/artifacts/{aid}/content")
            with closing(self._http.send(request, stream=True)) as response:
                raw = self._read(response, maximum=MAX_FILE)
                if response.status_code != 200:
                    decode_json(response.status_code, raw)
                if not response.headers.get("content-type", "").startswith("application/octet-stream"):
                    raise ProtocolError("expected binary artifact content")
        except httpx.RequestError:
            raise TransportError() from None
        return check_artifact_bytes(metadata, raw)

    def capture_artifact(self, sandbox_id: str, request: CreateArtifact | Json, key: str | None = None) -> Json:
        key = key if key is not None else str(uuid4())
        try:
            created = self.create_artifact(sandbox_id, request, key)
        except TransportError:
            raise UncertainRequest(key) from None
        except ApiError as error:
            if error.code == "backend_unavailable":
                raise UncertainRequest(key) from error
            raise
        aid = created["artifact"]["id"]
        try:
            self.wait_operation(created["operation"]["id"])
            artifact = self.artifact(aid)
            if artifact.get("state") != "available":
                raise ProtocolError("artifact is not available after capture")
            return artifact
        except Error as error:
            raise ArtifactError(aid, error) from error


class SandboxLease:
    def __init__(self, client: Client, request: CreateSandbox | CreateIsolatedSession | Json, *, parent_id: str | None = None):
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

    def __enter__(self):
        if self._id is not None:
            raise ProtocolError("lease cannot be entered twice")
        key = str(uuid4())
        try:
            created = self.client.create(self.request, key) if self.parent_id is None else self.client.create_isolated_session(self.parent_id, self.request, key)
        except TransportError:
            raise UncertainRequest(key) from None
        except ApiError as error:
            if error.code == "backend_unavailable":
                raise UncertainRequest(key) from error
            raise
        self._id = created["sandbox"]["id"]
        try:
            self.client.wait_operation(created["operation"]["id"])
            if self.client.sandbox(self.id).get("state") != "running":
                raise ProtocolError("sandbox is not running after create")
            return self
        except BaseException as error:
            self.__exit__(type(error), error, error.__traceback__)
            raise

    def close(self):
        if self._closed or self._id is None:
            return
        operation = self.client.terminate(self.id, self._delete_key)
        self.client.wait_operation(operation["id"])
        sandbox = self.client.sandbox(self.id)
        if sandbox.get("cleanup") != "complete" or sandbox.get("state") not in ("terminated", "failed"):
            raise ProtocolError("sandbox cleanup is not confirmed")
        self._closed = True

    def __exit__(self, exc_type, exc, traceback):
        try:
            self.close()
        except BaseException as error:
            raise CleanupError(self.id, exc, error) from error
