"""Synchronous code-context operations, shared by the public Client."""
from __future__ import annotations
import time
from contextlib import closing
from uuid import uuid4
import httpx
from ._protocol import ApiError, CodeContextSpec, CodeRunSpec, CodeRunOutput, CodeObservationError, Error, Json, ProtocolError, TransportError, UncertainRequest, WaitTimeout, decode_json, identity
from ._code import CodeCollector, check_context, check_run, collected, context_decoder, context_spec, run_spec


class CodeClientMixin:
    def create_code_context(self, sandbox_id: str, spec: CodeContextSpec | Json, key: str) -> Json:
        sid, spec = identity(sandbox_id), context_spec(spec)
        return check_context(self._request("POST", f"v1/sandboxes/{sid}/code-contexts", spec, key=key), sandbox_id=sid, spec=spec)

    def code_context(self, context_id: str) -> Json:
        cid = identity(context_id)
        return check_context(self._request("GET", f"v1/code-contexts/{cid}"), cid)

    def list_code_contexts(self, sandbox_id: str | None = None, after: str | None = None, limit: int = 100) -> Json:
        params = {"limit": limit}
        if sandbox_id is not None:
            params["sandbox_id"] = identity(sandbox_id)
        if after is not None:
            params["after"] = identity(after)
        value = self._request("GET", "v1/code-contexts", params=params)
        if not isinstance(value, dict) or not isinstance(value.get("items"), list):
            raise ProtocolError("invalid context page")
        for item in value["items"]:
            check_context(item, sandbox_id=params.get("sandbox_id"))
        return value

    def close_code_context(self, context_id: str, key: str) -> Json:
        cid = identity(context_id)
        value = check_context(self._request("DELETE", f"v1/code-contexts/{cid}", key=key), cid)
        if value["desired_state"] != "closed":
            raise ProtocolError("context close intent was not accepted")
        return value

    def _wait_code_context(self, context_id: str, timeout: float, ready: bool) -> Json:
        cid, deadline = identity(context_id), time.monotonic()+timeout
        while True:
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                raise WaitTimeout(cid)
            try:
                value = check_context(self._request("GET", f"v1/code-contexts/{cid}", timeout=min(30, remaining)), cid)
            except TransportError:
                if time.monotonic() >= deadline:
                    raise WaitTimeout(cid) from None
                raise
            if ready:
                if value["desired_state"] != "open" or value["state"] in {"closing", "closed", "failed", "unknown"}:
                    raise ApiError(409, {"code": "invalid_state", "message": value.get("reason") or "code context is unavailable"})
                if value["state"] == "ready" and value["cleanup"] == "pending" and value.get("ready_at"):
                    return value
            elif collected(value):
                return value
            time.sleep(min(.1, max(0, deadline-time.monotonic())))

    def wait_code_context_ready(self, context_id: str, timeout: float = 60) -> Json:
        return self._wait_code_context(context_id, timeout, True)

    def wait_code_context_closed(self, context_id: str, timeout: float = 60) -> Json:
        return self._wait_code_context(context_id, timeout, False)

    def start_code(self, context_id: str, spec: CodeRunSpec | Json, key: str) -> Json:
        cid, spec = identity(context_id), run_spec(spec)
        return check_run(self._request("POST", f"v1/code-contexts/{cid}/runs", spec, key=key), context_id=cid)

    def code_run(self, run_id: str) -> Json:
        rid = identity(run_id)
        return check_run(self._request("GET", f"v1/code-runs/{rid}"), rid)

    def list_code_runs(self, context_id: str, after: str | None = None, limit: int = 100) -> Json:
        cid, params = identity(context_id), {"limit": limit}
        if after is not None:
            params["after"] = identity(after)
        value = self._request("GET", f"v1/code-contexts/{cid}/runs", params=params)
        if not isinstance(value, dict) or not isinstance(value.get("items"), list):
            raise ProtocolError("invalid code-run page")
        for item in value["items"]:
            check_run(item, context_id=cid)
        return value

    def cancel_code_run(self, run_id: str) -> Json:
        """Persist cancellation of this interpreter context and its queued runs."""
        rid = identity(run_id)
        return check_run(self._request("POST", f"v1/code-runs/{rid}/cancel"), rid)

    def code_context_events(self, context_id: str, after: int = 0, *, _deadline: float | None = None):
        cid = identity(context_id)
        decoder = context_decoder(cid, after)
        if _deadline is None:
            initial = self.code_context(cid)
        else:
            remaining = _deadline-time.monotonic()
            if remaining <= 0:
                raise WaitTimeout(cid)
            initial = check_context(self._request("GET", f"v1/code-contexts/{cid}", timeout=min(30,remaining)),cid)
        try:
            remaining = min(30, max(.001, _deadline-time.monotonic())) if _deadline is not None else 30
            request = self._http.build_request("GET", f"v1/code-contexts/{cid}/events", headers={"accept": "text/event-stream", "last-event-id": f"{cid}:{after}"}, timeout=remaining)
            with closing(self._http.send(request, stream=True)) as response:
                if response.status_code != 200:
                    decode_json(response.status_code, self._read(response))
                if not response.headers.get("content-type", "").startswith("text/event-stream"):
                    raise ProtocolError("expected context SSE response")
                for chunk in response.iter_bytes():
                    if _deadline is not None and time.monotonic() >= _deadline:
                        raise WaitTimeout(cid)
                    for event in decoder.feed(chunk):
                        if event.get("kind") == "closed":
                            value = check_context(event.get("data"), cid, initial["sandbox_id"])
                            if not collected(value):
                                raise ProtocolError("context closure lacks collection")
                            yield event
                            return
                        yield event
                decoder.finish()
                if not collected(initial):
                    raise TransportError()
        except httpx.RequestError:
            raise TransportError() from None

    def run_code(self, context_id: str, spec: CodeRunSpec | Json, key: str | None = None) -> CodeRunOutput:
        cid, spec, key = identity(context_id), run_spec(spec), key if key is not None else str(uuid4())
        try:
            accepted = self.start_code(cid, spec, key)
        except TransportError:
            raise UncertainRequest(key) from None
        except ApiError as error:
            if error.code == "backend_unavailable":
                raise UncertainRequest(key) from error
            raise
        rid = accepted["id"]
        collector = CodeCollector(accepted, spec.get("max_output_bytes", 1024*1024))
        deadline = time.monotonic()+spec.get("timeout_seconds", 60)+60
        try:
            for _ in range(3):
                if time.monotonic() >= deadline:
                    raise WaitTimeout(rid)
                with closing(self.code_context_events(cid, collector.cursor, _deadline=deadline)) as events:
                    try:
                        for event in events:
                            result = collector.accept(event)
                            if result is not None:
                                if result.run["state"] in {"cancelled", "timed_out"} and not collected(self.code_context(cid)):
                                    raise ProtocolError("code cancellation lacks context collection")
                                return result
                    except TransportError:
                        time.sleep(.1)
            raise ProtocolError("context stream ended before matching code completion")
        except WaitTimeout:
            raise WaitTimeout(rid) from None
        except Error as error:
            raise CodeObservationError(rid, error) from error
