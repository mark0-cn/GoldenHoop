"""Shared context validation and bounded result collection."""
from __future__ import annotations
import json
from uuid import UUID
from typing import Any
from ._protocol import CodeContextSpec, CodeRunSpec, CodeRunOutput, Json, ProtocolError, body, check_record, identity

CONTEXT_FRAME = 2*1024*1024+16384


def nonzero(value):
    if not UUID(identity(value)).int:
        raise ProtocolError("nil code resource identity")


def context_spec(value: CodeContextSpec | Json) -> Json:
    value = body(value)
    cwd = value.get("cwd", "/workspace")
    language = value.get("language", "python")
    if (not isinstance(language, str) or language not in {"python", "java", "go", "typescript", "bash", "javascript"} or not isinstance(cwd, str)
            or not 1 <= len(cwd.encode()) <= 4096 or "\0" in cwd or "\\" in cwd):
        raise ProtocolError("invalid code-context language or working directory")
    return value


def run_spec(value: CodeRunSpec | Json) -> Json:
    value = body(value)
    code, timeout, limit = value.get("code"), value.get("timeout_seconds", 60), value.get("max_output_bytes", 1024*1024)
    if (not isinstance(code, str) or not 1 <= len(code.encode()) <= 65536 or "\0" in code
            or type(timeout) is not int or not 1 <= timeout <= 3600
            or type(limit) is not int or not 1 <= limit <= 16*1024*1024):
        raise ProtocolError("invalid code source, deadline or output limit")
    return value


def check_context(value: Any, context_id: str | None = None, sandbox_id: str | None = None, spec: Json | None = None) -> Json:
    if not isinstance(value, dict):
        raise ProtocolError("invalid code-context record")
    nonzero(value.get("id"))
    nonzero(value.get("sandbox_id"))
    if context_id is not None:
        check_record(value, context_id)
    if sandbox_id is not None:
        check_record(value, sandbox_id, "sandbox_id")
    if (value.get("state") not in {"starting", "ready", "closing", "closed", "failed", "unknown"}
            or value.get("desired_state") not in {"open", "closed"}
            or value.get("cleanup") not in {"pending", "complete", "unknown"}
            or not isinstance(value.get("spec"), dict)):
        raise ProtocolError("invalid code-context state")
    if spec is not None:
        for field, expected in {"language": spec.get("language", "python"), "cwd": spec.get("cwd", "/workspace")}.items():
            if value["spec"].get(field) != expected:
                raise ProtocolError("code-context specification mismatch")
    return value


def collected(value: Json) -> bool:
    return value.get("cleanup") == "complete" and value.get("state") in {"closed", "failed"} and isinstance(value.get("finished_at"), str)


def check_run(value: Any, run_id: str | None = None, context_id: str | None = None) -> Json:
    if not isinstance(value, dict):
        raise ProtocolError("invalid code-run record")
    nonzero(value.get("id"))
    nonzero(value.get("context_id"))
    if run_id is not None:
        check_record(value, run_id)
    if context_id is not None:
        check_record(value, context_id, "context_id")
    if (value.get("state") not in {"pending", "running", "kernel_succeeded", "kernel_failed", "cancelled", "timed_out", "rejected", "unknown"}
            or type(value.get("events_after")) is not int or not 0 <= value["events_after"] <= 2**63-1):
        raise ProtocolError("invalid code-run state or acceptance cursor")
    return value


def context_decoder(context: str, after: int):
    from ._protocol import SseDecoder
    if type(after) is not int or not 0 <= after <= 2**63-1:
        raise ProtocolError("invalid context event cursor")
    return SseDecoder(context, after, event_type="code_context", identity_field="context_id", maximum=CONTEXT_FRAME)


class CodeCollector:
    def __init__(self, accepted: Json, maximum: int):
        self.accepted, self.maximum, self.cursor, self.used = accepted, maximum, accepted["events_after"], 0
        self.stdout: list[str] = []
        self.stderr: list[str] = []
        self.results: list[Json] = []
        self.displays: list[Json] = []
        self.errors: list[Json] = []

    def accept(self, event: Json) -> CodeRunOutput | None:
        self.cursor = event["sequence"]
        if event.get("run_id") != self.accepted["id"]:
            return None
        kind, data = event.get("kind"), event.get("data")
        if not isinstance(data, dict):
            raise ProtocolError("invalid code event data")
        if kind in {"stdout", "stderr", "result", "display", "kernel_error"}:
            if type(data.get("late")) is not bool:
                raise ProtocolError("code output lacks provenance")
            if data["late"]:
                return None
            self.used += len(json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode())
            if self.used > self.maximum:
                raise ProtocolError("code output exceeds requested budget")
            content = data.get("content")
            if not isinstance(content, dict):
                raise ProtocolError("invalid kernel output content")
            if kind in {"stdout", "stderr"}:
                if not isinstance(content.get("text"), str):
                    raise ProtocolError("invalid kernel text output")
                (self.stdout if kind == "stdout" else self.stderr).append(content["text"])
            else:
                {"result": self.results, "display": self.displays, "kernel_error": self.errors}[kind].append(content)
        elif kind == "run_completed":
            value = check_run(data, self.accepted["id"], self.accepted["context_id"])
            if value["events_after"] != self.accepted["events_after"] or not isinstance(value.get("finished_at"), str):
                raise ProtocolError("code completion lacks matching cursor/timestamps")
            state = value["state"]
            if state in {"kernel_succeeded", "kernel_failed"}:
                if not isinstance(value.get("started_at"), str) or value.get("kernel_status") != ("ok" if state == "kernel_succeeded" else "error"):
                    raise ProtocolError("code completion lacks matching kernel observations")
            elif state == "unknown":
                raise ProtocolError("kernel execution outcome is unknown")
            elif state not in {"cancelled", "timed_out", "rejected"} or value.get("kernel_status") is not None or state == "rejected" and value.get("started_at") is not None:
                raise ProtocolError("code result is not an explicit completion")
            return CodeRunOutput(value, "".join(self.stdout), "".join(self.stderr), self.results, self.displays, self.errors)
        return None
