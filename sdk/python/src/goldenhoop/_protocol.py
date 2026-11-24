"""Shared protocol validation; no network or resource management here."""
from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

Json = dict[str, Any]
TERMINAL = frozenset(("succeeded", "failed", "cancelled", "timed_out"))
MAX_BODY = 24 * 1024 * 1024
MAX_FILE = 16 * 1024 * 1024
MAX_FRAME = 2 * 1024 * 1024


class Error(Exception):
    """Base error; neither waiting nor observation failures cancel work."""


class ProtocolError(Error):
    pass


class TransportError(Error):
    def __init__(self):
        super().__init__("API transport is unavailable")


class ApiError(Error):
    def __init__(self, status: int, payload: Json):
        self.status, self.code, self.retryable = status, payload["code"], payload.get("retryable", False)
        self.payload = payload
        super().__init__(f"HTTP {status}: {self.code}: {payload['message']}")


class WaitTimeout(Error):
    def __init__(self, identity: str):
        self.identity = identity
        super().__init__(f"wait deadline exceeded for {identity}; operation was not cancelled")


class UncertainRequest(Error):
    def __init__(self, key: str):
        self.idempotency_key = key
        super().__init__(f"request outcome is unknown; retry the same request with idempotency key {key}")


class ObservationError(Error):
    def __init__(self, execution_id: str, error: Error):
        self.execution_id, self.error = execution_id, error
        super().__init__(f"execution {execution_id} observation failed: {error}")


class ArtifactError(Error):
    def __init__(self, artifact_id: str, error: Error):
        self.artifact_id, self.error = artifact_id, error
        super().__init__(f"artifact {artifact_id} operation failed: {error}")


class CleanupError(Error):
    def __init__(self, sandbox_id: str, original: BaseException | None, error: BaseException):
        self.sandbox_id, self.original, self.error = sandbox_id, original, error
        super().__init__(f"sandbox {sandbox_id} cleanup is unconfirmed: {error}")


@dataclass(frozen=True)
class CreateSandbox:
    profile: str
    image: str
    ttl_seconds: int = 1800
    resources: Json = field(default_factory=lambda: {"cpu_millis": 1000, "memory_bytes": 1073741824, "pids": 256})
    required_capabilities: list[str] = field(default_factory=list)
    network: Json = field(default_factory=lambda: {"default_action": "deny", "rules": []})
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Command:
    argv: list[str]
    cwd: str = "/workspace"
    env: dict[str, str] = field(default_factory=dict)
    timeout_seconds: int = 300
    max_output_bytes: int = 4 * 1024 * 1024


@dataclass(frozen=True)
class CreateArtifact:
    path: str
    name: str = "artifact.bin"


@dataclass(frozen=True)
class RunOutput:
    execution: Json
    stdout: bytes
    stderr: bytes


def body(value: CreateSandbox | Command | CreateArtifact | Json) -> Json:
    return asdict(value) if isinstance(value, (CreateSandbox, Command, CreateArtifact)) else dict(value)


def check_artifact_created(value: Any, request: Json, sid: str) -> Json:
    try:
        artifact = value["artifact"]
        identity(artifact["id"])
        if (artifact["sandbox_id"] != sid or artifact["name"] != request.get("name", "artifact.bin")
                or artifact["source_path"] != request["path"] or value["operation"]["resource_id"] != artifact["id"]):
            raise ProtocolError("artifact create response identity mismatch")
    except (KeyError, TypeError):
        raise ProtocolError("invalid artifact create response") from None
    return value


def check_artifact_bytes(metadata: Json, raw: bytes) -> bytes:
    if len(raw) > MAX_FILE or metadata.get("size_bytes") != len(raw) or metadata.get("sha256") != hashlib.sha256(raw).hexdigest():
        raise ProtocolError("artifact content integrity check failed")
    return raw


def identity(value: str) -> str:
    try:
        return str(UUID(str(value)))
    except (ValueError, AttributeError, TypeError):
        raise ProtocolError("invalid resource UUID") from None


def endpoint(base: str, token: str) -> str:
    try:
        parsed = urlsplit(base)
        parsed.port
    except ValueError:
        raise ProtocolError("invalid endpoint") from None
    host = parsed.hostname or ""
    try:
        loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    if (parsed.scheme not in ("http", "https") or not parsed.hostname
            or parsed.scheme == "http" and not loopback
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment):
        raise ProtocolError("endpoint requires HTTPS, or HTTP on loopback, without embedded credentials/query")
    if not 32 <= len(token) <= 512 or any(not 33 <= ord(c) <= 126 for c in token):
        raise ProtocolError("invalid API token format")
    return base.rstrip("/") + "/"


def key_headers(key: str | None) -> dict[str, str]:
    if key is None:
        return {}
    if not 1 <= len(key) <= 128 or any(not 33 <= ord(c) <= 126 for c in key):
        raise ProtocolError("invalid idempotency key")
    return {"idempotency-key": key}


def decode_json(status: int, raw: bytes) -> Any:
    try:
        value = json.loads(raw) if raw else None
    except (ValueError, UnicodeDecodeError):
        raise ProtocolError("invalid JSON response") from None
    if not 200 <= status < 300:
        if not isinstance(value, dict) or not isinstance(value.get("code"), str) or not isinstance(value.get("message"), str):
            raise ProtocolError("invalid API error envelope")
        raise ApiError(status, value)
    return value


def check_record(record: Any, expected: str, field: str = "id") -> Json:
    if not isinstance(record, dict) or record.get(field) != expected:
        raise ProtocolError("response identity mismatch")
    return record


def check_created(value: Any, request: Json) -> Json:
    try:
        sandbox = value["sandbox"]
        if (identity(sandbox["id"]) != value["operation"]["resource_id"]
                or sandbox["profile"] != request["profile"] or sandbox["image"] != request["image"]):
            raise ProtocolError("create response identity mismatch")
    except (KeyError, TypeError):
        raise ProtocolError("invalid create response") from None
    return value


def binary(data: str, maximum: int) -> bytes:
    try:
        value = base64.b64decode(data, validate=True)
    except (ValueError, binascii.Error, TypeError):
        raise ProtocolError("invalid binary encoding") from None
    if len(value) > maximum:
        raise ProtocolError("binary payload exceeds requested limit")
    return value


class SseDecoder:
    """Bounded incremental decoder. Commit a cursor only after a whole frame."""
    def __init__(self, execution_id: str, after: int = 0):
        self.execution_id, self.cursor = execution_id, after
        self.pending = bytearray()
        self.data: list[str] = []
        self.data_size = 0
        self.kind = self.event_id = ""

    def feed(self, chunk: bytes):
        self.pending.extend(chunk)
        while True:
            end = self.pending.find(b"\n")
            if end < 0:
                break
            if end > MAX_FRAME:
                raise ProtocolError("SSE line exceeds limit")
            raw = self.pending[:end]
            del self.pending[:end + 1]
            try:
                line = raw.decode("utf-8").removesuffix("\r")
            except UnicodeDecodeError:
                raise ProtocolError("invalid UTF-8 SSE frame") from None
            if not line:
                if self.data:
                    if self.kind == "error":
                        decode_json(503, "\n".join(self.data).encode())
                    if self.kind != "execution":
                        raise ProtocolError("unexpected SSE event type")
                    value = decode_json(200, "\n".join(self.data).encode())
                    if (not isinstance(value, dict) or value.get("execution_id") != self.execution_id
                            or value.get("sequence") != self.cursor + 1
                            or self.event_id != f"{self.execution_id}:{self.cursor + 1}"):
                        raise ProtocolError("event identity or sequence mismatch")
                    self.cursor += 1
                    yield value
                self.data.clear()
                self.data_size = 0
                self.kind = self.event_id = ""
            elif line.startswith("data:"):
                value = line[5:].removeprefix(" ")
                self.data.append(value)
                self.data_size += len(raw) + 1
            elif line.startswith("id:"):
                self.event_id = line[3:].lstrip(" ")
            elif line.startswith("event:"):
                self.kind = line[6:].lstrip(" ")
            if self.data_size > MAX_FRAME:
                raise ProtocolError("SSE frame exceeds limit")
        if len(self.pending) + self.data_size > MAX_FRAME:
            raise ProtocolError("SSE frame exceeds limit")

    def finish(self):
        if self.pending or self.data:
            raise TransportError()


class Collector:
    def __init__(self, sandbox_id: str, execution_id: str, limit: int):
        self.sandbox_id, self.execution_id, self.limit = sandbox_id, execution_id, limit
        self.cursor = 0
        self.stdout, self.stderr = bytearray(), bytearray()

    def accept(self, event: Json) -> RunOutput | None:
        self.cursor = event["sequence"]
        kind, data = event.get("kind"), event.get("data")
        if not isinstance(data, dict):
            raise ProtocolError("invalid event payload")
        if kind in ("stdout", "stderr"):
            if data.get("encoding") != "base64":
                raise ProtocolError("unsupported output encoding")
            decoded = binary(data.get("data"), self.limit - len(self.stdout) - len(self.stderr))
            (self.stdout if kind == "stdout" else self.stderr).extend(decoded)
        elif kind == "completed":
            check_record(data, self.execution_id)
            if (data.get("sandbox_id") != self.sandbox_id or data.get("state") not in TERMINAL
                    or data.get("cleanup") != "complete"
                    or data.get("state") == "succeeded" and data.get("exit_code") != 0):
                raise ProtocolError("completion lacks a matching terminal result and cleanup")
            return RunOutput(data, bytes(self.stdout), bytes(self.stderr))
        return None
