"""Public snapshot identity and completion validation shared by both clients."""
from ._protocol import ProtocolError, body, identity

KINDS = frozenset(("rootfs", "volumes", "memory_and_disk"))
STATES = frozenset(("pending", "capturing", "ready", "failed", "unknown", "collecting", "collected"))


def _uuid(value):
    result = identity(value)
    if result == "00000000-0000-0000-0000-000000000000":
        raise ProtocolError("snapshot identity is nil")
    return result


def request(value):
    result = body(value)
    if set(result) != {"kind"} or not isinstance(result["kind"], str) or result["kind"] not in KINDS:
        raise ProtocolError("snapshot request requires an explicit supported kind")
    return result


def record(value, snapshot_id=None, sandbox_id=None, kind=None):
    try:
        sid, source = _uuid(value["id"]), _uuid(value["source_sandbox_id"])
        if (snapshot_id is not None and sid != snapshot_id
                or sandbox_id is not None and source != sandbox_id
                or kind is not None and value["kind"] != kind
                or value["kind"] not in KINDS or value["state"] not in STATES
                or value["cleanup"] not in ("pending", "unknown", "complete")
                or value["state"] == "collected" and value["cleanup"] != "complete"
                or value["cleanup"] == "complete" and value["state"] not in ("failed", "collected")
                or value["state"] == "ready" and value.get("manifest") is None):
            raise ProtocolError("snapshot identity or completion evidence mismatch")
        manifest = value.get("manifest")
        if manifest is not None:
            objects = manifest["objects"]
            if (type(manifest["format_version"]) is not int or manifest["format_version"] != 1
                    or _uuid(manifest["id"]) != sid or _uuid(manifest["source_sandbox_id"]) != source
                    or manifest["kind"] != value["kind"]
                    or any(not isinstance(manifest[k], str) or not manifest[k]
                           for k in ("driver", "architecture", "runtime_version", "image_digest"))
                    or not isinstance(objects, dict) or not objects
                    or value["kind"] == "memory_and_disk" and set(objects) != {"state", "memory", "disk"}
                    or any(not isinstance(digest, str) or not digest.startswith("sha256:")
                           or len(digest) != 71 or any(c not in "0123456789abcdef" for c in digest[7:])
                           for digest in objects.values())):
                raise ProtocolError("snapshot manifest differs from public resource")
    except (KeyError, TypeError, AttributeError):
        raise ProtocolError("invalid snapshot resource") from None
    return value


def operation(value, snapshot_id):
    try:
        _uuid(value["id"])
        if (_uuid(value["resource_id"]) != snapshot_id
                or value["state"] not in ("pending", "running", "succeeded", "failed", "cancelled")):
            raise ProtocolError("snapshot operation identity mismatch")
    except (KeyError, TypeError):
        raise ProtocolError("invalid snapshot operation") from None
    return value


def created(value, sandbox_id, kind):
    try:
        snapshot = record(value["snapshot"], sandbox_id=sandbox_id, kind=kind)
        operation(value["operation"], _uuid(snapshot["id"]))
    except (KeyError, TypeError):
        raise ProtocolError("invalid snapshot create response") from None
    return value


def page(value, sandbox_id, after, limit):
    try:
        items = value["items"]
        if not isinstance(items, list) or len(items) > limit:
            raise ProtocolError("snapshot page exceeds requested limit")
        cursor = after
        for item in items:
            record(item, sandbox_id=sandbox_id)
            item_id = _uuid(item["id"])
            if cursor is not None and item_id <= cursor:
                raise ProtocolError("snapshot page cursor did not advance")
            cursor = item_id
        if value["next_cursor"] is not None and (_uuid(value["next_cursor"]) != cursor or len(items) != limit):
            raise ProtocolError("snapshot continuation cursor differs from page")
    except (KeyError, TypeError):
        raise ProtocolError("invalid snapshot page") from None
    return value


def parameters(sandbox_id, after, limit):
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ProtocolError("snapshot page limit must be between 1 and 1000")
    sandbox_id = identity(sandbox_id) if sandbox_id is not None else None
    after = identity(after) if after is not None else None
    return sandbox_id, after, {"limit": limit, **({"sandbox_id": sandbox_id} if sandbox_id else {}), **({"after": after} if after else {})}
