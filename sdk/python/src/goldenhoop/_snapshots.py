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


def restore_request(value):
    try:
        result = body(value)
        target = result["target"]
        if (set(result) != {"target"} or not isinstance(target, dict)
                or not set(target) <= {"profile", "image", "resources", "ttl_seconds", "required_capabilities", "network", "metadata", "child_budget", "feature_limit"}
                or any(not isinstance(target.get(k), str) or not target[k] for k in ("profile", "image"))):
            raise ProtocolError("restoration requires an explicit target sandbox request")
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ProtocolError("invalid restoration request") from None
    return result


def restored(value, snapshot_id=None, target_id=None, request=None):
    try:
        snapshot, target = _uuid(value["snapshot_id"]), _uuid(value["sandbox"]["id"])
        if (snapshot == target or snapshot_id is not None and snapshot != snapshot_id
                or target_id is not None and target != target_id):
            raise ProtocolError("restoration identity differs from its original target")
        operation(value["operation"], target)
        if request is not None and (value["sandbox"]["profile"] != request["target"]["profile"]
                or value["sandbox"]["image"] != request["target"]["image"]
                or "resources" in request["target"] and value["sandbox"]["resources"] != request["target"]["resources"]):
            raise ProtocolError("restoration target configuration differs")
        bindings, previous, ids = value["executions"], None, set()
        if not isinstance(bindings, list) or len(bindings) > 256:
            raise ProtocolError("restoration execution binding limit exceeded")
        for binding in bindings:
            source, execution = _uuid(binding["source_execution_id"]), binding["execution"]
            eid = _uuid(execution["id"])
            if (eid in (source, target) or eid in ids or _uuid(execution["sandbox_id"]) != target
                    or previous is not None and source <= previous):
                raise ProtocolError("restoration execution binding differs")
            previous = source
            ids.add(eid)
    except (KeyError, TypeError, AttributeError):
        raise ProtocolError("invalid restoration response") from None
    return value
