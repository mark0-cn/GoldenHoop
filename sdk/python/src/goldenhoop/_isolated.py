"""Hierarchy response validation shared by both transports."""
from datetime import datetime
from ._protocol import Json, ProtocolError, check_created, check_record, identity


def _limits(value, *, zero=False):
    names = ("cpu_millis", "memory_bytes", "pids")
    if (not isinstance(value, dict) or any(type(value.get(name)) is not int or value[name] < (0 if zero else 1) for name in names)):
        raise ProtocolError("invalid sandbox scope resources")
    return value


def check_scope(value, sandbox_id: str) -> Json:
    check_record(value, sandbox_id, "sandbox_id")
    root = identity(value.get("root_id"))
    parent, depth = value.get("parent_id"), value.get("depth")
    if (root == "00000000-0000-0000-0000-000000000000" or type(depth) is not int or not 0 <= depth <= 4
            or depth == 0 and (parent is not None or root != sandbox_id)
            or depth > 0 and (parent is None or identity(parent) in (sandbox_id, "00000000-0000-0000-0000-000000000000") or root == sandbox_id)):
        raise ProtocolError("invalid sandbox hierarchy identity")
    features = value.get("feature_limit")
    if (features is not None and (not isinstance(features, list) or any(not isinstance(item, str) for item in features) or len(set(features)) != len(features)) or depth > 0 and features is None):
        raise ProtocolError("invalid sandbox feature ceiling")
    envelope = _limits(value.get("envelope"))
    used = _limits(value.get("allocated_to_children"), zero=True)
    budget = value.get("child_budget")
    if budget is not None:
        _limits(budget)
        if any(used[name] > budget[name] or envelope[name] <= budget[name] for name in ("cpu_millis", "memory_bytes", "pids")):
            raise ProtocolError("sandbox allocation exceeds its reservation")
    elif any(used[name] for name in ("cpu_millis", "memory_bytes", "pids")):
        raise ProtocolError("sandbox allocation lacks a reservation")
    return value


def check_isolated_created(value, request: Json, parent: Json, parent_scope: Json) -> Json:
    value = check_created(value, {"profile": parent["profile"], "image": request.get("image") or parent["image"]})
    sandbox = value["sandbox"]
    scope = check_scope(value.get("scope"), sandbox["id"])
    resources = request.get("resources", {"cpu_millis": 1000, "memory_bytes": 1073741824, "pids": 256})
    if (scope["parent_id"] != parent["id"] or scope["root_id"] != parent_scope["root_id"] or scope["depth"] != parent_scope["depth"] + 1
            or sandbox.get("resources") != resources or scope.get("child_budget") != request.get("child_budget")
            or request.get("feature_limit") is not None and not set(scope["feature_limit"]).issubset(request["feature_limit"])):
        raise ProtocolError("isolated session create response mismatch")
    try:
        expiry, created, deadline = (datetime.fromisoformat(record[name]) for record, name in ((sandbox, "expires_at"), (sandbox, "created_at"), (parent, "expires_at")))
        if any(value.tzinfo is None for value in (expiry, created, deadline)) or not created < expiry <= deadline:
            raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise ProtocolError("invalid isolated session lifetime") from None
    return value
