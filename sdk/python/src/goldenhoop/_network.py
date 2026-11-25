"""Desired-policy response identity checks; these values are not live leases."""
from ._protocol import ProtocolError, check_record, identity


def policy_state(value, sandbox_id):
    value = check_record(value, sandbox_id, "sandbox_id")
    revision = value.get("revision")
    if type(revision) is not int or not 0 <= revision <= 2**63 - 1 or not isinstance(value.get("policy"), dict):
        raise ProtocolError("invalid desired network policy")
    return value


def policy_request(expected_revision, policy):
    if type(expected_revision) is not int or not 0 <= expected_revision < 2**63 - 1 or not isinstance(policy, dict):
        raise ValueError("invalid network policy revision or policy")
    policy = dict(policy)
    policy.setdefault("rules", [])
    if isinstance(policy["rules"], list):
        policy["rules"] = [dict(rule, ports=rule.get("ports", [])) if isinstance(rule, dict) else rule
                           for rule in policy["rules"]]
    return {"expected_revision": expected_revision, "policy": policy}


def policy_change(value, sandbox_id, request):
    if not isinstance(value, dict):
        raise ProtocolError("invalid network policy change")
    policy = policy_state(value.get("policy"), sandbox_id)
    operation = check_record(value.get("operation"), sandbox_id, "resource_id")
    identity(operation.get("id"))
    if policy["revision"] != request["expected_revision"] + 1 or policy["policy"] != request["policy"]:
        raise ProtocolError("network policy response differs from requested version")
    return value
