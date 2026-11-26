"""Credential metadata validation; provider values are write-only input."""
from ._protocol import Json, ProtocolError, identity


def record(value: Json, sandbox: str, binding: str | None = None) -> Json:
    if not isinstance(value, dict):
        raise ProtocolError("invalid credential metadata")
    rid = identity(value.get("id"))
    revision, applied = value.get("revision"), value.get("applied_revision")
    if (identity(value.get("sandbox_id")) != sandbox or binding is not None and rid != binding
            or type(revision) is not int or revision <= 0
            or applied is not None and (type(applied) is not int or not 0 < applied <= revision)
            or value.get("state") not in {"pending", "active", "revoking", "revoked", "failed"}
            or value.get("state") == "active" and applied != revision
            or not isinstance(value.get("binding"), dict)
            or {"secret", "sealed", "signing_key", "fingerprint"} & value.keys()):
        raise ProtocolError("credential identity or revision differs")
    return value


def records(value: list[Json], sandbox: str) -> list[Json]:
    if not isinstance(value, list) or len(value) > 256:
        raise ProtocolError("invalid credential collection")
    checked = [record(item, sandbox) for item in value]
    if len({item["id"] for item in checked}) != len(checked):
        raise ProtocolError("credential collection repeats an identity")
    return checked


def ca(value: Json, sandbox: str) -> Json:
    if not isinstance(value, dict):
        raise ProtocolError("invalid credential public CA")
    pem = value.get("certificate_pem")
    if (identity(value.get("sandbox_id")) != sandbox or not isinstance(pem, str)
            or len(pem) > 16384 or not pem.startswith("-----BEGIN CERTIFICATE-----")
            or "PRIVATE KEY" in pem):
        raise ProtocolError("credential public CA identity differs")
    return value
