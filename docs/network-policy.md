# Versioned network policy

This increment exposes desired-policy metadata and an update contract for an
allocation that already has a trusted public-source protected binding. Normal
public sandbox creation still uses none-network isolation. `NetworkPolicy` is
not advertised: initial public provisioning and actual hierarchy composition
remain release gates. The private contract producer is a test setup tool.

## API and clients

`GET /v1/sandboxes/{id}/network-policy` returns only
`{sandbox_id, revision, policy}`. Revision zero is the original create request;
subsequent revisions are durable overrides. Reads do not require a live worker
and do not establish that a policy is currently applied.

`PUT` on the same route requires an `Idempotency-Key` and this body:

```json
{
  "expected_revision": 0,
  "policy": {
    "default_action": "deny",
    "rules": [{"destination": "93.184.216.34", "ports": [443], "action": "allow"}]
  }
}
```

The response is HTTP 202 with `{policy, operation}`. Reusing a key with the same
request returns the original policy snapshot and operation identity, together
with that operation's current status. Stale revisions and changed key contents
conflict. Unknown fields and bodies larger than 64 KiB refuse. An ordinary
running none-network allocation returns `unsupported_capability`; an allocation
still awaiting its protected binding returns `invalid_state`.

Rust and synchronous/asynchronous Python clients provide `network_policy` and
`set_network_policy`. The CLI provides `network-policy ID` and
`network-policy-set ID --policy FILE --expected-revision N`. The latter prints
the idempotency key and operation ID before waiting; `--no-wait` returns the
pending operation. These interfaces do not enable an unavailable profile.

## Application and hierarchy

Each node has an independent own-policy version. Effective configuration is
compiled from the root-to-node user layers and the installation's immutable
administrator policy. Public requests cannot set administrator exceptions, TCP
ceilings, native identities, controller ownership, or lease data. Changing the
bound administrator policy currently refuses; administrator rollout is separate
future work.

An ancestor update compiles and fences affected live descendants atomically.
Pending children use the latest source lineage when staging. An incompatible
legacy running child refuses the entire update. The operation waits for each
target's source revision to be confirmed by the protected native apply path;
concurrent child changes can confirm the same ancestor source. Confirmed
collection may satisfy an absent descendant, but collection alone cannot make
the changed node's own unapplied policy succeed. Superseded unapplied changes
are cancelled.

Fencing invalidates dispatch readiness before asynchronous application. It does
not promise instantaneous packet revocation: native replacement and the finite
kernel lease bound enforcement. An operation records completed application;
current readiness still requires the worker's process-local lease and actual
runtime observations. Restarted processes cannot derive that lease from SQLite.

Schema 12 adds intent, change-target and historical source-acknowledgement
tables. Schema 11 private policy/history payloads remain byte-for-byte intact;
migration does not promote them to public bindings or live authority.
