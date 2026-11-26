# Versioned network policy

Public protected creation is optional and requires a pinned host controller and
administrator network configuration. With no network configuration, profiles
retain none-network isolation and do not advertise `NetworkPolicy`. New public
creation, environment-probe and five-level runtime gates require actual
supported-host acceptance. The [4613870 focused gate](evidence/m3-native-45787821888-archive.json)
passes all eight public creation/hierarchy groups on both runc and gVisor,
including five levels, pause/restart/recovery and complete subtree collection.
The current resolver/credential candidate also passes all twenty
[credential groups](evidence/m3-native-45816391918-archive.json) on both runtimes;
the combined Stage gate remains required.

## Earlier readiness diagnosis

At 8353aed, all ten host records and both sixteen-group public policy gates pass.
The runc environment probe completes six root/child commands and confirmed
collection, and two public node creation operations succeed. The five-level
case then fails while the third node waits for readiness: the root is Unknown
with published private readiness expired, while descendants pause with desired
Running. The gVisor probe still fails child readiness before any command. The
[immutable network archive](evidence/m3-policy-sampling-budget-ci-45717051531-archive.json)
preserves twenty-four records with Complete cleanup. Full five-level public
acceptance remains required. Active metadata is not Ready.

The earlier [diagnosis](evidence/m3-network-probe-completion-diagnosis.json)
separates these failures from a definite, previously unreached completion bug:
the known private deployment-probe operation could never settle successfully.
Its durable success guard now requires historical Running, normal Terminated
and Complete cleanup. Actual root/child commands, policy observations and
confirmed collection remain mandatory in the worker before advertising support.
Static dispatch refusal reasons now distinguish the existing readiness checks
and are retained in the sandbox observation. No check, lease lifetime,
publication margin, timeout or execution assertion is relaxed.

The current [sampling-budget diagnosis](evidence/m3-policy-sampling-budget-diagnosis.json)
records a conservative accounting mismatch: the manager previously calculated
remaining time after sampling, while the client anchored it at request start.
The manager now returns a start-relative budget after the same complete native
checks and a still-live-at-finish check. The client retains request-start
anchoring and every existing dispatch fence. The native maximum, original
lifetime and one-second publication margin are unchanged. Its effect on the
full supported-host hierarchy requires a current-source retest.

The independent readback fixture now proves its private IPv6 address can bind
TCP and UDP before testing the production manager. Its seven local and f79409c
hosted groups pass. This does not identify the original hosted binding failure's
cause or establish public protected creation. Positive supported-host
creation/hierarchy retesting remains required. Startup metadata and failure
journals provide no live authority or native absence proof.

## Deployment

Pass `--network-config FILE` and `--egress-controller-image sha256:<digest>` to
the worker. The controller must be the trusted host-egress image, pinned by its
actual image ID. The JSON file is bounded to 64 KiB and rejects unknown fields:

```json
{
  "upstream": "8.8.8.8:53",
  "operator": {"deny_always": [], "allow_always": [], "tcp_cap": null},
  "private_exceptions": [],
  "control_addresses": []
}
```

The resolver and exceptions are administrator input. Workload policy cannot
provide these values. The operator policy is immutable for an installation;
changing it currently refuses rather than silently changing existing authority.
Existing allocations retain their frozen destination bindings.

Protected workloads use the actual owned network gateway as their DNS server.
The driver installs the exact resolver file read-only before startup and checks
it again during recovery. Client resolver options use a five-second wait and one
attempt so paired A/AAAA queries can complete their serialized native policy
transactions. This client wait does not extend a DNS installation deadline,
grant expiry or controller lease. A reachable resolver grants no permission:
names must satisfy the effective policy, destination floor and live source
grant before an address answer can authorize traffic.

While probing, the public worker registration is Unavailable. A private root
and, when supported, child run through actual protected creation, native apply,
commands with explicit stdout/exit, ancestor policy changes and cascade
collection. Only a successful probe with confirmed resource absence publishes
`NetworkPolicy`. Failed primitives make the profile Unavailable; unconfirmed
probe collection prevents startup. There is no none-network fallback. Probes
temporarily reserve 500 millicores, 256 MiB and 64 PIDs per node, including a
child reservation when hierarchy is supported. Probe roots have durable private
markers, remain absent from public sandbox listings and are collected after a
worker crash before new support is advertised.

New sandboxes on an enabled available profile take the protected path even
with the default deny policy. Previously running none-network allocations keep
their original isolation and cannot acquire public policy updates. A new or
uncertain allocation cannot fall through to none-network creation.

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
`network-policy-set ID --policy FILE --expected-revision N`. Creation and
`isolated-create` accept `--network-policy FILE`, which also requires the
NetworkPolicy capability even when the file contains the default deny policy.
The setter prints
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
tables. Schema 13 adds bridge/workload creation dispatch and settlement records.
The record commits immediately before the actual daemon write. Correlated
daemon responses or fresh matching owned physical IDs may settle it; a timeout,
EOF or empty inventory cannot. An unsettled dispatch prevents native collection
and cleanup completion. Prepared runtime IDs are durable before supervisor
start; partial creation never replays through another runtime path.

Schema upgrades preserve existing private/public policy and acknowledgement
payload bytes. Migration invents neither dispatch completion nor a live lease.
