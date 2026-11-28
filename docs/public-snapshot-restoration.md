# Public memory continuation

The public restoration path creates one new sandbox from a Ready memory-and-disk
snapshot after positive original-source collection. It uses the existing native
manager's independently supervised continuation path. Native MemorySnapshot
advertisement requires an [actual continuation and collection probe](native-memory-capability.md);
the actual public KVM release gate remains a separate requirement.
The complete [M0-M6 objective](roadmap.md) is unchanged.

## Requests and durable identity

`POST /v1/snapshots/{id}/restore` requires an explicit idempotency key and a
`RestoreSnapshot` body containing a target `CreateSandbox` request. The target
preserves the captured source's image, profile, resource limits and feature ceiling.
It may select a new lifetime and metadata. The native continuation path currently
requires its configured baseline image and default-deny isolated networking;
prepared-image memory continuation and additional retained state remain separate
implementation and acceptance work.

The response contains the snapshot ID, new sandbox, restoration operation and
explicit source-to-target execution bindings. The operation's resource is the new
sandbox. `GET /v1/sandboxes/{id}/restoration` reads those durable bindings.

SQLite v21 inserts the target, scope, restoration operation, immutable target
intent and execution bindings in one immediate transaction. One snapshot has one
target, including after refusal or target collection. An exact retry returns its
original target and operation before consulting live worker/profile availability.
Changed content under the same key conflicts; another key cannot allocate a
second target. Restoration and snapshot deletion serialize in the same database.

The worker persists dispatch before native admission. A transport retry uses the
exact original target and restoration ID. Native journal identity and the unique
native continuation claim prevent ordinary boot, another generation or a second
supervisor from relaunching an already settled target. A stored runtime handle
cannot be replaced or erased before positive target collection.

The private native request and journal bind the expected captured source handle,
including its generation. A foreign validly encoded generation is refused before
target allocation. Temporary VM-capacity or validation-slot pressure preserves the
same operation and pending target until reconciliation, TTL or cancellation.

## Retained execution and events

The snapshot's immutable inventory supplies the source public execution IDs,
command specifications, observed start times and durable event cursors. Restoration
allocates new public execution IDs and privately binds them to the retained agent
IDs. A second continuation composes the earlier binding and cursor offset rather
than treating the intermediate public ID as a new agent job.

Before activation, the worker requires an observed Running target and authenticated
inspection of every retained execution. Target activation, Running publication and
operation success commit together. These observations acknowledge restoration;
they do not claim that a retained command has completed successfully.

Inspect, event reads and cancellation translate the new public ID to the retained
agent ID through the original target handle. The new public event stream starts
at sequence1 after the capture inventory's acknowledged agent cursor. Completed
event payloads also receive the new public execution and sandbox identity.
Already observed source output is not duplicated. Retained agent start/completion
timestamps come from the guest and can precede the new host resource's creation
time after continuation. They are distinct from host operation observations.
Guest wall-clock synchronization is not established by this contract gate.

A missing retained agent execution fails the restoration and collects its target.
It never enters Start. Source execution results and source cancellation handles
retain their original scope. Stream EOF and a terminal agent result without its
durable completed event retain the existing uncertain-result semantics.

## Authorization and collection

Creating or retrying a restoration requires Write permission with an all-resource
grant, as for creating an independent sandbox. The source's exact sandbox grant
does not authorize a new target. Target reads, operations, executions and
cancellation require that target's own grant; Read, Write and Execute remain
distinct permissions. This preserves the [M3 exact-grant policy](m3-delivery.md).
The target's lifecycle scope is independent of the terminated source, so its new
lifetime is the one authorized by the creator. Old execution IDs retain their
original scope. Private runtime references never appear in public responses.

Snapshot deletion refuses while its restoration target lacks a positive collection
receipt. Target termination first asks the native manager to close the exact
restoration. The original target mutex serializes collection against delayed
creation. Existing targets require their original journal and actual resource
absence; a target without a journal receives a durable pre-reservation closure.
Both ordinary boot and restoration consult that permanent closure before backend
effects. Exact closure retries survive native-manager reconnects; foreign intents
cannot replace the receipt.

Unknown or lost collection replies keep the target and snapshot references. Failed
restoration operations do not imply cleanup. Only positive target closure permits
normal source-bound snapshot GC. Native closure metadata is retained to fence
late requests and has its own bounded history; it is not a disposable VM resource.

## Clients

Rust and sync/async Python clients expose `restore_snapshot` and
`snapshot_restoration`. Calls require an explicit recovery key and validate target,
operation and execution binding identity. Waiting or cancellation of a local
request does not implicitly delete either sandbox or snapshot.

```text
goldenhoop snapshots restore <snapshot> --request <restore-request.json> --idempotency-key restore-1
goldenhoop snapshots restoration <new-sandbox>
```

The request file contains `{"target": {...CreateSandbox fields...}}`. The CLI
prints the recovery key, target and operation before waiting. `--no-wait` reports
durable acceptance. Default waiting requires an observed Running target.

## Acceptance boundary

SQLite migration, reopen, routing, authorization, loopback transport, CLI startup
and native closure files can be checked locally. VM and agent observations in the
worker fixtures are synthetic. The separate [actual public KVM gate](evidence/m4-public-memory-acceptance-summary.json)
passes14 groups/399 inputs/Complete atbfd6992 on the configured baseline: actual
RAM/disk continuation, capability probing, exact new-target grants, manager
SIGKILL/worker reconnect, explicit completion/cancellation and positive VM/object
collection. Matching392-input full Windows/Ubuntu CI passes at63ff6d1.
Prepared-image continuation, additional retained state, rootfs/volume snapshots,
templates, broader failure/pressure coverage, combined M4 and M5-M6 remain required.

The real-backend gate must include validly encoded handles for a foreign source
generation, foreign target/operation identities and corrupt content. Such requests
must not acquire another generation's restoration or collection authority.
RestoreSnapshot, RestoredExecution and SnapshotRestored are registered in the
model schema export; generation resolves all93 references across76 components.
This schema verification remains separate from the actual baseline KVM gate.
Concurrent restoration and native validation-slot pressure also require real
acceptance: temporary capacity pressure should preserve the original pending
target and recovery key rather than consume its one-use continuation.

The final [Windows workspace report](evidence/m4-snapshot-restore-validation-windows-final.json)
passes325 Rust and36 SDK tests. The [GNU-root workspace report](evidence/m4-snapshot-restore-validation-linux-final.json)
passes449 executions and the images-service release build. Formatting and strict
all-target workspace clippy pass on those same391 inputs. Focused Windows36,
GNU-root44 and SDK36 also pass on that map. The [diagnosis](evidence/m4-snapshot-restore-development-diagnosis.json)
preserves the initial test-premise failures and the corrected draft authorization
design; the final source preserves M3 exact grants.
The [musl report](evidence/m4-snapshot-restore-validation-musl.json) passes21 scoped
tests, strict firecracker/init all-target clippy and four static component release
builds on that same391-input map. The [implementation summary](evidence/m4-snapshot-restore-implementation-summary.json)
records all final checks, five positively collected check tags and the one
automatically blocked failed-test directory whose absence remains unverified.
