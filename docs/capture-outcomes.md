# Durable capture admission outcomes

Current configured-baseline public memory acceptance is recorded in the
[14-group actual KVM summary](evidence/m4-public-memory-acceptance-summary.json):
399 source inputs and Complete collection. The notes below retain this earlier
increment's validation scope and historical pending states. Additional failure
cuts and combined M4-M6 remain required; deployment support still needs its real
continuation/collection probe.

The subsequent [public snapshot interface](public-snapshot-api.md) exposes stored
resources and durable collection intent while retaining this refusal proof. Its
native missing-record collection path also reconciles the same closed ID without
submitting a producer.

The worker may commit its dispatch marker and lose the request before the native
manager receives it. A timeout or missing native record cannot release that
source's fence: an earlier request could still arrive later. The native manager
now records a permanent, source-bound refusal before acknowledging that this
capture never reserved resources. This is private implementation work; public
MemorySnapshot registration remains disabled and actual KVM acceptance is separate.

## Original-source decision

The worker's observed submission uses `CheckpointCaptureObserved`. Existing raw
`CheckpointCapture` callers retain their error contract. A previous dispatch first
uses read-only `CheckpointInspectBound`; only a NotFound reply permits
`CheckpointReconcileBound`, which cannot start capture.

Reconciliation checks the original native owner, acquires the same VM mutex as
capture admission, rechecks the owner and original intent, and rejects a capture
hold with no acknowledged reservation. It then takes the store quota mutex and
recovers pending metadata for this exact capture. An existing reservation is
inspected. It is never converted to a refusal or collected by this path.

New reservations write `admission-{capture}.json` before creating the job mutex or
reservation. This sidecar binds the installation, store nonce, source sandbox,
source generation, request digest, capture ID and full intent digest. Legacy
reservation records remain readable without a sidecar, and the job lock header
format is unchanged. An incomplete legacy mutex without a source-bound admission
cannot establish which original source owns it and remains unconfirmed.

When no reservation or contradictory source hold exists, the manager atomically
publishes `refusal-{capture}.json`. The refusal binds the original source and store
nonce, retains a bounded private diagnostic and reports a sanitized reason. Both
new and legacy capture submissions check it. Late requests for that same ID cannot
create a job mutex, reservation, capture hold or producer. Exact retries return
the original decision even when a later error differs. A new capture ID may be
admitted against the same healthy source.

Refusal metadata is retained, including after an inspect or collect call. It is
not a memory object or an active byte reservation. The existing 1024-entry history
limit now counts the union of reservations, admissions and refusals without
eviction. Full history, pending metadata from an unconfirmed writer, mismatched
source bindings and malformed receipts remain errors; they cannot manufacture a
no-effects acknowledgement.

## Worker and SQLite settlement

The native projection accepts `Refused` only with the exact original capture and
generation handle, a non-nil store nonce, a complete source identity, a valid
request digest, zero reserved bytes, positively absent objects and no manifest,
reference, verified content or contradictory failure. Other phases cannot carry
a refusal. Native diagnostics and private proof fields remain private.

SQLite schema v19 adds the private `capture_refusal` column. The worker persists
the validated receipt with resource Failed, operation Failed, Cleanup Complete
and fence release in one transaction. This acknowledges no resources for this
capture; it does not claim that the healthy source was collected. A duplicate
settlement must retain the same receipt and reason. A terminal refusal cannot
subsequently publish Ready. Exact idempotency-key retries retain the old result;
fresh intent needs a new key and capture ID. Settled refusals stop occupying the
profile's capture producer slot.

| Backend observation | Worker result | Original source |
| --- | --- | --- |
| Timeout, transport error or plain NotFound | Unknown; inspect/reconcile original ID | Fence retained until positive outcome or original collection |
| Existing pending capture or incomplete ownership proof | Existing state or Unknown | Existing capture authority retained |
| Durable source-bound refusal before reservation | Failed, Cleanup Complete; proof retained | Fence released; no source removal implied |
| Positively failed capture after reservation | Failed; cleanup still required | Original source collection precedes backend object GC |

## Verification boundary

The focused tests use real SQLite reopen/migration, actual root-owned filesystem
records, actual child-process SIGKILL and source mutexes. Worker/backend and VM
observations in these tests are synthetic. They do not establish a new native
KVM capture/refusal gate. Public capture, restoration and deletion, rotated
target/execution identities, retained guest execution/event/cancel bindings,
actual capability probing and hardware recovery/collection acceptance remain
required. Rootfs/volume snapshots, templates and complete M4-M6 remain open.

The frozen-source [Windows workspace report](evidence/m4-capture-outcomes-validation-windows.json)
passes304 tests; the [GNU-root workspace and host release report](evidence/m4-capture-outcomes-validation-linux.json)
passes426 executions. Both include formatting and strict all-target workspace
clippy. The [focused GNU-root report](evidence/m4-capture-outcomes-targeted-linux-final.json)
passes31 executions across12 storage,5 native projection,8 worker and6 snapshot
database tests. All bind the same356 inputs as the [byte-exact source/index audit](evidence/m4-capture-outcomes-source-index-audit.json).
The earlier [Windows focused report](evidence/m4-capture-outcomes-targeted-windows.json)
passes14 tests before two native-only compile corrections, so its earlier source
map is retained separately. The [development diagnosis](evidence/m4-capture-outcomes-development-diagnosis.json)
retains both original failures and verifies the failed tags are absent; no
production permission, timeout or ownership condition was relaxed.

The [scoped musl report](evidence/m4-capture-outcomes-validation-musl.json) passes21
descriptor/control/init tests, strict firecracker/init all-target clippy and
release builds of agent, egress, init and image-builder. Its source map is also
identical. The [implementation summary](evidence/m4-capture-outcomes-implementation-summary.json)
binds all final reports and positive collection of the three owned check tags.

The [upstream review](evidence/m4-capture-outcomes-upstream-review.json) compares
OpenSandbox's observation-based convergence and Temporal's terminal ID reuse
policy. The permanent refusal and source/metadata proof are GoldenHoop-specific
requirements, not claims that either upstream implements the same mechanism.
