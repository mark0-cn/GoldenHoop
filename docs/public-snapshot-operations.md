# Public snapshot operation storage

The subsequent [durable capture outcome increment](capture-outcomes.md) adds
schema v19's private refusal receipt and atomic release for positively proved
pre-reservation failures. The original foundation's v18 evidence below remains
bound to its original source.

The storage increment supplies domain resources, durable capture intent and source
admission fencing. The [worker bridge](snapshot-worker.md) now adds authenticated
private admission, native capture/inspection and failed-capture collection. Public
snapshot HTTP routes, restored public execution bindings and MemorySnapshot
capability registration remain unavailable.
The complete M0-M6 objective remains in [roadmap.md](roadmap.md).

## State and ownership

Public `Snapshot` and `SnapshotCreated` contain resource/operation state and a
digest-only manifest. The original runtime handle, opaque backend reference,
dispatch marker and execution candidates remain private `StoredSnapshot` data.
The public response does not serialize those private objects.

The SQLite v18 migration preserves installation identity and existing sandbox
rows. Capture request, operation, source runtime identity, source fence and
candidate execution inventory commit in one transaction. An exact idempotent
retry returns the original resource/operation; different request content conflicts.
An unsupported kind, unavailable profile, unresolved command dispatch or capability
ceiling refusal rolls back both the resource and idempotency reservation.

| Observation | Snapshot | Operation | Source admission |
| --- | --- | --- | --- |
| Intent persisted | Pending | Pending | Fenced |
| First dispatch marked durably | Capturing | Running | Fenced |
| Dispatch/reply uncertain | Unknown, cleanup Unknown | Running | Fenced |
| Backend Ready binding validated | Ready, content cleanup Pending | Succeeded | Fenced until original source collection |
| Refusal before any dispatch marker | Failed, cleanup Complete | Failed | Fence released; no backend call was authorized |
| Original source collected | Content state retained | Retained | Fence released; original source identity acknowledged as collected |

A second `begin_snapshot_capture` returns `first_dispatch=false`; it authorizes
inspection/reconciliation rather than another capture dispatch. Source handle
replacement or erasure before positive collection is refused. The source's actual
cleanup observation and fence release commit atomically, even when normal source
collection clears its current runtime handle. Source collection does not claim
snapshot object collection or release backend object references.

Ready publication checks source/resource/kind/image/profile identity, format,
bounded runtime metadata and the three state/RAM/disk digest roles. A duplicate
publication must carry exactly the original manifest and private reference.
Backend observations and object verification still belong to the worker/driver;
SQL validation alone cannot establish an actual snapshot.

## Dispatch boundary and execution identity

The stored fence blocks new command/file/context/child admission through the
running-tree authorization path, command cancellation and pause/resume requests.
Both worker RPC envelopes consult the fence. Normal reconciliation does not
resume or synchronize a held source; explicit termination and absolute expiry
remain able to collect it. Idempotent reads of an earlier operation preserve that
operation and grant no new runtime effect.

This fence is not proof that previously accepted RPC effects have drained. The
backend worker must coordinate the existing per-sandbox lock with the native
capture's source-generation guard, trusted guest quiescence and physical source
collection before a target may resume.

`snapshot_execution_candidates` preserves each already observed running command's
original public ID, specification, state and event cursor at admission. It is an
inventory rather than proof that an execution is present in captured RAM. Source
rows may subsequently settle; they do not rewrite this immutable inventory.
Restore still needs new public execution IDs, an explicit binding to actual
retained agent IDs, authenticated target generation and correctly translated
event/cancellation cursors. A missing retained agent execution must never fall
through to Start. Old source handles must not acquire target authority.

## Evidence and remaining work

Five real SQLite tests cover concurrent idempotency, persistent fences and
database reopen, no new permit after uncertain dispatch, source identity
replacement/erasure refusal, immutable Ready references and private metadata
separation, original-source collection, unsupported/unsettled admission rollback
and v17 migration. Runtime/collection observations in these tests are synthetic.

The first full Windows/GNU runs exposed legacy migration fixtures that rewrote
the version without removing the new v18 tables. Ten downgrade statements now
remove those test-only tables in dependency order, and six upgrade assertions
expect v18. Production migrations still refuse duplicate table creation. The
[diagnosis](evidence/m4-public-snapshot-migration-diagnosis.json) preserves both
failed runs, the actual SQLite error and the correction scope.

A later Windows workspace run failed in the existing public network policy suite;
its specific assertion was lost by the old diagnostic capture. The same-source
focused13 and full295 rechecks pass after correcting stdout/stderr observation.
The [observation report](evidence/m4-public-snapshot-validation-observation.json)
retains that failure and states that its cause remains unverified; no Rust source,
assertion or production limit was changed for those rechecks.

Worker restoration/Ready-object deletion, no-intent convergence, execution bindings, gateway permissions,
REST/CLI/Rust/Python clients and actual profile probe/public KVM acceptance remain
required before enabling the capability. Rootfs/volume snapshots, templates and
combined M4-M6 remain separate required work. The upstream comparison is recorded
in [the source review](evidence/m4-public-snapshot-upstream-review.json).
