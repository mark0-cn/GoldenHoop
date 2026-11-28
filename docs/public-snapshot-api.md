# Public snapshots and durable deletion

The [restoration interface](public-snapshot-restoration.md) adds a new target,
retained execution bindings and target-held content references. Snapshot deletion
also requires positive collection of that restoration target.

The gateway, Rust/Python clients and CLI expose snapshot admission, stored reads,
pagination and deletion intent. Memory capture still requires a currently
advertised and available MemorySnapshot capability. Native registration keeps
that capability off until actual public restoration and profile acceptance are
complete. Rootfs/volume capture, templates, combined
M4 and complete M5-M6 remain required in [roadmap.md](roadmap.md).

## Routes and source authorization

| Request | Result |
| --- | --- |
| `POST /v1/sandboxes/{source}/snapshots` | `202 SnapshotCreated`; explicit kind and Idempotency-Key required |
| `GET /v1/snapshots/{id}` | Stored public Snapshot |
| `GET /v1/snapshots?sandbox_id={source}&after={cursor}&limit={n}` | SnapshotPage; limit1-1000, ascending UUID cursor |
| `DELETE /v1/snapshots/{id}` | `202 Operation`; durable collection intent |
| `POST /v1/snapshots/{id}/restore` | `202 SnapshotRestored`; explicit key and all-resource Write grant |
| `GET /v1/sandboxes/{target}/restoration` | Stored new-target bindings; target Read grant |
| `GET /v1/operations/{id}` | Capture/collection use source grants; restoration uses its new target grant |

Snapshot resources and both operation kinds inherit the original source sandbox's
grant. Read keys cannot mutate. A sandbox-scoped key must provide exactly one
authorized `sandbox_id` for collection reads; unfiltered collections require a
global grant. Unknown query fields and duplicate selectors are refused. Snapshot
operation kinds resolve through the snapshot table before generic resource UUID
lookup, so an unrelated table's matching UUID cannot change source authority.

Fresh capture checks the available profile and delegates to the authenticated
private worker. The worker owns source serialization and native dispatch. The
gateway checks reply identity against the common store and returns stored public
metadata, rather than forwarding mutable backend payloads. Capture requests have
an8KiB limit and reject unknown fields. Backend handles, private references,
refusal receipts, host paths and worker credentials stay private.

Exact capture retries read the original request binding before requiring a live
worker or capability. A changed request conflicts. Stored reads and deletion
intent remain available after worker retirement. A lost admission reply grants
no new key or second dispatch; retry with the same explicit key.

## Source-safe deletion

The current native memory mode is a single-use continuation with a held source.
Deleting the snapshot does not authorize removing that source. For an already
dispatched capture with outstanding resources, explicitly collect the source
sandbox first. An early deletion request conflicts without reserving a key or
changing the source. This also protects captured state while a source writer or
retained restoration backing may still own it.

The existing reserved-capture failure path collects an unresolved source before
backend GC. A definitive pre-reservation refusal instead leaves the source
available. This distinction is part of the native transfer mode; unsupported
requests are rejected before creating a capture intent.

SQLite v20 adds a private immutable collection operation binding. Deletion and
the first capture marker serialize in one transaction: an undispatched capture
can be cancelled with no backend call; once dispatch wins, deletion requires the
original source collection receipt. A capture already proved resource-free can
also settle immediately. New deletion keys alias the same collection operation.

Outstanding deletion becomes Collecting with a Pending/Running operation. Its
original source handle and backend reference remain retained across database
reopen, timeout and lost replies. The worker uses source-bound GC without creating
a VM or issuing Start. A native missing-record reply can reconcile a permanent
pre-reservation refusal; it never resubmits capture. Only positive Collected or a
validated durable Refused observation completes the collection transaction.
Unknown and foreign observations keep Cleanup Unknown and the operation Running.

Positive collection atomically clears backend authority, sets Collected / Cleanup
Complete and succeeds the collection operation. Snapshot rows and public digest
metadata remain as source-authorization and idempotency history. A completed capture operation retains its original outcome; an
unpublished capture superseded by deletion becomes Cancelled. Resource collection
never manufactures capture success or revives a deleted snapshot.

## Clients and CLI

Rust exposes `create_snapshot`, `snapshot`, `list_snapshots` and `delete_snapshot`.
Python provides the same methods on Client and AsyncClient, with
`CreateSnapshot("memory_and_disk")`. Submission/deletion require an explicit key.
Waiting or cancelling an async request leaves the original operation recoverable
with that key. Clients check source/resource/operation identity, manifest digest
roles, collection completion, pagination ordering and continuation cursors.

```text
goldenhoop snapshots create <source> --kind memory_and_disk --idempotency-key capture-1
goldenhoop snapshots get <snapshot>
goldenhoop snapshots list --sandbox <source>
goldenhoop delete <source> --idempotency-key explicit-source-delete
goldenhoop snapshots delete <snapshot> --idempotency-key snapshot-delete-1
```

Create/delete wait for their operation by default. `--no-wait` prints durable
acceptance. The CLI prints recovery keys and operation/resource IDs before
waiting, and requires Ready or positively Collected for a completed result.

## Verification boundary

SQLite migration/reopen, in-process public HTTP, actual loopback private/client
transport and CLI startup are separate checks. Their VM and object observations
are synthetic. Native KVM public capture/restore/delete, profile advertisement,
retained execution/event/cancel binding and the complete M4 stage remain unverified
until their actual backend gates pass.

The [Windows workspace report](evidence/m4-snapshot-api-validation-windows.json)
passes316 Rust and33 Python SDK tests; the [GNU-root workspace report](evidence/m4-snapshot-api-validation-linux.json)
passes438 executions and the host release build. Formatting and strict all-target
workspace clippy pass. The [source/index audit](evidence/m4-snapshot-api-source-index-audit.json)
binds the same383 Rust/manifest/Docker/Python inputs. Focused Windows/GNU suites
each pass27 Rust tests and Windows Python33. The [diagnosis](evidence/m4-snapshot-api-development-diagnosis.json)
retains the missing test dependency and the original first-Store.open GNU failure;
its underlying startup category was not captured. Same-source targeted and full
runs pass without relaxing a production timeout, pool limit or ownership rule.

The [musl report](evidence/m4-snapshot-api-validation-musl.json) passes21 scoped
tests, strict firecracker/init all-target clippy and four static component release
builds on the same383 inputs. The [implementation summary](evidence/m4-snapshot-api-implementation-summary.json)
binds all successful checks, retained development failures and positive collection
receipts for the three owned check images. Actual public KVM acceptance remains
separate.
