# Worker-owned memory capture

The worker now owns authenticated private admission, first capture dispatch,
inspection-only recovery and collection of positively failed captures. The
complete M0-M6 objective remains in [roadmap.md](roadmap.md). Public snapshot
REST/CLI/SDK routes, public restoration/execution bindings and the actual public
profile probe remain required. MemorySnapshot is still unadvertised.

## Admission and producer ownership

`POST /internal/snapshots` is a private control-to-worker call, protected by the
existing worker bearer boundary and an 8KiB body limit. Its request contains a
source UUID, `CreateSnapshot` and a validated idempotency key; it accepts no backend
reference, host path or caller-chosen snapshot ID. This is not a public gateway
endpoint. Gateway source authorization remains part of the forthcoming public API.

A read-only exact retry returns the original resource/operation before attempting
to acquire the source lock or requiring the old driver to remain available. Changed
request content conflicts. A miss reserves nothing. First admission holds the
same source-sandbox mutex used by ordinary worker command/file dispatch, performs
pure driver validation, and creates the durable store intent/fence. Previously
accepted effects finish before that fence is written. A queued retry rechecks
idempotency after obtaining the lock.

`RuntimeDriver` has private typed memory-capture observations and explicit default
unsupported behavior. `supports_memory_capture` describes configured private
implementation only; it never inserts a public capability. Native prepared-image
continuation remains explicitly unsupported by preflight. The native bridge calls
the existing manager-owned capture job and never ordinary VM creation or workload
Start.

Reconciliation takes the same source lock and persists the dispatch marker before
calling capture. A prior marker only calls inspection, even if its original reply
was lost or the backend reports NotFound. The worker's single snapshot task permit
bounds concurrent RPC/hash work; persisted in-flight state additionally retains
the profile's producer slot after a Pending reply releases that task permit.
Later same-profile captures remain queued until the original capture settles.
Unrelated sources' ordinary work uses its own source locks and the remaining
ordinary worker permits.

## Source-bound native observations

`checkpoint_inspect_bound` and `checkpoint_collect_bound` add the original runtime
handle to the private native call. The manager checks its original journal owner
and the capture's installation, source UUID, generation and request fingerprint
before inspection or collection. Neither operation calls capture when absent.

The typed native bridge accepts Ready only from a verified Ready observation with
a valid complete manifest/reference, original source resources, canonical native
generation handle and enough retained bytes. It projects only the public manifest's
three state/RAM/disk digests and runtime metadata. Private source/restore records,
host paths and native diagnostics do not become public response fields.

Source Paused is freshly inspected before publication, following the normal
Running/Pausing/Paused state path. Already collected sources keep their durable
original collection acknowledgement. A reported missing/exited source is actually
collected before acknowledgement; metadata absence alone is insufficient.

| Observation | Resource/operation | Collection obligation |
| --- | --- | --- |
| Transport/dispatch uncertain | Unknown / operation still Running | Original source fence and backend reservation retained; inspect only |
| Backend Pending | Capturing or prior Unknown / Running | Producer slot retained; no Ready inference |
| Verified Ready | Ready / Succeeded | Snapshot references retained; source fence lasts until its collection |
| Positively failed backend capture | Failed / Failed | Cleanup Pending, source still fenced |
| Source removal or object GC uncertain | Failed / Failed | Cleanup Unknown, original failure preserved |
| Original source and backend objects positively collected | Failed / Failed | Cleanup Complete; no manufactured operation success |

Failed captures remain in the work scan after source collection releases the
source fence. Source removal precedes object GC, and positive object collection
must match the original source and capture. The terminal capture error/operation
is preserved across cleanup retries. Explicit termination and absolute expiry are
processed inside snapshot reconciliation so repeated polling cannot starve source
collection by repeatedly taking its mutex first.

## Verification and remaining acceptance

Seven worker tests exercise real file-backed SQLite, mutex ordering, database
reopen, authenticated private HTTP, uncertain dispatch, source-generation refusal,
durable producer occupancy, unrelated RPC progress and independent failure/GC
recovery. Their backend observations are synthetic. Three native projection tests
check full reference/source/resource binding, contradictory Ready and collection
states, private metadata separation and unchanged capability registration. The
retained five snapshot database tests remain selected.

The initial GNU targeted14 report predates the durable producer-slot refinement;
the final full workspace reports must bind the final source. The original test
pool wait and unit-binding lint are retained. The corrected mutex test keeps the
admission future polled alongside its observer and proves it has queued on the
original lock before checking the fence; it changes no production timeout or limit.

Before enabling the capability, implement and actually verify definitive native
refusal/no-intent convergence for the marker-before-send crash window. The current
conservative state stays Unknown when native inspection cannot prove what happened,
including after source collection; it does not recapture, release unknown object
references or claim cleanup from NotFound. Complete public capture/restore/delete,
rotated target/public execution IDs, guest retained-ID/event/cancel bindings, actual
profile probing and public KVM recovery/collection acceptance are still required.
Rootfs/volume snapshots, templates, combined M4 and complete M5-M6 remain required.
