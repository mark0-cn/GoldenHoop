# Private native capture and persistent content

The Rust Machine capture path and local checkpoint store are implemented. At47ac2cc, final
formatting, strict all-target workspace clippy and full tests pass Windows290 /
Linux-root394 executions on the same339 source inputs. Musl21 scoped tests,
strict clippy and4 static guest release builds also pass. The4 targeted GNU-root
storage tests use synthetic guest provenance and actual filesystem/process effects.
All3 successful local check images are collected with positive absence; both
earlier failed image tags are absent, with original failed reports retained. See
the [implementation summary](evidence/m4-checkpoint-capture-implementation-summary.json).
The [actual KVM capture gate46036731540](https://github.com/mark0-cn/GoldenHoop/actions/runs/46036731540)
passes60 groups/377 source inputs with Complete collection at47ac2cc. Its
[acceptance summary](evidence/m4-checkpoint-capture-acceptance-summary.json)
retains the immutable raw evidence. This is private capture infrastructure, not
public snapshot/restore support, a restore claim or a template implementation.
The earlier protocol3 same-VMM authority gate passes55 groups/371 inputs with
Complete collection at6c32d1a; that report does not accept these newer sources.

The newer [manager integration](native-managed-checkpoints.md) passes full
Windows290/GNU-root397 checks and musl21/static4 on340 identical source inputs.
Its separate actual managed-capture gate remains required.

## Capture boundary

The caller owns the actual Machine and supplies a trusted private store policy.
The store first reserves an immutable capture intent. The guest control identity
and task ceiling must match that VMM. PID1 closes and drains effects, freezes the
workload group and syncs the drive before the host pauses the actual VMM. Both
the barrier and the observed Paused state are required.

Full snapshot creation uses fresh state/memory names inside the source jail;
occupied or unconfirmed names refuse before API dispatch. `sync_snapshot_files`
is explicitly true. The actual paused VMM acknowledges creation before state,
memory and drive descriptors are opened and their ownership, regular-file type,
link count, lengths and hashes checked. The source must still be paused before
the independently verified anonymous copies are published outside its root.
There is no source resume, automatic thaw or capture-dispatch replay on failure.

Only the private probe creates a random32-byte token inside a live guest process,
observes its stdout, and checks that the captured RAM contains those bytes. A
separate file payload allows physical copied-drive inspection. These are capture
oracles; production capture has no marker command/file writes. Retained process
continuation requires a separate fresh-VMM restore test.

## Persistent identity and publication

The store root has a persistent inode/birth-time receipt, installation and nonce.
Its quota-lock inode is pinned by a second complete initialization receipt. A
missing initializer acknowledgement, replaced directory or replaced mutex never
causes adoption or deletion. Supported local disk filesystems and trusted root
ancestry are required. Root initialization interrupted before acknowledgement
remains unconfirmed; it is not silently repaired by treating an occupied folder
as an empty store.

Each capture has a permanent kernel mutex bound to its complete intent digest,
and a separate durable record. Before any content acquires a name, all three
anonymous output inode receipts are durably declared. The receipts bind store,
capture, role, manifest reference, content digest/length and exact inode/birth.
Files are linked without overwrite, synced and read back independently. The
atomic Ready record is the final publication point. Readers reject every other
phase and check the exact reference, receipts and complete content.

Ready bytes do not require a live producer, source pathname or source jail. A
reader uses a shared capture lease, and releases the global quota mutex before
hashing. Publication and deletion use the exclusive capture lease. Content is
mode0400 and handled through read-only descriptors. The store does not lend a
mutable backing file to a workload or publish a weaker runtime capability.

## Reservation and collection

Capture reserves two copies of configured guest RAM and the maximum state-file
bound, plus one independent drive copy. This charges both raw source outputs and
the retained copies, using logical lengths even for sparse files. Active jobs
share the configured byte/count limit. Capacity remains reserved through failures
and unknown writes. Permanent locks and collected-operation history remain as
coordination metadata; history is bounded by refusal rather than identifier reuse.
Within this store, the same source generation or original VMM process cannot
mint a second continuation capture.

Mutation recovery records the producer process and the original VMM writer in
their observed host boot/PID namespace. A different observer context does not
prove either old process stopped. An unacknowledged interrupted producer must
actually be absent. Ready publication or a positively settled failure acknowledges
that producer's own writes have finished. Collection
still requires the original VMM writer and its exact source-root pathname to be
absent under the unchanged trusted parent. Stopping a PID while raw capture files
remain in its jail does not release the reservation.

Collection first persists revocation, then removes only the exact acknowledged
object inodes and receipts. Missing owned objects are observed absent; replaced,
unacknowledged or symlink entries are preserved. Corrupt bytes in an otherwise
owned inode can be collected without repairing the artifact. Only observed
absence permits the terminal Collected state and quota release. Capture outcome
and resource phase are separate: collecting an interrupted capture does not turn
it into a successful capture.

## Scope still required

The optional `probe-guest --checkpoint-config` and private `checkpoint-inspect` /
`checkpoint-collect` commands exercise this implementation. The new private
[manager jobs](native-managed-checkpoints.md) integrate capture and shared host
memory admission, with their own hardware gate still required. Public API
integration, durable unique restore claims, source/target orchestration,
fresh paused target load, public continuation semantics, rootfs/volume snapshots,
templates and combined M4 acceptance remain required. M5 and M6 are unchanged.

GNU-root tests use synthetic guest metadata with actual files, source-process
absence, producer SIGSTOP/SIGKILL and foreign-object refusal. They do not accept
KVM capture. The separate real capture workflow at47ac2cc verifies actual
RAM/drive contents after source collection, exact object collection and quota
observations. That accepted source does not grant acceptance to newer manager code.
