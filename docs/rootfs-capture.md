# Private Rust rootfs capture coordinator

This candidate connects the original-generation guest filesystem barrier to the
Rust independent disk-content store through the native manager. It is not yet
accepted by an actual KVM run. Public rootfs snapshots, product isolated-inspector
transport, fresh cold boots, volume snapshots, immutable templates and the
remaining M4-M6 objectives remain required in [roadmap.md](roadmap.md) and
[native-rootfs-templates.md](native-rootfs-templates.md).

The operator config optionally pins `rootfs` capture policy: its store budget,
protected guest configuration, expected guest settings and inspector inventory.
The private root-only manager methods are `rootfs_capture`, `rootfs_inspect` and
`rootfs_collect`, each bound to the original RuntimeHandle and capture UUID.
They do not register a public runtime snapshot capability. Disabled policy is
serialized without a new field, preserving existing configuration fingerprints.

## Original source and producer

The manager takes the original per-VM lease and the installation's bounded
capture slot before reserving content. Its persistent supervisor owns a separate
`rootfs_hold`; the existing permanent memory `capture_hold` is unchanged.
Ordinary pause, resume, workload dispatch and another capture kind cannot bypass
an active rootfs operation, including after manager death. Independent supervisor
expiry/collection remains available. Client IPC never owns the background
producer, source lease or capture slot.

Before guest/VMM mutation the store reserves the immutable capture intent,
original VMM/producer identities and original source disk device/inode/birth time,
UID and length. The private store record is now format2; the rootfs content
manifest stays format1. Unbound old private records are refused, not silently
adopted. The caller also verifies the existing original VM-root receipt and
opens its fixed jailed disk without following the final symlink.

The Rust coordinator closes/drains/freezes the guest through the reserved host
control channel, observes the original filesystem receipt, pauses that VMM and
requires an actual Paused response. It then invokes the descriptor-bound sparse
producer and verifies that the same VMM is still paused after publication.
There are no production workload markers or retained RAM/state objects.

Captured or Failed is durable before any recovery attempt. The original VMM is
explicitly resumed, the original guest barrier is explicitly thawed, and the
coordinator observes the same generation/limits and a successful agent ping.
The guest receipt must remain Resumed/Thawed. Only the acknowledged original
source receipt permits the supervisor to release that exact rootfs hold.
Source recovery and host producer I/O settlement are separate acknowledgements.
Pause dispatch and its positive Paused observation are durable before copying;
resume intent is durable only after capture is closed. A Running observation
does not settle a possibly delayed pause. An unconfirmed earlier resume is not
silently sent again. Ambiguous VMM control retains the original source fence.

## Recovery and collection

On producer death, reconciliation acquires the original persistent object mutex
and confirms old producer absence in the same observer context. A published
verified disk is retained. An incomplete capture becomes Failed and never starts
another copy or guest freeze under that ID. Reconciliation recovers the same
source VM/supervisor and operation rather than launching a replacement.

An explicit thaw for an unused operation can permanently spend that ID with a
NotDispatched receipt. It performs neither a filesystem nor workload thaw, and
requires open, certain admission with an unfrozen workload group. It cannot
adopt another active/spent barrier. Delayed quiesce for that ID is refused.
An earlier unconfirmed agent effect still fences recovery. Unknown kernel freeze
ownership never authorizes FITHAW or successful source recovery.

A live source with an unacknowledged supervisor release blocks ordinary
collection. Failed source recovery does not mean producer I/O is still running:
once synchronous disk work has ended, it can be recorded settled while source
recovery remains unknown. Independent disk GC still requires source recovery or
positive original VMM absence, as well as exact object ownership and absence.
This permits eventual cleanup after source expiry without requiring a healthy
manager process to die. A spent ID remains closed after collection.

## Gates

Focused checks exercise real files/processes, source inode substitution, original
producer cuts, dead-source GC and supervisor rejection before runtime dispatch.
The targeted actual KVM gate uses an asynchronous guest writer, kills the actual
manager producer at Capturing, reconciles the same supervisor/VMM, and performs a
new complete Rust capture. The independent published disk is then inspected
inside actual runsc, with pinned agent/init/config and copied counter data, while
the original source continues. That inspector parent is explicitly test code;
it does not implement the product's durable Rust inspection transport.

Full static CI runs on the frozen source. Full retained backend regression is
reserved for final M4 acceptance; narrow checks are not cold-boot, template or
public-operation acceptance.

The pinned Firecracker v1.18.0
[API dispatcher](https://github.com/firecracker-microvm/firecracker/blob/v1.18.0/src/firecracker/src/api_server/mod.rs)
waits for each accepted VMM action's result. This is useful ordering after an
accepted request; it does not prove that a disconnected or timed-out request
was accepted or completed. GoldenHoop therefore retains explicit control intent
and observations rather than treating a fresh Running response as no dispatch.
Reviewed source hashes are retained in the upstream evidence record.
