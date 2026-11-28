# Private guest rootfs freeze and thaw

This candidate implements a filesystem barrier for the next M4 rootfs capture
path. Actual KVM acceptance is pending. It does not yet implement the Rust rootfs
capture/store coordinator, fresh cold boot, public snapshot operations, volume
snapshots or templates. Those requirements remain in
[native-rootfs-templates.md](native-rootfs-templates.md) and [roadmap.md](roadmap.md).

The existing version3 private control endpoint adds `rootfs_quiesce`,
`rootfs_status` and `rootfs_thaw`, each binding the current guest generation and
one barrier ID. A distinct format1 receipt contains the phase, observed workload
freezer state, filesystem dispatch/acknowledgement state, original ext4 root
device/inode/mount identity and a permanent thaw-started fence. It cannot decode
as the existing memory freeze/sync receipt. Existing Info and memory messages
retain their wire fields; older guests reject unsupported rootfs requests.

PID1 closes workload admission and drains accepted effects before freezing its
original agent/workload cgroup. It opens and retains a descriptor of its writable
ext4 root, verifies its device, root inode and mount ID, then invokes FIFREEZE.
Only a successful ioctl plus stable root identity and frozen workload group
permits Quiesced/Frozen. An exact retry observes the original freeze instead of
issuing a second ioctl. Rootfs and memory barriers share bounded spent-operation
history, and active barriers fence the other kind and authority transfer.

The filesystem state is explicit: NotDispatched, Frozen, Thawed or Unknown.
The handler records Unknown before any kernel dispatch. An ioctl error, EBUSY,
lost response or RPC timeout never establishes source recovery or collection.
A failed freeze cannot be adopted as someone else's successful freeze. Unknown
ownership keeps admission fenced and can require collection of the original VM.
Dropping a request, lock or file descriptor performs no implicit thaw.

Explicit thaw permanently closes capture for that barrier before effects. An
owned Frozen root must receive a successful FITHAW before workload thaw and
admission reopening. If a request is cancelled after filesystem thaw but before
workload thaw, an exact retry continues at the original later boundary. A
resumed/spent barrier cannot freeze again. A never-dispatched filesystem ioctl
can recover its earlier workload freeze without issuing an unowned FITHAW.

The host AgentClient retains its configured RPC deadline and records dispatch
uncertainty. A deadline does not cancel a kernel ioctl inside the guest. A slow
or unconfirmed operation is not acknowledged as complete; the future Rust
capture coordinator still needs durable owner/phase records and recovery.

The targeted KVM gate starts an actual asynchronous writer, checks ext4 recovery
flags before/after freeze, observes exact retry and foreign/cross-kind refusal,
pauses the original VMM and makes a separate sparse test copy through a pinned
source descriptor. It explicitly resumes/thaws the original guest, observes the
same running command advancing its counter, then sends only the copied disk to
the existing source-built runsc inspector. The isolated checker validates clean
ext4, exact pinned agent/init/config and the copied user counter; input bytes
remain unchanged. Lost freeze/thaw replies must reconcile the original operation.
The Python copy is test construction, not the future production Rust store.

The existing private guest-barrier workflow accepts `component=rootfs` and calls
the separate [KVM/rootfs workflow](../.github/workflows/firecracker-rootfs-barrier.yml).
Full retained backend regression belongs to final M4 acceptance. Focused checks
must not be reported as independent cold-boot or public snapshot support.

## Primary-source comparison

Linux v5.10.244 [UAPI](https://github.com/gregkh/linux/blob/v5.10.244/include/uapi/linux/fs.h#L178)
defines FIFREEZE/FITHAW with the native read/write ioctl encoding and an int
size. The implementation uses libc's architecture-aware encoder and public
fstatvfs flags, rather than assuming private statfs fields or GNU/musl request
types. The same kernel's [ext4 freeze](https://github.com/gregkh/linux/blob/v5.10.244/fs/ext4/super.c#L5401)
flushes the journal before clearing its recovery flag; the VFS supplies the
filesystem write barrier. Exact reviewed source hashes are retained in
[the source record](evidence/m4-rootfs-capture-upstream-source.json).

QEMU's [guest-agent freeze/thaw protocol](https://www.qemu.org/docs/master/interop/qemu-ga-ref.html#command-guest-fsfreeze-status)
separates filesystem freeze from status and explicit thaw, and notes that an
outside actor can invalidate a cached status. GoldenHoop pins the original
descriptor and operation, restricts these methods to the reserved host control
channel and preserves uncertainty. This is not a claim of QEMU's all-filesystem
coverage or its automatic error-thaw policy: the current candidate targets one
owned ext4 root, with explicit cleanup and future attached-volume work remaining.
