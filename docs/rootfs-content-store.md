# Private independent rootfs content

The Rust `rootfs` module implements a separate format1 ext4 manifest and local
disk-content producer/store. This candidate has not yet been connected to the
native manager's capture coordinator, actual isolated inspection transport,
fresh cold boots, or public REST/SDK/CLI operations. It grants no public rootfs
capability. The complete requirements in
[native-rootfs-templates.md](native-rootfs-templates.md) and [roadmap.md](roadmap.md)
remain required, including volumes, immutable templates, remaining memory
coverage and final M4 acceptance, followed by M5-M6.

## Content and capture ownership

An immutable intent binds installation, source sandbox and generation, capture
and request digest, original image provenance, independent disk object ID and
logical reservation, exact boot executables/kernel, guest control ABI, protected
agent/init/config bytes and expected guest settings. It also pins a separate
inspection generation and inspector inventory fingerprint before effects.
Rootfs references use their own digest domain. Memory state/RAM objects, retained
execution IDs and memory host-CPU compatibility are absent from this schema;
strict decoding refuses substitution between the two manifest kinds.

Reservation persists the exact intent, original VMM identity and producer
identity before capture can begin. Both processes bind boot ID, host PID/start
ticks, executable digest and observer PID namespace. Store, quota mutex, capture
mutex and disk ownership bind original inode identities, including birth time.
Roots require protected canonical root-owned ancestry, a private directory and
supported local disk storage. A foreign installation, replaced mutex or occupied
unmarked directory is refused; it is never adopted by filename.

The caller must hold the original VM operation lease and positively establish
the [guest filesystem barrier](guest-rootfs-barrier.md) and VMM pause. The store
does not infer either condition from a process or pathname. After the original
frozen receipt is saved, the Rust producer checks the source descriptor's owner,
type, link count, length and change stamps. It hashes at a bounded logical
length, copies nonzero regions into an unnamed independent sparse inode, syncs
and hashes the readback, then checks the source stamps and original VMM again.
No host ext4 mount or filesystem parser participates in this byte transfer.

The complete disk inode/content receipt is durable in Publishing before linkat
gives the read-only inode a name. Publication refuses replacement. A lost reply
or dead producer is reconciled through the original mutex and receipt. A named
verified inode can advance to Captured; an unnamed inode lost on process death
becomes Failed, retaining its reservation. Recovery never repeats guest freeze,
thaws a source, changes capture identity, or opens admission implicitly.

## Readiness, readers and collection

Captured is not Ready. The store separately requires the original generation's
explicit Resumed/Thawed receipt and a successful isolated inspector report with
collected tools/staging, exact copied disk, protected boot assets, guest config
and pre-pinned inspector inventory. The owning coordinator must authenticate
these observations and retain the session until its inspector's original host
process and cgroup are positively collected. The current store does not provide
that transport/host-process orchestration.

Readers take the original capture mutex in shared mode, validate their trusted
manifest/boot policy and rehash the owned disk. Keep the whole read lease until
independent materialization is complete. A raw descriptor is not a durable
runtime/template reference; those reference tables and publication/deletion
rules remain required before public support.

Collection takes the original mutex exclusively. A live unsettled producer or
unrecovered live source retains its reservation. Explicit source recovery can
allow deletion while that source continues running; unlike memory checkpoint
collection, source termination is not the normal successful capture path.
Unacknowledged/replaced disk objects are preserved, and uncertain inventory
blocks new admission. Only positive independent-object absence allows the
Collected tombstone and quota release. A spent capture ID cannot be reused.
This is independent disk collection, not proof of source VM/jail/cgroup cleanup.

## Validation scope

Focused Linux tests use actual owned files, processes, sparse copies, locks and
SIGKILL recovery, including cuts before and after disk naming. Guest freeze/thaw
and inspector receipts in these tests are explicitly synthetic. They do not
prove actual KVM capture, runsc orchestration, cold boot or public operation
support. Those gates must exercise the integrated Rust coordinator later.

## Upstream comparison

At containerd revision `0e1fb1bf00c3e690e13e2447cd034db9ed4f96fb`, its
[content writer](https://github.com/containerd/containerd/blob/0e1fb1bf00c3e690e13e2447cd034db9ed4f96fb/plugins/content/local/writer.go)
syncs and checks size/digest before committing content. Closing an ingest keeps
it resumable; abandoning it uses a separate operation. These are useful
persistence boundaries, not a claim that containerd supplies GoldenHoop's guest
barrier, source recovery or inode/producer receipts. Reviewed source hashes are
retained in [the source record](evidence/m4-rootfs-store-upstream-source.json).

Linux [O_TMPFILE and linkat semantics](https://man7.org/linux/man-pages/man2/open.2.html)
support filling and setting inode attributes before giving the file a name;
unnamed content disappears when its final descriptor closes. GoldenHoop uses
this only for owned local output, with separate synced publication metadata and
explicit named-object collection.
