# Private checkpoint content admission

The Rust `checkpoint` module verifies a pinned manifest and materializes three
independent read-only anonymous files. It is a content prerequisite for native
capture and restore. It does not call the snapshot API, publish durable objects,
observe source termination, reserve shared capacity or authorize a restore.

The versioned manifest binds installation, sandbox, source generation, capture
operation and original request digest; the completed protocol3 barrier; resource
limits; exact Firecracker, jailer, kernel, architecture and host compatibility
digests; and separate state, memory and disk object identities, hashes and lengths.
Its domain-separated reference hashes the typed manifest serialization. The
caller must retain that reference in trusted metadata. Editing a manifest and
minting a new reference cannot substitute for an existing trusted reference.

Admission requires the exact expected runtime and the caller's previously
reserved logical byte budget. The current private format supports the implemented
x86_64/Firecracker1.18 profile, a full memory file matching configured guest RAM,
a bounded state file and one bounded root drive. It refuses incomplete barriers,
aliased object identities, unsupported layouts and excess bytes. These checks
do not independently observe any guest, CPU, VMM or capacity reservation.

Linux materialization accepts descriptors rather than source paths. The caller
authenticates their producer or immutable store before passing them here. Each
input must be a regular file with the explicitly expected UID, no untrusted write
mode and at most one link; source roles must have distinct inodes. File identity,
length, ownership, link count and change/modification times are checked before
and after copying. Hashes and exact lengths are verified while copying and by a
second read of each output. The entire set succeeds before any descriptor is
returned. A live file descriptor is sufficient; its original pathname and
producer need not still exist. That is content availability, not absence proof
for a previous producer or source VMM.

Staging requires an existing canonical private root-owned host directory with
trusted ancestry on supported local disk storage. A pinned directory descriptor
selects `O_TMPFILE` output creation. There is no named-partial or remote-filesystem
fallback. Copies preserve sparse zeros and use bounded dirty/cache windows.
Outputs have independent inodes and offsets, mode0400 and read-only descriptors;
the module drops its write descriptors before returning. Any error drops all
partial anonymous outputs. Nothing is published to a pathname, and kernel file
lifetime follows the returned descriptors. Shared quota accounting and durable
publication remain the future coordinator's responsibility.

Portable tests exercise pinned-reference substitution, strict nested decoding,
exact compatibility, incomplete barriers and byte bounds. Linux-root tests use
actual sparse 128MiB memory/64MiB disk inputs: they delete source paths, verify
independent copied bytes and write refusal, observe descriptor closure in an
isolated child, and verify no anonymous descriptors or named partials remain
after corruption, truncation, UID, symlink, permission and budget refusals.
Their manifest/guest provenance is synthetic; no KVM capture or restore is
accepted by these filesystem tests.

Initial335-source full checks pass Windows290 and Linux-root390 executions
(including the isolated child). These precede the separate private-boot identity
correction discovered by actual protocol3 gate46019365079. Fresh final full
checks also pass Windows290/Linux-root390 on corrected335-source bytes, along
with musl21 descriptor/control/init tests, strict clippy and4 static release
binaries. All3 owned local check images are collected and their absence verified.
Historical reports remain unchanged. See the
[implementation summary](evidence/m4-checkpoint-content-implementation-summary.json).

The [remaining snapshot contract](native-snapshots.md) still requires actual
paused capture, durable owned content/manifests and quota, unique restore claims,
confirmed source collection, fresh target load and authority transition, public
integration, rootfs/volume snapshots, templates and combined M4 acceptance.
M5 and M6 remain unchanged.
