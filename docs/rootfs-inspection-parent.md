# Private durable Rust inspector parent

This is an implementation candidate. Actual runsc/producer-death acceptance is
pending. Rootfs cold boot, public snapshot operations, volumes/templates and
complete M4-M6 remain required by [roadmap.md](roadmap.md).

The optional `rootfs.inspector_image` pins an immutable daemon image ID. Missing
configuration returns UnsupportedCapability without dispatch. The private
`rootfs_validate` manager method binds the original source handle and capture
UUID, requires an acknowledged independent disk and source release, and uses
the disk store's original permanent exclusive mutex. It shares the installation's
single bounded capture worker. Client IPC does not own the producer or its I/O.

The rootfs record persists a separate inspector operation: immutable disk/boot
assets/config and inventory, inspector generation, daemon ID, host boot, original
producer PID/start time/PID namespace, one nonce, effect intent, acknowledged
container IDs, original host process/cgroup observation, and accepted result.
Optional absent fields preserve the existing format2 capture records. The
content manifest and memory checkpoint formats are unchanged.

The Rust parent uploads fixed-name trusted tar headers and the descriptor-bound
disk bytes into an owned volume through a never-started seeder. It checks the
original regular root-owned0400 disk, length, link count, exact content digest
and unchanged descriptor metadata. The host parses no ext4 data. The isolated
tool receives a read-only input volume and a separate output volume, without
host mounts, daemon sockets or host credentials. Only runsc executes inspection;
there is no weaker runtime fallback. The seeder is never executed.

Actual image/configuration, capabilities, mounts, networking, resource limits,
stdin and immutable object identity are checked before the one private newline
permit. HostGuard observes the actual PID/pidfd and effective host cgroup limits;
guest virtual cgroups are not evidence. The tool has a fixed1GiB/one-CPU/64-task
budget and one concurrent parent per manager. Deployment admission must account
for that additional bounded worker and its independent temporary disk copy.

An EOF or successful start is not completion. Ready requires actual zero exit,
bounded output, the pinned disk/agent/init/config/inventory report, internal tool
and staging collection, original host process/cgroup absence, exact container
absence and owned volume absence. Pending inspection blocks disk GC and quota
release. A failed acknowledged inspection can be collected without publishing
Ready. A self-reported tool result cannot replace the original host receipt.

Recovery acquires the original object lock and proves original producer absence
in the same host/provider context. It neither resends a permit nor starts a new
container under an earlier operation. A durably acknowledged result can survive
the producer and is accepted only after original resource collection. Output
which was not acknowledged before death is discarded, even if a tool finished.
Unacknowledged create effects remain Unconfirmed; a read-side absence is not
evidence that a delayed create has settled. Those cases retain their reservation.

The targeted gate keeps the existing actual Rust producer cases, then checks a
production-parent Ready result and an actual manager SIGKILL after host-bound
inspection authorization/result acknowledgement. It records the actual durable
cut, original immutable IDs/receipt/result, same-source continuation, provider
and host collection, and disk quota. The additional independent counter check
still uses a test fixture; it does not supply production parent execution.
Failure paths reconcile original operations and positively inspect the owned
provider resource set. Full retained backend regression stays at M4 acceptance.

Native identity tests hash their actual executable, including its debug data.
Full type/variable DWARF grew the test binary to231MB and exhausted a15-second
fixture cut before acknowledged capture, including in a serial retry. The
workspace test profile now retains file/line backtrace information, assertions
and overflow checks. The actual cut diagnostic measures68.5MB and7.643-second
readiness, and the focused16-test run again uses two threads with unchanged
timeouts/assertions. [The source review and measurements](evidence/m4-rootfs-inspector-parent-upstream-test-profile.json)
retain the failed attempts separately from final-source checks.
