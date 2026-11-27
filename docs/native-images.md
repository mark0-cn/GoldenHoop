# Prepared images on the native profile

The private Ready-image resolver/materializer is accepted at `a4587f9`: the
actual default-runsc pipeline passes ten groups with Complete collection and
329 verified inputs. [Raw archive](evidence/m4-image-prepare-45990105658-archive.json).
The native selection path is accepted at `376328c`: its actual public/KVM gate
passes53 groups with366 verified inputs and Complete collection. This does not
accept subsequent protocol3 changes or complete M4. Snapshots, restore, templates
and M5-M6 retain their original requirements.

The first public placement run at `c4b8d87` failed while compiling static musl
guest components, before runtime execution. Its zero-case build artifact is not
placement acceptance. The [ABI diagnosis](evidence/m4-native-image-input-musl-diagnosis.json)
records the pinned nix comparison and retained failure. The correction normalizes
libc ancillary lengths and filesystem integer types across GNU and musl targets;
the corrected source passes [run46009592844](https://github.com/mark0-cn/GoldenHoop/actions/runs/46009592844).
See the [placement acceptance summary](evidence/m4-native-image-placement-acceptance-summary.json).

## Administrator policy

`DriverConfig.prepared_images` is optional. Without it, the original fixed-image
configuration and request path remain in use. With it, the administrator supplies:

| Field | Meaning |
| --- | --- |
| `inventory` | Exact `BuilderInventory` from the pinned trusted converter image: agent, init, conversion tools and builder version. Never copy policy from a job's self-reported payload or a workload request. |
| `max_disk_bytes` | Per-image logical size, 64 MiB through 16 GiB, aligned to 4096 bytes. |
| `disk_budget_bytes` | Sum of initial logical disk sizes of every uncollected native generation, including fixed-image VMs and uncertain reservations. |
| `staging_root` | Existing root-owned mode0700 directory, trusted ancestry, on an administrator-provisioned tmpfs. |
| `staging_bytes` | Upper bound for the actual tmpfs size, at least one maximum disk. The driver samples the actual filesystem and reserves this memory once in host capacity. |
| `allow_runc_development` | Explicit opt-in to consuming a development-converter job; false by default. No weaker-runtime fallback. |

The kernel tmpfs bound covers simultaneous private copies across workers and
continues to apply when a manager dies. The service observes this mount; it does
not create, detach or recursively collect administrator mounts. `staging_bytes`
is additional to guest, supervisor and manager memory reservations. Source-blob
storage and the VM's persistent writable disk remain separate resources.

## Public create and private handoff

The existing REST, Rust SDK, Python SDK and CLI `image` string carries the
canonical `prepared:<job UUID>:<generation UUID>:<manifest SHA256>` reference.
Clients supply that logical reference. Host paths, private blob references,
storage credentials and Docker access are absent from the workload request.

The worker resolves an exact Ready job, checks the administrator's pinned guest
contract and materializes a verified independent file. Shared permanent inode
locks permit concurrent Ready readers while excluding producers and collectors.
An unready, collected or changed image refuses that create before native RPC;
it does not become an Unknown reservation that starts later when the image changes.
Provider/storage interruptions keep their existing distinct error semantics.

The authenticated root Unix exchange first acknowledges descriptor readiness,
then receives exactly one `SCM_RIGHTS` file with atomic `MSG_CMSG_CLOEXEC`.
Malformed, extra and truncated rights are closed. Ordinary buffered JSON reads
never consume the descriptor byte. The manager verifies file ownership, type,
unlinked state, actual staging filesystem, length and content. At most two
blocking verifiers run concurrently; hashing does not block the manager event
loop or hold the installation admission mutex.

The supervisor inherits only a dedicated input descriptor, immediately restores
CLOEXEC and closes the original inherited slot. It independently verifies the
input, acknowledges its actual VM-root receipt and copies the disk into its own
jail. Existing bounded-cache file transfer verifies both the copied bytes and
the actual destination. The input closes before the VMM starts. No source disk
descriptor or host credential is intentionally inherited by a workload.

## Recovery and collection

Each native journal retains the selected immutable manifest/reference, fixed
hypervisor/jailer/kernel/supervisor artifacts and expected VM-owned disk path.
Recovery authenticates that generation's original processes, root and cgroups.
It neither rereads current job availability nor hashes a running writable disk
against the initial image. Original blob collection is safe after the verified
independent copy has finished; existing VMs continue on their own disks.

A successful full native probe can record its configuration/boot/PID-namespace
context only after real create, command, file, pause/resume and confirmed
collection succeed. When a later probe fails solely for capacity, allocated no
generation, and actual KVM plus a live generation are freshly authenticated,
that exact-context receipt can establish support without allocating another VM.
No earlier receipt or no authenticated live VM means no such recovery. Other
probe failures remain unavailable.

The dedicated [placement workflow](../.github/workflows/firecracker-image-placement.yml)
retains the root47 suite, then prepares two real runsc disks and selects them
through public requests on one profile. It requires distinct guest markers,
input block release, wrong/unready/collected refusal, shared disk quota, actual
origin-blob deletion and same running/paused VM recovery after real manager and
worker SIGKILL without spare probe capacity. Until that immutable report passes,
these runtime paths remain unverified.

The descriptor protocol follows the Linux
[Unix socket](https://man7.org/linux/man-pages/man7/unix.7.html) and
[recvmsg](https://man7.org/linux/man-pages/man2/recvmsg.2.html) contracts and Tokio's
[raw socket readiness API](https://docs.rs/tokio/1.54.1/tokio/net/struct.UnixStream.html).
The earlier [pinned upstream review](evidence/m4-ready-materialization-upstream-review.json)
explains the OpenSandbox Ready/scope comparison and copy-based device-image baseline.
