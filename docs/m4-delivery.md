# M4 delivery and acceptance

M4 remains incomplete. The first increment adds Rust KVM-device observations and
private Firecracker control components. It does not register an available
Firecracker profile. Jailed guest boot, the shared public/client contract,
images, disk/memory snapshots and templates still require implementation and
actual supported-host acceptance. M0-M3 evidence remains in the unchanged
[roadmap](roadmap.md).

## Pinned upstream and control boundary

The initial API target is Firecracker v1.18.0 at
[eaf83bb718a559d324613d566eaf776b31a62340](https://github.com/firecracker-microvm/firecracker/tree/eaf83bb718a559d324613d566eaf776b31a62340).
Its [API schema](https://github.com/firecracker-microvm/firecracker/blob/eaf83bb718a559d324613d566eaf776b31a62340/src/firecracker/swagger/firecracker.yaml)
defines the instance states, machine/boot/root-drive/vsock configuration,
start/pause/resume and full snapshot interfaces used by the Rust client.
[Jailer constraints](https://github.com/firecracker-microvm/firecracker/blob/eaf83bb718a559d324613d566eaf776b31a62340/docs/jailer.md),
[vsock transport](https://github.com/firecracker-microvm/firecracker/blob/eaf83bb718a559d324613d566eaf776b31a62340/docs/vsock.md)
and [snapshot limits](https://github.com/firecracker-microvm/firecracker/blob/eaf83bb718a559d324613d566eaf776b31a62340/docs/snapshotting/snapshot-support.md)
are requirements for the following increments, not proof of GoldenHoop support.

`goldenhoop-firecracker probe-kvm` opens only the actual `/dev/kvm`, refuses a
symlink or non-character device, checks API version 12, and creates then drops an
empty VM descriptor. It never loads a module, changes permissions, starts a
guest, allocates guest RAM or selects another runtime. The JSON observation
always keeps `runtime_capabilities_verified=false`; exit 2 reports an unavailable
prerequisite. A successful empty-VM check does not establish a working sandbox.

The private API client verifies the socket type/owner and actual Linux
`SO_PEERCRED` PID/UID against the trusted lifecycle input. On the same connection
it checks the expected instance UUID, application and pinned VMM version before
sending any mutation. One bounded deadline covers connection, identity read,
request and complete response. Bodies are bounded to 64 KiB. Unknown states,
foreign peers/instances, malformed/oversized replies and incorrect success
statuses refuse confirmation. EOF cannot substitute for a successful response.

Results retain `NotSent`, explicit `Rejected` and `Uncertain` dispatch states.
Rejected/uncertain errors are not marked retryable, and the client never retries
or redirects an operation. Rejection is not proof of resource collection;
uncertain native changes will require inspection or fenced collection by the
future lifecycle owner. A 204 acknowledgement does not prove that a VM booted,
guest code completed, data was durably snapshotted or resources were collected.

Snapshot bindings keep state and memory files distinct and restore with
`resume_vm=false`. File paths are validated as unambiguous jailed paths, not
treated as trusted artifacts. Digests, ownership, compatibility and fresh restore
authority must be established by the remaining driver/storage work.

## Remaining increments

| Increment | Required behavior and evidence |
| --- | --- |
| Images and guest control | Verified kernel/rootfs/agent digests; Rust image preparation and guest init; private host-to-guest vsock; ordinary workload UID; no host/provider keys or daemon sockets; bounded large-artifact streaming. |
| Jailed VM lifecycle | Persist installation/sandbox/generation intent before launch; verified binary/process/start-time/UID identity; jailer, host cgroup resource limits and default-deny network; actual agent readiness; confirmed process/jail/cgroup/disk collection. |
| Public driver integration | Register implemented profiles only after actual probes; durable create/execute/file/delete, pause, absolute expiry and API/worker failure recovery; Rust/Python/CLI shared contract on actual KVM. |
| Disk and volume snapshots | Guest quiescence and durable disk state; immutable versioned manifests and bounded content hashes; independent restored disks and volumes; verified corruption/incompatibility refusal. |
| Memory snapshots and restore | Actual paused full-memory capture and restore; CPU/VMM/kernel compatibility; retain workload state while rotating runtime/control/network identities before untrusted execution; old leases/transports cannot authorize the clone. |
| Templates | Immutable verified snapshot versions; new sandbox identities and admission/quota accounting for each allocation; physical separation and collected failed allocations. |
| Combined stage | Actual jailed KVM execution and snapshot/identity gates together with the retained runc/gVisor/network/S3 regression. Missing hardware, skipped gates or a healthy VMM process leave M4 unaccepted. |

The `Firecracker prerequisites` workflow checks the actual hosted Linux KVM
device with the same Rust probe. Its source-fingerprinted report is only a
prerequisite. Unix socket tests use controlled HTTP fixtures and cannot accept
the hardware backend. The complete M0-M6 objective remains in scope.

## Verified first component increment

[Windows validation](evidence/m4-kvm-api-component-validation-windows.json) passes format, strict workspace/all-target Clippy and all 267 Rust tests. [Linux validation](evidence/m4-kvm-api-component-validation-linux.json) passes the same checks and all 295 Rust tests, including six actual Unix socket transport groups. The five shared new tests cover wire shapes, refused paths/CIDs/resources/states and actual host/CLI observations. Socket fixture directories are positively collected by the tests. Linux uses a cache-only build, with no service containers or image tags. The [pinned upstream comparison](evidence/m4-firecracker-upstream-comparison.json) records source hashes and the future VMM release digest. None of these checks establishes actual jailed guest support.
