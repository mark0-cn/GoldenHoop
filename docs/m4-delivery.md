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

## Native query failure and zero-argument correction

The [first actual KVM gate](evidence/m4-native-45859682866-archive.json) failed on immutable dcfdbe2. Its root process opened the fixed character device but GET_API_VERSION returned a negative result, so no numeric API version was observed; its errno was not recorded. The process and its descriptors were collected. This remains a failed prerequisite.

The [pinned Rust VMM/Linux comparison](evidence/m4-kvm-ioctl-zero-argument-upstream-diagnosis.json) identifies an interface error: the original variadic libc ioctl call omitted its third argument. Linux requires a zero argument for GET_API_VERSION; the Rust VMM helper supplies it explicitly. The corrected call supplies zero, records errno for failed queries/creation and distinguishes a failed syscall from a numeric unsupported API. An actual /dev/null control verifies ENOTTY and no claimed API version. The original native errno is unknown; the correction still requires a new actual KVM gate.

[Windows checks](evidence/m4-kvm-ioctl-zero-argument-validation-windows.json) pass all 267 tests plus format/strict workspace-all-target lint. [Linux checks](evidence/m4-kvm-ioctl-zero-argument-validation-linux.json) pass all 296 tests and the same checks. No device, permission, module or capability requirement is relaxed. Jailed guest acceptance remains required.

## Actual KVM prerequisite accepted

The corrected [native run 45862682399](https://github.com/mark0-cn/GoldenHoop/actions/runs/45862682399) at 0e026e0d3ca39dddbd7436f4ba827f0fc9731cde passes both prerequisite groups. Its [archive](evidence/m4-native-45862682399-archive.json) verifies all 21 source inputs against that immutable commit, records actual API 12 with no errno and confirms collection of the empty VM descriptor/child. The [summary](evidence/m4-control-kvm-prerequisite-summary.json) retains the first failed run, all current source-bound results and the explicit guest/runtime limitations. [Portable CI 45862561992](https://github.com/mark0-cn/GoldenHoop/actions/runs/45862561992) passes both platforms.

This is a positive hardware prerequisite on the tested hosted Linux machine. No guest started, no jailed driver/profile was published, and M4 remains incomplete under the remaining increments above.

## Guest bootstrap implementation, pending hardware acceptance

The next component adds Rust PID1 guest initialization and host-to-guest vsock
transport while reusing the existing Rust agent. Guest init refuses ordinary
host processes before mounting anything. Inside the guest it mounts private
filesystems, enables loopback, disables new user namespaces, applies no-new-privileges,
bounds the agent/workload process tree to 256 tasks and reaps adopted children.
Only host CID2 may reach the reserved control port. Control frames and concurrent
connections are bounded; unavailable vsock has no alternate transport.

The private `probe-guest` path verifies root-owned image/tool ancestors and
streams digest-checked copies with 64 KiB buffers. It persists a generation
intent before launch, uses a separately configured cgroup v2 leaf, runs the
matching pinned jailer with a private PID/network namespace and tracks the actual
VMM through executable digest, UID, parent, start time, boot ID, generation,
cgroup and pidfd. A PID file alone never grants signaling authority. Guest disks
use an owned short path on `/var/lib`, avoiding the host's small `/run` tmpfs.
An API or process acknowledgement does not establish guest readiness.

The [pinned artifacts](../images/microvm/upstream.json) identify Firecracker
v1.18.0 and the exact official Linux 6.18.62 guest kernel/configuration. The
[upstream comparison](evidence/m4-guest-bootstrap-upstream-comparison.json)
records the applied jailer/vsock contracts and exact Tokio/libc source inputs.
The initial static build failed after GNU tests passed because libc's ioctl
request type differs on GNU and musl; the
[failure evidence](evidence/m4-guest-bootstrap-component-validation-linux-failed-20261126T174857Z.json)
is retained. Fixed low loopback request numbers now use the target ABI type.

The manual `Firecracker guest bootstrap` workflow prepares a trusted offline ext4
test fixture from the `microvm-rootfs` image target. Its export container is
never executed. Actual Rust validation must reject a corrupt kernel digest,
boot a jailed hardware VM, obtain an authenticated guest reply, roundtrip a file,
execute a nonce command as UID1000 and confirm privilege/task/no-NIC constraints.
It must also confirm VMM reaping and jail/cgroup/disk collection on both branches.
The source-fingerprinted report preserves failures and Unknown collection.

This implementation does not register a public Firecracker driver/profile.
Current hardware acceptance still requires a successful immutable-candidate run.
Public lifecycle, expiry/recovery, disk and memory snapshots, restore identity,
templates and combined Stage acceptance above remain required for M4.

[Windows checks](evidence/m4-guest-bootstrap-component-validation-windows.json)
pass all 269 Rust tests plus format/strict workspace lint;
[Linux checks](evidence/m4-guest-bootstrap-component-validation-linux.json)
pass 302 tests and the static musl guest/rootfs build. The
[input review](evidence/m4-guest-bootstrap-local-input-review.json) verifies all
257 inputs on each platform and isolates the later build-only concurrency bound.
These portable/build results cannot accept the hardware gate.

## Actual guest boot failure and next correction

[Native run 45871959877](evidence/m4-native-45871959877-archive.json) verifies 47
source fingerprints at 1e02c67 and preserves the failed readiness result. The
console records kernel boot, mounted ext4/devtmpfs and Rust init entry, followed
by EBUSY. Its false guest_started flag means that the accepted agent-readiness
marker was never reached. Both the corrupt-digest refusal and failed boot confirm
owned collection. Portable CI 45871909422 succeeds on both platforms.

The [OpenRC/Linux diagnosis](evidence/m4-guest-devtmpfs-upstream-diagnosis.json)
retains uncertainty about the original generic error's exact operation. The
correction observes the existing kernel /dev mount, remounts it with verified
nosuid/noexec constraints, refuses foreign/ambiguous mounts and annotates every
initialization failure. An empty jailer PID-file observation now consumes only
the original readiness budget and cannot authorize signaling. Updated
[Windows](evidence/m4-guest-devtmpfs-validation-windows.json) and
[Linux](evidence/m4-guest-devtmpfs-validation-linux.json) format/strict full
workspace checks pass 269 and 309 tests respectively. A fresh actual guest run
is still required; none of the remaining M4 scope is removed.

## Actual private bootstrap accepted

The corrected [native run 45874469518](https://github.com/mark0-cn/GoldenHoop/actions/runs/45874469518)
at 36474ead1ff1a998c785cf4a9fa342e21e213179 passes six actual KVM bootstrap
groups. Its [archive](evidence/m4-native-45874469518-archive.json) verifies all
48 source inputs; the [summary](evidence/m4-guest-bootstrap-acceptance-summary.json)
records the original failed run, successful result, cleanup and remaining scope.
Portable CI 45874415952 passes Ubuntu and Windows.

The actual guest answers through authenticated private vsock, roundtrips a nonce
file and completes a UID1000 command with a verified stdout nonce and descendant
collection. The command confirms no-new-privileges, zero effective capabilities,
the 256-task group, only loopback, reserved-vsock binding refusal and absence of
the tested host/provider environment keys and Docker socket. Host observations
confirm VMM UID10000, private PID1/network namespaces, no-new-privileges, zero
effective capabilities and seccomp mode2. Both the negative artifact control and
positive execution confirm process/jail/cgroup/disk/fixture collection.

This is a private, fixed 1-vCPU/256-MiB bootstrap with an offline test-image
fixture. It does not register a public runtime capability or accept production
image preparation, configurable public lifecycle, expiry/recovery, snapshots or
templates. The full remaining-increments table and combined Stage gate still
apply. Snapshot work must keep its controller outside the frozen workload groups;
the current bootstrap groups agent and workload together. The
[pinned E2B freezer](https://github.com/e2b-dev/runtime/blob/86cb50338fe3bd73c10b13270aaa576b48f5d582/packages/envd/internal/services/cgroups/freeze.go)
provides a relevant separation pattern, while GoldenHoop's private vsock authority
and restore identity requirements still need their own implementation and gates.

## Durable native lifecycle implementation

The Rust `FirecrackerDriver` now implements `RuntimeDriver` and `AgentTransport`
behind a private root-only test interface. Durable installation/sandbox/generation
intent binds the original image, request, resources, host boot and absolute
expiry. A separate Rust supervisor retains the actual VMM handles and console
drain after the caller exits. It owns authenticated pause/resume and bounded
collection; the driver confirms process, jail, disk and cgroup absence before
releasing a reservation. Neither process launch nor an EOF accepts an operation.

CPU/memory reservations include explicit VMM/supervisor overhead. Guest PID
limits and generation identity come from validated boot arguments and actual
private guest control observations. This increment permits only the existing
offline/no-NIC policy and four implemented capabilities: commands, files, pause
and network isolation. A probe advertises them only after real guest work,
pause/resume and physical collection all succeed.

[Windows checks](evidence/m4-native-lifecycle-validation-windows.json) pass format,
strict full-workspace lint and 270 tests. [Linux checks](evidence/m4-native-lifecycle-validation-linux.json)
pass the same checks and 313 tests, then build the actual static musl guest
components and rootfs target. The [upstream comparison](evidence/m4-native-lifecycle-upstream-comparison.json)
records OpenSandbox's persisted expiry and per-sandbox lifecycle serialization,
and the Linux process/cgroup rules used by the independent helper.

The manual `Firecracker native lifecycle` workflow retains the accepted bootstrap
controls and adds same-intent reconnect, per-sandbox limits/disks, foreign-owner
refusal, caller SIGKILL recovery and paused absolute-expiry collection after the
original caller service group disappears. These new hardware paths are pending
at this implementation commit. No public Worker, API, SDK or CLI runtime profile
is registered. Production image preparation, public integration, snapshots,
restore identity, templates, combined M4 Stage and all M5-M6 work remain required.

## First lifecycle failure and public integration candidate

[Native run 45884238891](https://github.com/mark0-cn/GoldenHoop/actions/runs/45884238891)
at 899ed39 retains six passing bootstrap controls but fails the new native
lifecycle probe. Its [archive](evidence/m4-native-45884238891-archive.json) verifies
all 57 source fingerprints and preserves Failed with Complete collection. The
supervisor recorded its authenticated identity, but no accepted VMM or guest
readiness was recorded. Original stderr, exit status and resource event counters
were not retained, so the cause is unconfirmed. Subsequent code preserves bounded
private stderr, actual child exit status and cgroup resource events before
collection. Linux file-cache accounting is a diagnostic consideration, not a
proven explanation of this original failure.

The next candidate introduces the shared Worker backend interface and explicit
`worker --runtime docker|firecracker|both` selection. Docker remains the default.
Native modes require a root-owned `--firecracker-config` whose installation ID
matches the store; native-only startup does not connect to Docker. The public
registration uses the actual native lifecycle probe. Protected-network entry
points require an explicit Docker implementation; global Docker network settings
cannot grant those capabilities to the native no-NIC profile.

A separate manual public gate exercises the real Rust API/Worker, Python SDK and
Rust CLI, including command/file work, actual feature refusals, worker SIGKILL
recovery without command replay, pause/resume, retained artifacts and independent
paused expiry. Its private prerequisites must pass first. Both new native gates
remain unaccepted. Workspace checks remain mandatory in portable CI and phase
acceptance; hardware workflows now build only their required guest binaries
instead of rerunning all workspace checks inside every image build. The Docker
build default still runs all checks, and invalid validation flags are refused.

The [combined candidate review](evidence/m4-public-native-candidate-review.json)
verifies 264 inputs per platform against current format/strict workspace checks:
[Windows](evidence/m4-public-native-diagnostics-validation-windows.json) passes
270 tests and [Linux](evidence/m4-public-native-diagnostics-validation-linux.json)
passes 313 plus static musl guest/rootfs construction. These results establish
portable component validation only. The [first native failure diagnosis](evidence/m4-native-supervisor-failure-diagnosis.json)
preserves the missing telemetry and the requirement for a new hardware result.

## Persistent service parent

The [next native-public archive](evidence/m4-native-45887664380-archive.json)
retains six passing bootstrap groups and six new private groups at 6cc9a93,
followed by Failed/Unknown collection during a second VM removal. All 288
reported inputs are verified. The journal reached `vm_collected`, but the
original report did not identify every remaining process/path. Its exact
residual item is not reconstructed, and no public groups were reached.

The next implementation runs an explicit foreground installation service:

```sh
goldenhoop-firecracker manage --config /etc/goldenhoop/native.json
```

A service supervisor owns this process. The worker uses the same private
configuration through `--runtime firecracker --firecracker-config ...`; Docker
remains the default runtime selection. The persistent manager retains and reaps
each VM supervisor as its actual child after a worker or CLI exits. Private IPC
binds installation, configuration digest, epoch and real peer identity. The
manager reserves 768 MiB in host capacity, enforces its own CPU/memory/task
limits and bounds connections and heavy RPCs. Existing guest/VMM/supervisor
limits remain in force.

`manager-stop --config ...` only acknowledges a pending drain request. The
service parent waits for actual exit and verifies its cgroup, socket and marker
collection. The manager drains VM generations before exiting. Unclean restart
with uncollected generations is fenced pending service-parent recovery; it does
not infer collection from an exited nonchild. Actual fixtures now own this
foreground service and record individual residual observations. Two real Linux
process regressions plus the retained Firecracker checks pass 31 focused tests.
Portable full checks and a new actual KVM public gate remain required. Production
service packaging, image preparation, snapshots/restores/templates and full
M4-M6 acceptance are still outstanding.

[Windows validation](evidence/m4-native-manager-validation-windows.json) passes
270 tests; [Linux validation](evidence/m4-native-manager-validation-linux.json)
passes 315 plus static guest/rootfs construction. Both include format, strict
workspace/all-target lint and fingerprints of all 266 build inputs. These
portable results do not replace the corrected actual KVM gate.

## Manager frame exchange correction

The [ce12171 native-public archive](evidence/m4-native-45894594350-archive.json)
verifies all 291 inputs and retains Failed/Unknown collection. Its foreground
manager becomes ready, but no native generation is created and both probe and
stop IPC fail. The configured frame ceiling exceeds the common reader's 24-MiB
maximum, causing rejection before either endpoint reads a message.

The correction shares that exact ceiling and marks uncertain transport errors
nonretryable. A real Unix socket test roundtrips both a stop envelope and a valid
16-MiB file envelope with ownership-bound replies. Recovery refuses collection
while the actual owned supervisor is still preparing and skips a recorded PID
after positively observing its old identity gone. If stop IPC fails, the fixture
retains that failure while signaling only its actual child for graceful drainage;
physical collection remains an independent observation.

[Windows checks](evidence/m4-native-manager-frame-validation-windows.json) pass
270 tests and [Linux checks](evidence/m4-native-manager-frame-validation-linux.json)
pass 316, including the real socket regression, plus static musl guest/rootfs
construction. Both include format, strict workspace/all-target lint and all 266
input fingerprints. A new actual native-public gate remains required before
accepting this component. Image preparation, snapshots/restores/templates,
combined M4 and all M5-M6 deliverables remain outstanding.

## Independent expiry observation and large storage foundation

The [next native-public archive](evidence/m4-native-45897727960-archive.json)
verifies all 291 inputs at 01cce17. Six bootstrap and seven private groups pass,
including caller SIGKILL recovery, before a failed expiry assertion; final
collection is Complete. The original report lacks the assertion line, but it
records the paused VM's paths gone with its manager-owned supervisor still in
Z state. This actual intermediate observation must not be treated as absence or
used to reconstruct the prior run's unknown residual.

Both native expiry fixtures now wait for path and recorded-process absence
together, using their original deadlines and retaining bounded transitions and
precise failure sites. A replay of the captured Z observation confirms that the
joint check waits and still refuses an expired deadline. Corrected actual
hardware acceptance remains required.

The Rust [large artifact store](large-artifacts.md) provides bounded immutable
streaming for future image/snapshot objects. Local 25-MiB transfers and the
[18-group actual RustFS/S3 contract](evidence/m4-large-stream-s3-frozen-validation-windows.json)
pass, including interrupted unpublished uploads, same-generation resume,
independent versions and confirmed scoped collection. Full portable checks pass
[275 Windows tests](evidence/m4-large-stream-validation-windows.json) and
[321 Linux tests](evidence/m4-large-stream-validation-linux.json), plus strict
format/lint and static guest/rootfs construction. This component does not
implement image conversion, guest quiescence, snapshots, restore authority or
templates. Their implementation and all combined M4-M6 gates remain required.
