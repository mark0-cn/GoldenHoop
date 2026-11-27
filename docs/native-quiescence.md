# Private guest quiescence

The protocol2 barrier is accepted at `376328c`: the actual KVM gate passes52
groups, verifies365 source inputs and confirms Complete collection. The newer
protocol3 generation scope and authority transition require their own real gate.
This prerequisite does not implement snapshot creation, restore, templates or a
public snapshot capability.
The complete M0-M6 scope remains in [roadmap.md](roadmap.md).

## Control and task accounting

Guest PID1 serves the reserved host-CID2 vsock endpoint. Its private protocol3
provides `quiesce`, `barrier_status` and `thaw`; every operation carries the exact
current generation and a non-nil barrier UUID. The original Info request retains
its wire shape. Host `AgentClient` checks the control version and guest identity
before sending a barrier request and validates the returned observation.

The guest task tree is:

```
goldenhoop/                 pids.max = configured aggregate ceiling
  control/                 PID1 and trusted control
  workloads/               agent and all workload descendants
```

The parent has no processes. Limits cover both children, including trusted
userland. PID1 freezes only `workloads`; its control endpoint remains runnable.
No unprivileged task receives cgroup migration or control-socket authority.

## Acknowledgement conditions

Quiesce first closes workload request admission independently of its async
future. An accepted proxy request retains a read guard through the complete
agent reply. A writer guard drains these effects before freezing the agent and
all background jobs. Requests that have not acquired admission refuse with
InvalidState; they cannot begin later merely because the source thaws.

After writing the freezer request, PID1 waits for actual `cgroup.events`
`frozen=1`, checks its own and the agent's task-group membership, synchronizes
the root filesystem with checked `syncfs`, and observes freezing again. Only
then does it return Quiesced with both `workload_frozen` and `rootfs_synced` true.
The synchronous sync needs no additional task when the guest task budget is
full. A stalled sync produces no success acknowledgement. Tmpfs state belongs
to a future memory capture; this is not a volume-snapshot implementation.

An agent request sent without a complete valid reply remains uncertain when
its future/socket disappears. That fence survives subsequent source thaw and
successful unrelated requests for this guest's lifetime. A future barrier
cannot call it drained. Cancellation before dispatch does not create this
uncertainty. Drain and freezer timeouts preserve closed admission and an
unconfirmed barrier rather than automatically resume workloads.

Same-barrier retries can finish an interrupted quiesce. Status samples actual
freezer state and invalidates a completed observation if it drifts. Thaw first
invalidates capture state, confirms `frozen=0`, and only then reopens admission.
Repeated thaw is idempotent; a resumed identifier cannot start another capture.
The guest retains up to 128 barrier identifiers and refuses exhaustion instead
of forgetting spent authority. Another active/unknown barrier cannot be replaced.

## Evidence and remaining authority work

Local admission tests exercise actual asynchronous guards, cancellation,
unconfirmed dispatch and completed replies. Wire tests reject wrong identities
and inconsistent observations. These tests do not observe a guest freezer.

The accepted native host configuration uses GNU/Linux. Musl builds the static
guest components; its descriptor/wire/init tests are separate checks. A broader
musl-host root-recovery test remains Failed: Rust 1.100's metadata birthtime
support is GNU-only on Linux, and the existing inode receipt refuses without
that observation. No weaker receipt is substituted. Full native root/recovery
contracts continue to run on the GNU/Linux host, with the limitation documented
by the [Rust source](https://github.com/rust-lang/rust/blob/0ef1bc386059596dada8fb65b50425aab2ea637a/library/std/src/sys/fs/unix.rs).

The [KVM workflow](../.github/workflows/firecracker-guest-barrier.yml) retains
root47 and adds actual guest task-group observations; wrong-identity health
checks; a running atomic-replace counter; concurrent file write versus capture;
read-only debugfs observations of the exact VM-owned disk; continued PID1
responses; refusal of new workload effects; real VMM pause/resume and explicit
thaw of the same command. Its existing Rust lifecycle owns final VM collection.
No host filesystem mount substitutes for these observations.

Generation authority initially comes from guest boot identity. Protocol3 adds
an explicit frozen [guest authority transition](native-authority.md); its new
real protocol gate is still required. A barrier observation is not durable host
capture/restore authority and does not permit loading memory into another
generation. The host still needs durable
capture intent and object ownership, independent memory/state/disk verification,
source termination and a single-use restore claim before transferring guest
authority and admitting target workload RPC. Those requirements remain in
[native snapshots](native-snapshots.md).

The implementation follows the kernel's
[cgroup freezer contract](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)
and checked [syncfs semantics](https://man7.org/linux/man-pages/man2/syncfs.2.html).
Firecracker's pinned [snapshot constraints](https://github.com/firecracker-microvm/firecracker/blob/eaf83bb718a559d324613d566eaf776b31a62340/docs/snapshotting/snapshot-support.md)
continue to govern subsequent checkpoint/restore work.
