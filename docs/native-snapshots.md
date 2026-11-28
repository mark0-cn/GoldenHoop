# Native snapshots and restore: remaining implementation contract

This is the remaining M4 implementation contract. Private owned-Machine capture
and storage are accepted at47ac2cc (actual60 groups/377 inputs/Complete).
Native-manager capture64 and private fresh-VMM continuation pass the c7fbfce
70-group/384-input gate with Complete collection. The strengthened full/live
backing observer also passes70/384/Complete at9a77320, run46060867499, with
authenticated live VMM PID/start and full memory length.
The [private native manager restoration](native-managed-restoration.md) increment
adds durable target orchestration and typed collection reconciliation. Its
targeted native6/shared-guest6 gate passes12/90/Complete at0caa8a7. The independent
actual missing-writer cut also passes9/90/Complete at2f3a8a5, including a live VMM
unacknowledged by both native journal and store, original collection proof and
Closed/Unconfirmed with exact quota/GC and no relaunch.
Public native snapshot/restore/template execution and capability registration
remain unavailable. The [public operation foundation](public-snapshot-operations.md)
now persists capture intent, source fencing and immutable execution candidates;
The [worker bridge](snapshot-worker.md) now implements private source-serialized
admission, capture dispatch, inspection and failed-capture collection. The
[durable capture outcome increment](capture-outcomes.md) adds source-bound
pre-reservation refusal and late-producer fencing. Actual manager/worker KVM
refusal acceptance, public restoration/clients and full profile acceptance remain
required.
The complete M0-M6 objective in [roadmap.md](roadmap.md) is unchanged.

## Upstream constraints

The pinned Firecracker v1.18.0 revision is
`eaf83bb718a559d324613d566eaf776b31a62340`. Its
[snapshot contract](https://github.com/firecracker-microvm/firecracker/blob/eaf83bb718a559d324613d566eaf776b31a62340/docs/snapshotting/snapshot-support.md)
requires a VM-state file, guest-memory file and separately managed drive files.
Backing resources must be available at the expected jailed paths. Memory backing
files remain immutable and retained throughout a restored VM's lifetime.

The same source documents reset vsock connections, software/hardware compatibility,
disk quotas, and replicated userspace identifiers/random caches/tokens. VMGenID
reseeds supported guest kernels; it does not rotate arbitrary application state.
A conservative first memory-restore mode therefore transfers one captured state
once, after confirmed source termination. Multi-use memory templates remain a
separate implementation and acceptance requirement.

## Work split and acceptance order

| Increment | Concrete implementation | Required observation |
| --- | --- | --- |
| Earlier native allocation/metadata recovery | Bind pending writes and generation allocations to durable producer/object receipts; reconcile only after writer absence | Kill at write/dispatch boundaries; preserve ambiguous/replaced objects; no create or signal replay |
| Guest quiescence | Protocol2 accepted at376328c and protocol3 retained at6c32d1a; separate PID1/control from agent/workloads, fence admission and drain accepted effects | Original barrier/root52/365 and subsequent authority55/371 both pass with Complete collection |
| Guest authority protocol | Protocol3 generation-bound native frames and frozen transition accepted at6c32d1a | Actual same-VMM55/371/Complete; not host restore/source-termination proof |
| Independent content admission | Private pinned manifest and descriptor-based anonymous state/memory/disk copies; final335-source Windows290/Linux-root390 and musl21/static4 checks pass | Actual independent source deletion, exact bytes and read-only output; corrupt/truncated/untrusted inputs leave no outputs; guest provenance remains synthetic |
| Private checkpoint | Owned Machine capture/local store accepted at47ac2cc; manager-owned capture retained in the accepted c7fbfce and9a77320 gates | All4 manager groups pass within70/384/Complete. Original39/380/Complete and41/380/Unknown failures remain preserved |
| Private single-use memory restore | Private durable single-use claim and fresh jailed paused loader accepted; native persistent manager/supervisor and missing-writer collection have separate targeted acceptance | Private6 within70/384/Complete prove retained RAM execution and old-scope refusal. Native6/shared6 passes12/90/Complete; actual writer-loss3/shared6 passes9/90/Complete with original collector proof and Closed/Unconfirmed |
| Public integration | Persist operations, idempotency, quota and object references; add REST/CLI/Rust/Python clients and actual capability probe | Public success/failure/recovery and deletion on the supported real profile |
| Rootfs/volume snapshots and templates | Distinguish fresh boot from memory continuation; bind volume identity and immutable template versions | Kind-specific consistency/isolation, independent instances and template update/deletion behavior |
| Combined M4 Stage | Freeze the full implementation and execute retained plus new backend gates together | Source-verified reports, actual resource collection and requirement-by-requirement evidence |

## Guest barrier and authority

The protocol2 quiesce/status/thaw barrier is accepted at376328c as described in
[native quiescence](native-quiescence.md). Protocol3 now binds every native RPC
to generation and provides a frozen [guest authority transition](native-authority.md);
its same-VMM55/371/Complete gate is accepted at6c32d1a. Initial identity still comes
from guest boot arguments; changing a host VMM ID alone cannot change it.
The private [single-use continuation](native-continuation.md) implements a claim,
same-observer source-termination fences and a fresh owned-Machine loader. Its
actual fresh-target gate passes70/384/Complete. Native persistent manager/supervisor
coordination passes its separate targeted12/90 and writer-cut9/90 hardware gates;
public restoration remains unimplemented. Old guests refuse
requests requiring unsupported semantics.

PID1 remains outside workload task groups. The implemented private barrier closes
workload admission, drains accepted RPC effects, freezes the exact owned workload
group, observes frozen state and syncs the root filesystem before host pause. The trusted
control service must remain reachable to report the barrier and transition its
authority. Keep the configured aggregate guest task limit above both trusted and
workload subgroups; restructuring must not exempt the agent or its descendants
from that total budget. A failed or disconnected barrier is unconfirmed, never a
capture permit.

Restore allocates a new sandbox/generation, supervisor, VMM process, control epoch
and guest RPC authority. Establish a restore barrier before source capture so
restored user processes cannot run before authority transition. Old connections,
command/session handles and credential bindings must not silently acquire target
authority. Retained execution state needs explicit API semantics; EOF is not
completion, and source dispatch must never be replayed on the target.

For the initial single-use memory mode, the source remains paused after capture
until it is positively collected. The target is not resumed until that collection
and the unique restore claim are durable. An interrupted or uncertain restore
retains its original target and reservation. It does not allocate a second VM.

## Durable content and recovery

Use separate private versioned manifests rather than treating the existing public
SnapshotManifest shape as complete storage/authority metadata. Bind installation,
source generation, capture operation, artifact hashes and lengths, runtime/kernel/
CPU compatibility, resource bounds, guest barrier, quota reservation and object
references. Keep restore authority separate from the immutable content manifest.

Persistent captured content must live outside the source VM's collected jail.
The private [content admission/materializer](native-checkpoint-content.md) can
produce independently verified anonymous copies without depending on a source
pathname or live producer. That materializer does not implement durable publication,
shared quota, capture producer fencing or restore claims; anonymous staging is not persistent
snapshot storage. The [persistent store and owned capture](native-checkpoint-store.md)
passed its actual60-group gate at47ac2cc. Native-manager integration and private
continuation have separate local/hardware evidence; public integration remains unaccepted.
The existing VM-root receipt deliberately binds a host boot and PID namespace;
it is not a persistent snapshot-reader contract. Separate immutable-object
identity from the original producer's write/collection fence. A Ready reader
must verify the exact retained objects without requiring the producer or source
image job to stay alive. Cross-boot/source-node authority still needs explicit
runtime and store evidence; a different boot UUID on an arbitrary other host is
not proof that the original producer or source VM stopped.

Publish objects without overwriting existing content, sync files/directories and
publish the manifest last. A named pending file or a matching digest alone does
not grant deletion or producer authority. Reuse actual producer absence and object
receipts; never collect by filename prefix. Remote object storage needs its own
conditional publication/fencing contract rather than a local kernel-lock claim.

Deletion first prevents new restore claims, then waits for existing runtime/object
references and positively collects the exact owned objects. A mapped memory file
cannot be removed as unused while a restored VMM still depends on it. Failed
operations and collection failures retain distinct states and original errors.

## Actual release gates

Require real KVM tests for retained guest memory and disk state, fresh authority,
single-use exclusion, source absence, malformed/altered/truncated objects,
incompatible inputs, quotas, concurrent dispatch, manager/supervisor interruption,
paused expiry and complete VMM/process/jail/cgroup/object collection. Wire tests,
unit checks and a successful snapshot API response do not establish restore.

Keep SIGKILL recovery distinct from host power-loss durability. Capabilities stay
unavailable until their actual profile probe and public contract pass. M5 and M6
continue after M4; this plan does not redefine platform completion.
