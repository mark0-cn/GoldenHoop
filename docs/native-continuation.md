# Private single-use memory continuation

The private continuation code is in local validation. Its actual fresh-VMM gate
has not executed. This does not register native-manager/public restore or memory
template capabilities, and does not complete M4-M6.

A Ready capture reference remains immutable content. Its continuation is a
separate mutable lifecycle, with a permanent inode/birth-bound witness pinning
the entire restoration intent. That intent binds the exact reference/runtime,
restoration UUID, new sandbox/generation and a new target path under its original
trusted parent. The same reference cannot mint another target. An exact retry
returns its original lifecycle, including after collection, and grants no new
writer session. A missing/rolled-back claim with a surviving witness refuses
replay and collection. Unknown initialization is retained for reconciliation.

Before a claim, the original VMM writer and original source directory must be
positively absent in their original host boot/PID namespace. Another observer
context cannot establish that fact. The new target reserves an additional mutable
drive copy; the capture already reserves two RAM/state copies. Reservations stay
until the tracked target writer and target directory are absent. A private target
launch without an acknowledged writer remains unconfirmed, even if a caller says
it cleaned up. Closed claims retain their permanent identity history.

The writer session owns a shared capture lease and an exclusive continuation
lease. Ready readers can still verify immutable content during target copying.
GC cannot collect referenced objects. Global quota locks are released during
large hashes and reacquired before admitting the aggregate reservation. Each
state change verifies the original producer and exact record preimage. A killed
producer cannot mint another target; collection distinguishes interrupted work
from a positively activated continuation.

The loader creates a new jailed, unconfigured Firecracker VMM. It makes independent
state/memory copies and a mutable drive copy at the expected jailed paths, then
loads with `resume_vm=false`. It requires an actual Paused observation. The
jailer owns its root directory initially; after snapshot load creates the vsock
listener, the loader changes the root to UID0/mode0755. The state/memory directory
is UID0/mode0555 and its files are UID0/mode0444. The VMM cannot replace or write
its lifetime memory backing. It still owns its separately copied writable drive.

Only then is the VM resumed with the captured workload cgroup still frozen. The
authenticated new physical VMM must acknowledge the exact protocol3 authority
transfer. Target generation/task limits and host isolation are checked before
explicit thaw. The loader performs no guest marker commands or workload writes.
Native persistent journal, supervisor and manager restore orchestration are still
required; the current independent-disk entry point explicitly refuses to apply
this private contract to an ordinary persistent Machine.

The private probe prepares an original guest process with a random RAM token.
After source capture/collection, `probe-restore` loads the new target, uses the
same captured execution UUID without a Start replay, and releases that process
to emit its retained token. It verifies captured drive contents, refusal of an
old-generation frame, unchanged original checkpoint objects after target drive
changes, actual target process/root/cgroup collection and reference release.
The Python observer also samples actual protected backing ownership/permissions.
Exact retry must return the old closed target with no launch; changed target intent
must fail before allocation. Temporary output files use anonymous descriptors.

Eight GNU-root store/process tests passed on a preliminary source: source and
target absence fences, target-drive quota, original claim identity, rollback
refusal, known-failure settlement and an actual claim-owner SIGSTOP/SIGKILL. Guest
and VMM provenance in those tests is synthetic. They cannot accept KVM memory
restoration, manager/supervisor crash reconnect, public execution/session rebinding,
cross-node/boot authority, multi-use templates, or complete M4-M6. Final current
Windows290/GNU-root400 full checks and musl21/strict clippy/static4 releases pass
on342 identical inputs. All3 owned check images are collected with positive
absence; the [local summary](evidence/m4-continuation-implementation-summary.json)
records exact evidence.

The retained managed gate at26d845e passes capture, hold/refusal and actual manager
SIGKILL/reconnect, then fails on source removal after41 groups with Unknown
collection. Its original [archive](evidence/m4-managed-checkpoint-46051406682-archive.json)
is retained. The new continuation gate has not run and must follow correction of
that retained collection failure; publishing the private implementation does not
accept its hardware behavior.
