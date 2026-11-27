# Native manager capture jobs

The optional native `checkpoints` policy enables private manager capture jobs.
Public snapshot capability registration and restoration remain separate work.
The preceding owned-Machine implementation passed the actual 60-group capture
gate at 47ac2cc; manager integration needs its own immutable-source hardware gate.

`DriverConfig.checkpoints` contains `max_bytes` and `max_checkpoints`. Its store
is fixed at `<data_root>/checkpoints` and bound to the configured installation.
Omitting the policy preserves earlier serialized configuration bytes and refuses
checkpoint operations. Enabling capture adds 128 MiB to both the manager's actual
cgroup budget and installation memory admission. One capture worker can hold this
extra budget at a time; unrelated VMs retain their independent operation locks.

The private `driver-call` operations are `checkpoint_capture` with an original
native handle and capture UUID, and `checkpoint_inspect` / `checkpoint_collect`
with that UUID. Exact capture retries return the original record, including after
source collection or terminal object GC. A reused UUID with another original
source intent is a conflict. The source generation is never recaptured or replayed.

Before acceptance the manager validates the live source and durably reserves its
intent. A manager-owned blocking worker retains the exclusive source VM guard,
original capture lease and single worker permit through every operation. Its
private async reactor handles VMM/control calls; bounded synchronous hashing and
materialization do not block the main manager reactor. Closing client IPC does
not own or cancel these leases. Normal manager shutdown waits for capture workers
before collecting generations. A process crash leaves durable intent and the
original producer/VMM identity fences for reconciliation.

Before any quiescence or snapshot effect, the original supervisor acknowledges a
capture hold in its own journal. The manager never overwrites that journal from
its recovered Machine view. Ordinary manager RPC and supervisor Resume both
refuse a held source. Status, stop and absolute-expiry collection remain available.
The supervisor does not execute the copy task, so its independent expiry loop
continues. No capture path automatically clears the hold, resumes the source or
thaws the guest. A failed or unconfirmed capture remains reserved and fenced.

Expected policy rejection precedes runtime dispatch and leaves the source journal
unchanged. This includes Resume on a held source and disabled/nil/changed capture
intent. Genuine runtime errors and operation timeout poison the journal as
Unknown; Status cannot overwrite that fence. Stop retains the original error and
the supervisor independently collects the uncertain generation. The original
9f260a6 gate exposed this distinction: capture succeeded, but a refused Resume
was incorrectly classified as Unknown and collected the source. Its original
Failed/Complete report remains in the
[diagnosis](evidence/m4-manager-denial-upstream-diagnosis.json).
The correction passes Windows290/GNU-root398/musl21 on identical340 inputs;
the [local summary](evidence/m4-manager-denial-implementation-summary.json) records
the exact reports and scoped collection. Actual held-source preservation and
manager recovery still require the fresh64-group hardware gate.

At26d845e, the actual gate passes capture after client disconnect, both held-source
refusals and original paused-source/Ready-content recovery after manager SIGKILL.
It fails on source removal after41 total groups with Unknown collection; its
[raw archive](evidence/m4-managed-checkpoint-46051406682-archive.json) is retained.
The new [exit-observation correction](evidence/m4-manager-exit-upstream-diagnosis.json)
separates a descriptor-bound wait from live executable/UID authentication. A
stopping supervisor can release `/proc/exe` before pidfd readiness; this must not
invalidate its original wait target. Stop settlement requires its actual absence,
not another live-service authentication. Physical process/root/cgroup fences and
live identity checks remain enforced. Local child tests do not accept that
hardware correction. Failure cleanup additionally requires fresh post-drain
journal/resource observations and exact Rust object GC; it never turns an
operation failure into a passed result.
The [final local checks](evidence/m4-manager-exit-implementation-summary.json)
pass Windows290/GNU-root402/musl21 on identical342 source inputs, with formatting,
strict clippy and all4 static guest releases. Scoped image collection is complete.
The combined actual continuation gate must still verify this correction and
retained manager64 before either hardware behavior is accepted.

Production capture has no marker command or test file write. The private probe
alone prepares RAM/disk oracles, then invokes the same reserved capture operation.
Both paths still require the frozen guest receipt, actual Paused state, fresh
snapshot names, explicit synchronous snapshot files, independently verified
state/memory/drive copies, and another fresh source observation before publication.

Pending inspection reads the atomic record and permanent mutex identity without
acquiring the producer's active lease. It reports no verified content. Ready
inspection acquires a shared capture lease and checks all immutable objects.
A positively settled failure records that this producer's I/O finished while its
exclusive lease remained held. That acknowledgement permits the producer process
to stay alive during later collection. Unacknowledged interrupted work still
requires the original producer process absent in the same observer context.
Every outcome additionally requires the original VMM writer and original source
root actually absent; a failure acknowledgement never frees raw-source quota.
Foreign/replaced object inodes remain preserved, including after partial linking.

The new `firecracker-managed-checkpoint.yml` retains the full actual capture60
contract and requires client-disconnect capture, both resume refusals, exact retry
and changed-source conflict, independent VM operation, same-source hold and Ready
content after manager SIGKILL/reconnect, retained drive payload after source
collection, and exact object absence/quota release. Compilation and ordinary
filesystem tests cannot substitute for that hardware gate. A unique host restore
claim, fresh target load, public continuation, rootfs/volume snapshots, templates,
combined M4 and all remaining M5-M6 work remain required.
