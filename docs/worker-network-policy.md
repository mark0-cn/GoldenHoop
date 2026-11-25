# Worker-held protected policy sessions

The production worker can adopt an explicitly staged complete protected network.
This path uses the actual Docker driver and controller transport. New supported
host gates cover Ready, commands, renewal, tightening, pause and crash recovery on
runc and gVisor. Their current acceptance status belongs in `progress.md`.
Public network provisioning, hierarchy policy composition and capability probes
remain required. NetworkPolicy and SecretInjection remain unadvertised.

Schema 11 adds a desired configuration, its fingerprint and version, the original
protected checkpoint, the approved upstream, controller ownership and an
append-only transition history. It leaves allocation/controller history bytes
unchanged. A stored Active receipt is historical metadata; it cannot reconstruct
the private `VerifiedPolicyLease` or authorize worker dispatch after restart.

Only a complete Bound allocation explicitly staged while Starting, before its
first Running observation, enters this path. Legacy, partial and unowned journals
retain terminal recovery. The private Rust contract producer stages test intent;
it does not publish a network capability or replace public API validation.

One task owns each controller session independently of the ordinary reconciliation
and artifact concurrency limits. Before recovery it fences the previous public
observation, settles and positively collects the old epoch, and records every
new create/start intent before dispatch. It restores exact DNS under fresh
quarantine, preserving the original source, destination, listener tuples and
absolute expiry. A paused runtime resumes only after this fresh deny confirmation.

The actor durably claims the new physical controller under the current worker
registration, records a policy attempt before mutation, applies the complete
desired configuration, and accepts only actual driver readbacks. It retains the
nonserializable monotonic lease and renews through full native readback every two
seconds. A one-second dispatch margin is subtracted from its conservative bound.
Renewals do not turn old persisted receipts into fresh proof.

Running publication requires a current local actor, matching desired version and
owner, current worker registration and a positive local lease. All worker agent
RPC paths, file transfer, artifact capture and runtime diagnostics check this
gate. Each dispatch rechecks metadata and lifetime; closing or losing a receiver
refuses work. Kernel expiry remains the independent bound for already-running
work when the worker crashes or cannot confirm a renewal.

A desired policy update uses compare-and-swap on the desired version. The same
transaction clears the previous acknowledgement and fences an old Running
observation before asynchronous I/O. In-flight old acknowledgements refuse. A
healthy actor tightens through the protected replacement method; an expired or
uncertain session must be collected and recovered in a new epoch.

Pause stops the actor, fences readiness and collects its controller before
pausing the runtime. Native quarantine is attempted immediately; an uncertain
result is never cleanup evidence. Resume requires a new epoch and fresh policy.
Termination waits for actor settlement before removing the workload and follows
the existing exact process/network/kernel collection path. A creator that fails
to settle remains tracked and cannot be raced by collection.

The new actual contract starts from the existing protected bootstrap, runs the
production worker, verifies explicit command exit and exact stdout, holds the
same epoch beyond the kernel lease duration, tightens policy, pauses/resumes and
kills the worker. It independently checks finite kernel expiry before restart,
requires a new worker/controller identity, and checks unchanged workload ID,
PID, start time, floors and original expiry. Local Docker Desktop cannot execute
this positive composition because its kernel lacks bridge-family nft support.
