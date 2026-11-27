# Private native manager restoration

This increment wires the already accepted private continuation loader into the
durable native manager and per-generation supervisor. It does not register the
public MemorySnapshot capability. Baseline images in the same installation are
the current input; prepared images are refused explicitly.

The private root manager call is `checkpoint_restore` with a `restore` object
containing `sandbox`, `request`, `reference` and `restoration`. The request binds
the complete CreateSandbox input, checkpoint reference, restoration UUID, target
sandbox UUID and its original creation/expiry times. The target generation is
allocated once and recorded in the native journal. A retry uses that generation;
a changed intent is Conflict. A completed retry returns the original handle even
after snapshot object collection, without reopening content or launching a VM.

Admission verifies immutable snapshot content, the original native capture hold,
resources, runtime artifacts and physical source absence. Under the installation's
allocation mutex, an existing native target for this capture or an existing store
continuation refuses another target before journal/cgroup allocation. The durable
single-use store witness remains the final guard across process failure.

The supervisor first acknowledges its own identity, then claims and retains the
store session itself. It loads the shared Rust loader into a fresh unconfigured
jailed VMM. The loader preserves independent immutable state/RAM backing and a
mutable target drive, loads paused, transfers frozen guest authority, explicitly
thaws and verifies readiness. Client disconnect does not own this session. Normal
native stop, absolute expiry and dead-supervisor recovery use the same collector.

## Acknowledgement loss and collection

A recorded launch intention without a VMM writer receipt cannot establish writer
absence. Ordinary private closure keeps refusing it. Native closure additionally
accepts a typed collection receipt from the original completed native collector:

- The original journal must acknowledge VM collection and root collection intent.
- Original supervisor identity, root receipt and both cgroup receipts are required.
- The boot, PID namespace, cgroup namespace, root parent/inode/birth and store's
  original acknowledged target directory must match.
- The original supervisor and any acknowledged VMM must actually be absent;
  zombies do not count. The exact root and cgroup paths must be absent in the
  same hierarchy, and replacements are refused.

Closure rechecks these observations under the original store leases. A closed
launch missing its writer retains this receipt durably. Interrupted Pending
becomes Unconfirmed. Collection does not manufacture execution success, Activated
or another launch right. Known failed outcomes remain Failed.

## Validation scope

The targeted GNU test actually kills a child which owns a continuation claim,
launch intention and root, then checks original root collection, identity/context/
replacement refusal, exact retry and quota release. Its completed native phase and
cgroup acknowledgements are synthetic. It does not accept a KVM writer-loss cut.

The separate `firecracker-managed-restore.yml` workflow targets six native groups:
source capture/collection; disconnected submitting client; live retry and competing
intent; actual manager SIGKILL with original process RAM continuation; actual target
supervisor SIGKILL with native collection; and exact retry after object GC. Full
retained hardware regression belongs to stage acceptance. Until its actual report
passes, these hardware cases remain unverified. Public snapshot/session rebinding,
prepared-image restoration, templates and combined M4-M6 remain open.
