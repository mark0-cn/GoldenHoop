# Rootfs snapshots and immutable templates: implementation contract

This is the next M4 implementation contract, not implemented public support.
The separate private [read-only inspector](rootfs-inspection.md) implements its
disk-validation boundary; capture, restoration and templates remain pending. Rootfs and
volume snapshots, templates, combined M4 acceptance and the complete M5-M6 work
in [roadmap.md](roadmap.md) remain required. Existing memory continuation keeps its
single-use source-termination and retained-execution rules.

## Public behavior

A rootfs snapshot captures filesystem state for a fresh boot. It does not resume
old processes, reuse their public execution IDs or recover their RAM. Capture,
inspection, deletion and restoration need durable operations, explicit recovery
keys and Rust/Python SDK and CLI support alongside the REST API.

A template has a stable ID and immutable versions. Each version fixes its source
snapshot/content digest, runtime family, guest ABI, machine constraints, startup
configuration and declared feature ceiling. Publishing another version does not
change an already accepted launch. Reads and cursor pages expose build/validation
state; Pending, Failed, unknown or incomplete content cannot be launched.

Creating a template, publishing a version or creating an independent sandbox
requires an all-resource Write grant. Source-scoped grants do not expand to new
objects. New sandboxes retain exact target grants for reads and execution, as in
[M3](m3-delivery.md) and [memory restoration](public-snapshot-restoration.md).
Template management initially uses all-resource grants until a separately
specified template scope is implemented and validated; a source sandbox ID is
never treated as template ownership.

## Independent disk content

Use a separate versioned rootfs manifest and store contract. A memory checkpoint
must not be reclassified by ignoring its memory/state objects. Bind installation,
original source generation, capture operation, disk length/digest, source image,
protected agent/init artifact digests, guest ABI and filesystem format. Persist
the operation and producer/object ownership before effects.

Capture closes guest workload admission, drains accepted effects, freezes the
original owned workload group, synchronizes its filesystem and pauses the VMM.
Use the source-bound disk descriptor and existing bounded, sparse-preserving
copy/hashing primitives to produce independent content. Publish verified objects
and synced metadata without overwriting existing content. A live producer or an
unacknowledged object retains its original reservation.

After a successful disk-only capture, the original source may thaw and resume.
This requires an independently verified copy: later source writes must not alter
the snapshot. Failure handling must reconcile the original barrier, producer and
objects; an uncertain thaw or pause is not successful source recovery.

Treat a copied guest disk as untrusted input. Filesystem/protected-binary
validation belongs inside the isolated image-preparation boundary, without a host
filesystem mount or host execution of disk contents. Extend the existing image
builder with an explicit disk-input contract rather than pretending its current
tar-input path already implements this validation. Missing, changed or redirected
protected boot assets must fail before a new guest is allocated.

## Fresh instances and references

A rootfs restore cold-boots a new independently owned disk and fresh supervisor,
VMM, guest authority, API execution inventory, network allocation and lifetime.
No captured controller token, old connection or running command becomes target
authority. Workload files retain their documented ownership and contents. Any
template entrypoint receives a newly admitted execution with its own public ID;
it is not a replay of a retained memory execution.

Rootfs content can create multiple independent instances. An exact recovery key
returns one original target; a different key can create another instance if
policy and quota permit. This needs kind-specific durable restoration storage:
the current memory table's one-snapshot/one-target constraint must remain intact.
Accepted requests freeze the exact template version and content digest instead
of resolving a mutable version pointer again during dispatch or recovery.

Template versions pin their source content. Deletion first closes new admission;
already accepted instances retain their immutable version and content references.
Release runtime references only after positive original-target collection, or a
separately proven independent-materialization handoff. A failed launch or lost
reply cannot release them. Version publication uses an expected current version
to prevent concurrent lost updates. No ordinary boot may reopen a permanently
closed target identity.

Volume snapshots remain a distinct required path, with explicit volume identity,
attachment/writer leases, consistency, independent restoration and deletion
references. Rootfs capture must not claim attached-volume coverage. Kubernetes
placement and persistent-volume integration continue in M5; this does not remove
the M4 kind-specific snapshot requirements.

## Evidence required before support

The actual KVM gate must demonstrate a source that resumes after disk capture,
then two fresh targets using the same immutable content. Verify independent
filesystem mutation, fresh runtime, guest-control generation and execution identity, absence of old
running processes, exact file content/ownership and protected boot assets.
Collect the original source and prove that targets no longer depend on its paths.

Exercise exact retry, changed-request conflict, immutable version selection,
concurrent publication, deletion with live references, quotas and explicit
unsupported-profile refusal through REST, both SDKs and CLI. Corrupt/truncated
disks, altered protected assets and foreign owner/object identities must not
allocate a target. Cut producer/manager/worker execution at publication and
dispatch boundaries and confirm original-owner reconciliation, retained unknown
references and positive process/disk/cgroup/object collection.

Unit tests and compilation are not cold-boot or clone-isolation evidence. Full
M4 acceptance still requires the retained runtime/network/image/memory gates on
the final frozen source, together with these new rootfs/volume/template gates.

## Upstream comparison

At OpenSandbox revision `3d1b543f685b047cad8bec04c8bd8e49abec7d07`, the
[template model](https://github.com/alibaba/OpenSandbox/blob/3d1b543f685b047cad8bec04c8bd8e49abec7d07/server/opensandbox_server/services/templates/template_models.py)
persists normalized build intent, phase and manifest reference. The
[template resolver](https://github.com/alibaba/OpenSandbox/blob/3d1b543f685b047cad8bec04c8bd8e49abec7d07/server/opensandbox_server/services/templates/template_service.py#L453)
requires a Succeeded row, resolves stored entrypoint/machine settings and validates
the immutable OCI manifest reference for that format. Its
[snapshot resolver](https://github.com/alibaba/OpenSandbox/blob/3d1b543f685b047cad8bec04c8bd8e49abec7d07/server/opensandbox_server/services/snapshot_restore.py)
uses persisted snapshot configuration to resolve the effective image/backend.

These are applicable persistence and readiness patterns. The immutable-version,
fresh-disk and native-owner contracts above are GoldenHoop design requirements,
not claims that OpenSandbox implements this same local Firecracker protocol.
The reviewed source SHA256 values are respectively
`fdda3d3f886d870e80351f04b25c737c0f6a2128763bb682a6f5d71f9d7231a5`,
`af68d583037d4e37175c38ee6893189d6e39e9c4f0efcbd88998cfd5927194c0`
and `28c4d9bc42a0fa8d5444cdd4c0fd3d0028592a0583eb9503e957aefc0c2bfa51`.
