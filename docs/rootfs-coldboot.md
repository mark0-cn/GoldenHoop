# Private rootfs cold boot

This increment is accepted on sourced9e0b37c by
[actual KVM/runsc46152336903](evidence/m4-rootfs-coldboot-46152336903-archive.json)
and [full CI46152295297](evidence/m4-rootfs-coldboot-ci-46152295297.json).
The gate proves two fresh VMs, independent disk writes after source-content GC
and original native/reference cleanup.
Public rootfs APIs/SDKs, volume snapshots, templates and complete M4-M6 remain
required by [roadmap.md](roadmap.md).

The private manager `rootfs_boot` request binds an immutable RootfsReference,
operation, target sandbox, resources and absolute lifetime. It can also bind the
original source handle. Ordinary boot, prepared-image input and single-use memory
restoration remain separate kinds. Existing journals omit the new optional field.
The inspected guest file's default task limit is a pinned file value. The trusted
host chooses each target's admitted limit through its kernel boot argument and
checks the actual guest/cgroups; that limit may differ from the file default.

The manager validates Ready metadata and the pinned kernel/VMM/guest contract,
writes the target journal, then reserves a permanent per-target source reference.
These records are independent for each target; memory restoration uniqueness is
unchanged. Pending target references fence source GC even when no process retains
a reader. Source admission and GC use the existing permanent quota/object locks;
there are at most128 pending and8192 retained target records. Retained records
prevent spent identities from selecting new content.

Before dispatch, the manager acquires an actual verified shared disk lease. Only
the shared mutex descriptor is inherited by its trusted supervisor. The supervisor
duplicates it with CLOEXEC, opens its own verified reader, and then closes the
incoming description. No source/store descriptor reaches the VMM. The supervisor
copies exact bytes into its new private VM root, verifies the target's independent
inode/link/ownership/digest and syncs it and its parent directory. An original
root/process receipt and copy receipt close that target's source hold before the
disk is given to the VMM. Source content can be collected after every pending
target has a verified independent copy or positive native collection.

Native collection produces a distinct receipt, bound to the original target,
host boot and PID namespace, root and original processes/cgroups. Source-store
reconciliation never substitutes a replacement target. Exact retry retains the
original generation. Collection of the source disk is separate from collection
of the target VM and its writable disk.
An unready target which was collected returns InvalidState on retry rather than
an apparently successful create result. A previously Ready collected target can
return only its original handle; that handle does not recreate the VM.

The local file/process tests use synthetic guest/inspector receipts. They cover
shared descriptor handoff, independent receiver offsets, durable two-target GC
fences, exact retry/refusal and two separate copies that survive source deletion.
They do not establish KVM behavior or death during actual cold-boot disk copying.
The hardware fixture submits production Rust requests and observes real target
VMs; Python does not implement their disk copies. Actual copy-time manager and
supervisor death remain separate required fault coverage.
