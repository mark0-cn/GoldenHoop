# Offline image preparation

The Rust `goldenhoop-image-builder` component converts an untrusted, uncompressed
OCI rootfs export into an offline ext4 disk. It overlays the administrator's
pinned static agent/init assets and writes a versioned content manifest. This
component alone does not prepare a production allocation or establish a usable
Firecracker profile. Host image resolution, durable allocation/collection and
actual KVM acceptance remain separate required work.

## Conversion boundary

The `image-builder` Docker target contains the converter, agent/init and e2fsprogs.
Its inventory reports actual executable bytes. A trusted parent must pin the
immutable image, verify its namespaces and resource settings, and mount only an
owned input volume read-only and an owned output volume read-write. No daemon
socket, host rootfs mount, credentials or workload entrypoint is supplied.

The converter requires root PID1, no-new-privileges, a read-only root, loopback
only, and exactly CHOWN, DAC_OVERRIDE, FOWNER and FSETID. These capabilities let
it reproduce numeric image ownership and establish protected agent directories
and a UID/GID1000 SGID workspace inside its private extraction tree. FSETID is
needed because Linux can silently clear SGID for a foreign group even when
`fchmod` returns success; ownership, mode and type are therefore read back from
the actual open descriptors. Installed assets must also have one hard link.
See the [Linux chmod contract](https://man7.org/linux/man-pages/man2/chmod.2.html).
No SYS_ADMIN, device mount or execution of source-image programs is used.

The cgroup boundary requires at most 2 GiB memory, 16-128 tasks and at most two
CPUs. The current component fixture uses 1 GiB, 64 tasks and one CPU. Its default
runtime is explicitly `runsc`; local runc testing requires both a named runtime
and `--allow-runc-development`. There is no runtime fallback. A runc component
test does not accept production gVisor conversion.

The current converter checks the visible cgroup v2 files and refuses missing or
unbounded values. gVisor's [compatibility documentation](https://gvisor.dev/docs/user_guide/compatibility/)
distinguishes virtual in-sandbox cgroups from limits enforced by the host kernel.
The production parent must verify the actual host resource boundary; virtual
guest accounting cannot substitute for it. That parent handoff and actual
gVisor acceptance remain unimplemented/unverified in this component increment.

## Input and publication rules

`/input/prepare.json` is bounded to 64 KiB. It binds one non-nil generation UUID,
exact archive/agent/init SHA256 and lengths, and a 4-KiB-aligned disk size from
64 MiB to 16 GiB. The archive is at most 8 GiB and each pinned asset at most
64 MiB. Inputs are root-owned regular files with no group/other write access;
archive and asset content is verified before and after extraction/installation.

Raw tar preflight bounds 200000 entries and extended headers before ordinary
tar iteration can allocate them. Extended headers are at most 64 KiB; PAX size
overrides, sparse/global extensions and special device/FIFO nodes are refused.
Declared file bytes cannot exceed the disk bound. Paths must remain relative
and at most 4096 bytes. Normal extraction uses tar-rs 0.4.46 `unpack_in` inside an
exclusively owned private tree, preserving numeric ownership while dropping
set-ID permissions and xattrs. The pinned [tar-rs implementation](https://github.com/composefs/tar-rs/blob/fc459c149f83bf4daceaa52e17d351989002e1a9/src/entry.rs)
does not protect against another process concurrently mutating its destination;
the isolated parent and exclusive output ownership are required assumptions.

Agent/init replacement creates fresh files instead of editing source-image hard
links. All resolved physical parents become root-owned 0755. Guest mount points
and workspace must be real directories. The workspace becomes 1000:1000 02770;
identity files and resolver configuration are replaced with fixed guest-only
values. Old aliases cannot modify the replacement executable.

`mke2fs -d` creates the disk without mounting it. `e2fsck -f -n` must exit zero.
Each tool has a 180-second limit, followed by actual child wait and separate
pipe drainage; launch, EOF or an unconfirmed kill cannot establish collection.
The disk is synced, fully hashed, read back and made read-only. Extraction data
is positively collected before a synced manifest is published with Linux
`renameat2(RENAME_NOREPLACE)`, followed by parent-directory sync. Existing
generations are never overwritten. The manifest binds source, assets, disk and
tool content, format/version and creation time.

A 600-second overall fence and TERM/INT cancellation stop new work. Blocking
hash/extraction operations check the shared fence while the Tokio signal loop
remains responsive. Owned staging is removed only after tool collection is
confirmed. Errors retain the operation failure and actual staging/tool status;
an uncertain outcome requires parent-side reconciliation.

The offline ext4 and immutable-source conversion patterns were compared with
pinned E2B [filesystem preparation](https://github.com/e2b-dev/runtime/blob/86cb50338fe3bd73c10b13270aaa576b48f5d582/packages/orchestrator/pkg/template/build/core/filesystem/ext4.go)
and [rootfs preparation](https://github.com/e2b-dev/runtime/blob/86cb50338fe3bd73c10b13270aaa576b48f5d582/packages/orchestrator/pkg/template/build/core/rootfs/rootfs.go).
Their applicability guides the implementation; only GoldenHoop's own actual
component, gVisor and KVM results can establish support.
