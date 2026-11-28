# Read-only ext4 inspection component

The Rust image builder now has a separate disk-input inspection path. This is a
private validation component, not a rootfs snapshot, cold-boot or template API.
The remaining implementation and actual KVM requirements are in
[native-rootfs-templates.md](native-rootfs-templates.md).

`rootfs-inventory` reports the pinned agent, init, e2fsck and debugfs content.
`inspect-rootfs` reads `/input/inspect-rootfs.json` and `/input/rootfs.ext4` in
the existing isolated builder. `await-inspect-rootfs` additionally requires a
trusted parent decision over private stdin. Its request fingerprint has a
rootfs-specific domain, so a tar-conversion permit cannot authorize inspection.
The production rootfs host orchestration has not yet been implemented.

The request binds a fresh generation, full disk length/digest, pinned boot
assets and expected PID1 configuration. Disks must be 64MiB through 16GiB, aligned
to 4096 bytes, with a clean full-length ext4 superblock and no pending recovery.
The inspector runs read-only `e2fsck -f -n`, checks protected physical parents,
workload directory ownership and fixed agent/init/config inodes, then compares
asset lengths and SHA256 against trusted inventory. A normal `/sbin -> usr/sbin`
layout is supported; boot assets must remain root-owned regular files with one
link and exact permissions. Unknown configuration fields are refused.

No filesystem is mounted, repaired or recursively extracted. Only three bounded
files are dumped by inode into the owned generation directory. Fixed commands
and destinations never come from guest filenames. Rust reads and hashes the
actual dump before accepting it; a tool exit code alone cannot prove extraction.
Disk content and tool inventory are checked again before success. Tracked tools
must be waited and drained, and the exact temporary directory must be positively
absent. Failure clears the inspection result and retains uncertain collection.

The JSON inspection result remains separate from a prepared-tar manifest and
contains no launch authority. It cannot establish guest ABI compatibility,
fresh-control identity, cold-boot success or independent clone behavior.

`tests/rootfs_inspection_contract.py` exercises actual source-built conversion
and inspection in owned Docker volumes. It defaults to runsc; its trusted test
parent reads physical host cgroups before passing the one private permit.
The explicit `--runtime runc --allow-runc-development` mode checks actual local
container limits and is development evidence only. The harness does not replace
the future Rust production parent. Both paths verify unchanged input bytes,
actual refusal, tool/staging collection and owned resource absence.

The component CLI fixture intentionally uses one private attachment with the
CLI's StdinOnce=true, retaining its writer until observed exit. It does not test
production Rust parent reconnection, whose direct Docker API uses false. A fixed
trusted-shell preflight checks actual placement, host cgroups and private stdin
before compiling Rust. It proves only transport; the separate full Rust/ext4 gate
remains mandatory. Docker CLI's [creation logic](https://github.com/docker/cli/blob/v29.0.0/cli/command/container/opts.go)
sets StdinOnce when OpenStdin and AttachStdin are enabled. Its reviewed SHA256 is
`a280447cefffdf1632951e85eb41ad1de09cbf257708edffde07fdf567092126`.

The existing image-preparation workflow can dispatch `component=rootfs` on a
candidate branch, invoking the reusable [inspection gate](../.github/workflows/rootfs-inspection.yml).
Full workspace CI and final M4 KVM acceptance remain separate gates.

## Upstream decisions

The e2fsprogs [dump implementation at v1.47.0](https://github.com/tytso/e2fsprogs/blob/v1.47.0/debugfs/dump.c#L138)
reports several dump failures through diagnostics and returns from a void
command handler. We therefore verify the actual bounded output rather than
treating successful process exit as proof. The project also records
[an rdump path traversal issue](https://github.com/tytso/e2fsprogs/issues/272);
this component avoids recursive extraction entirely. The reviewed dump.c SHA256
is `a24bd9d66a26296238add4062415cdbc25e994cd69badfc110821723e77196d2`.

Linux v5.10 [ext4_freeze](https://github.com/torvalds/linux/blob/v5.10/fs/ext4/super.c)
flushes the journal and clears its recovery flag only after a successful flush.
The reviewed file SHA256 is
`c40365d2d0875b20c76eabe3989950bcd31fd761212176e831e697bb0f5e989f`.
The current memory barrier's syncfs is not implemented filesystem freeze.
Cold-disk capture still needs a separate bounded freeze/thaw protocol and actual
source-resumption/clone-isolation evidence; this inspector does not supply it.

Moby's [capability normalization](https://github.com/moby/moby/blob/v28.3.2/oci/caps/utils.go#L56)
adds canonical CAP_ prefixes. The trusted test fixture follows the existing Rust
parent's name normalization while requiring exactly CHOWN, DAC_OVERRIDE, FOWNER
and FSETID, dropped defaults, a read-only root and no-new-privileges. A changed
spelling is not a broader permission set; extra/missing capabilities and weaker
permission settings are refused by explicit controls.
