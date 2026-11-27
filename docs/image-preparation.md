# Offline image preparation

The Rust `goldenhoop-image-builder` component converts an untrusted, uncompressed
OCI rootfs export into an offline ext4 disk. It overlays the administrator's
pinned static agent/init assets and writes a versioned content manifest. This
component alone does not prepare a production allocation or establish a usable
Firecracker profile. The trusted Rust host service now connects immutable source
acquisition, isolated conversion and verified private disk storage. Actual
production gVisor and produced-disk KVM acceptance remain separate required gates.

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

Direct `prepare` checks visible cgroup v2 files and refuses missing or unbounded
values, including swap. The host-driven `await-prepare` path instead requires a
private authorization decision after the host verifies actual enforcement.
Virtual guest accounting cannot establish that boundary. The runsc
[cgroup v2 implementation](https://github.com/google/gvisor/blob/cc5b7474bf134432a4f41a47d37022fc4f05ede6/runsc/cgroup/cgroup_v2.go)
and the [Linux cgroup contract](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)
guide the independent host observations below. Actual gVisor acceptance remains
required; compatibility is established by executing the real converter.

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
is positively collected before publication. A fresh sibling directory is claimed
without replacement; data names are linked and synced before the complete synced
manifest is linked last. Every link refuses an existing name. Directory/parent
sync, original staging removal and final single-link inode readback are required.
Directory presence alone is never Ready. The manifest binds source, assets, disk
and tool content, format/version and creation time. The shared-volume rationale
and the original failed gates are recorded below.

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

## Trusted Rust source acquisition

`goldenhoop-images` is a separate trusted host service. Its private CLI takes a
root-owned database and artifact root, an explicit job/generation UUID pair and
a locally cached `sha256:` image ID. It connects only to the default local
daemon socket, requires Linux/amd64 Docker API 1.53 or newer and never pulls a
mutable tag. Images declaring anonymous volumes are refused before carrier
creation. Source OCI entrypoints are never run; source acquisition exports
filesystem bytes only.

Schema 17 adds installation-bound private image jobs. Immutable request JSON and
its SHA256 bind the source ID and storage backend. Requests/payloads are bounded
to 64 KiB, generations are unique and each state update compares the previous
revision. A repeated job cannot reset its generation, input, pending dispatch
or revision. The intent is committed before creating its exact labeled carrier;
the large-object reference is committed before upload. No new host extraction
or staging-directory ownership scheme is introduced.

The carrier remains Created with PID0 and zero restarts, no mounts, a read-only
root, no network, no capabilities and no-new-privileges. Its entrypoint is a
fixed nonexistent path. Actual ID/image/name/labels/state/placement are checked
before export and after both reads. The service first hashes an at-most-8-GiB
export under a 180-second read budget, then streams a second export into the
existing immutable large-object store. The second stream must match the first
full digest and length; chunks and the final manifest are read back. No source
tar is unpacked on the host. The carrier is removed and actual ID/name absence
confirmed before the archive becomes Ready. Retained observations include its
actual Created/PID0 state and mount/network/read-only configuration.

A new process can reopen the same Ready job and verify its archive even after
the original source image has been collected. Stable archive collection requires
the caller to fence consumers, then compares the journal revision and deletes only its recorded generation
and requires verified object absence. Retrying an interrupted stable collection
uses the same immutable reference. A collected job cannot relaunch. Foreign
generations, changed inputs or changed storage bindings refuse admission.
Unacknowledged creates and uploads remain fenced/Unknown; automatic replay and
recovery of those uncertain preparation states are not implemented by this
increment. An operation failure alone cannot establish Complete collection.

The [frozen actual source contract](evidence/m4-image-source-export-actual-windows-frozen.json)
passes seven groups and binds 309 inputs. It independently reconstructs and
hashes a two-chunk 6679040-byte archive, reads its known payload without unpacking
it, verifies no-start observations, fresh-process reopen, foreign identity and
backend refusals, anonymous-volume refusal and idempotent collection. A separate
read-only observer finds no remaining blob files. All fresh fixture containers,
volumes, images and its exact temporary context are positively absent.

[Windows full checks](evidence/m4-image-source-export-validation-windows.json)
pass format, strict workspace/all-target Clippy and 279 tests. The
[Linux full checks](evidence/m4-image-source-export-validation-linux-current.json)
pass the same checks and 328 tests, then build the actual optimized host service.
Each report fingerprints all 308 Rust/Cargo/SQL/fixture-JSON/image inputs. The
old-schema regression fixtures now accurately remove the new image table before
simulating old versions; migration/reopen preserves both prior resources and a
new image intent. Earlier failed validation reports remain historical evidence.

The [initial actual run](evidence/m4-image-source-export-actual-windows-first.json)
retains Failed/Unknown despite passing its seven functional groups. Subsequent
inspection found SQLite WAL/SHM auxiliary files in its verified local temporary
directory; the original empty cleanup assertion omitted its failing line. The
attempt to delete that directory was rejected by automatic approval and was
not retried. It remains retained separately from later successful fixture
collection. The corrected fixture explicitly closes its readers and uses
[immutable SQLite access](https://www.sqlite.org/uri.html) only on its frozen
copied database, validates exact job inventory and records cleanup failure
locations. Production database locking/sync rules are unchanged.

These historical results accept source acquisition and offline conversion as
separate components. They do not accept production orchestration, uncertain
allocation recovery, gVisor/KVM use, or source S3 interoperability. The following
implementation requires its own actual gates and publishes no public
image/snapshot/template capability or combined M4-M6 acceptance.

## Durable converter parent

`goldenhoop-images prepare` takes explicit job/generation UUIDs, administrator-
trusted pinned source and builder image IDs, a disk size and runtime. Its default
is `runsc`. Missing runsc refuses admission before provider allocation. Local
`runc-development` also requires `--allow-runc-development`; there is no fallback.
Builder images with unexpected inherited environment, health checks or anonymous
volumes are refused. Source programs are never executed.

The private schema-17 parent intent binds source, builder, runtime, disk size and
storage backend. Its child source-export identity and all exact resource names
are committed before dispatch. Every mutation phase uses revision CAS. A pending
job never resets, reissues create/start/authorization, or chooses another runtime
when retried. Stable Ready jobs can reopen after their source image is gone and
must pass a fresh whole-disk storage readback and provider-absence checks.

The parent creates two owned local volumes with exact installation/job/generation/
request labels and NoCopy mounts. A never-started pinned-image seeder supplies
the bounded baked inventory and receives only a fixed-name tar envelope containing
`prepare.json` and the opaque `source.tar`. The host does not unpack source-image
entries. Both storage download verification and Docker upload acknowledgement
must complete. The seeder is checked as Created/PID0 and removed before conversion.
Docker may omit a false mount `ReadOnly` flag; absent and false are compared by
their access semantics, while mount source, target, options and observed RW must
still match exactly.

The actual converter has only read-only input and writable output volumes, a
read-only root, no network, no daemon socket, no host bind mounts, NNP and the four
required capabilities. The pinned host budget is one GiB, zero swap, 128 tasks
and one CPU. After start, the host authenticates PID/start ticks/boot ID with a
pidfd and requires its complete immutable container ID in the actual cgroup
path. Cgroup files are opened beneath root-owned, non-writable directories using
descriptor-relative no-follow opens on cgroup v2. The tightest finite memory,
swap, tasks and rational CPU limits are read through all ancestors, supporting
inherited sentry limits. Missing/unbounded/excessive enforcement refuses the
permit. The trusted service requires the real host PID/cgroup view; a workload
never receives it.

Only after persisting those observations does the host send one bounded JSON
line over the converter's private stdin. It binds generation, request content,
builder image, installation/job and a nonce; the converter additionally checks
the generation-bound hostname. This is a trusted-parent decision, not a signed
self-attestation: arbitrary JSON cannot prove host enforcement. The converter
waits at most 30 seconds before touching an archive. Nonblocking descriptor
readiness preserves cancellation without a blocking stdin task outliving the
deadline. Direct runc development also retains visible-cgroup checks.

The input half remains open until actual exit/output drainage: the pinned Moby
[attach copier](https://github.com/moby/moby/blob/3c2183c2a8eaf2e261dfeaaad627e8faa13a803b/daemon/internal/stream/attach.go)
closes attached stdout/stderr when stdin ends with StdinOnce=false. The newline
delimits the decision without requiring EOF. The
[Bollard 0.21.1 example](https://github.com/fussybeaver/bollard/blob/v0.21.1/examples/attach_container.rs)
also supplies explicit attach flags. Empty output/EOF never establishes success.

Success requires an actual zero wait status, Exited/zero/no-OOM/no-restart
inspection, a bounded Passed report with tools collected/staging absent, and a
manifest matching the exact request and baked tool/asset inventory. A separate
fixed-file download must yield the same manifest. The disk storage reference is
journaled before its bounded stream begins. The host validates tar header
checksums, exact regular-file names/sizes, bounded PAX metadata and a complete
zero trailer, without extracting entries. Every chunk and the complete disk are
verified by the existing large-object store.

Ready follows actual container ID/name absence, old PID absence (a zombie is
still present), complete container-cgroup absence, both volumes' 404 readbacks,
child source-archive collection and another full disk readback. Bounded exit,
output size/digests and stderr evidence are retained. Failed operations keep
their failure and uncertainty; removing one container is not Complete cleanup.

`collect-image` collects only stable disks after the caller fences all consumers.
`abort-before-input` is a narrow maintenance path after the caller fences its
original producer: it accepts failed acknowledged pre-input states, confirms a
remaining seeder is Created/PID0, and collects exact volumes/source storage. It
preserves the original error and cannot replay the job. Unacknowledged creates,
in-flight input/disk uploads and uncertain starts are refused by that path.
Automated fencing/reconciliation of all interrupted allocation states and actual
produced-disk KVM placement remain required before complete M4 acceptance.

The [frozen local runc-development pipeline](evidence/m4-image-prepare-actual-windows-frozen.json)
passes nine actual groups with 315 source bindings and Complete collection.
It independently reconstructs and checks the 64-MiB disk, fsck, pinned assets,
workspace ownership/SGID and guest identity, then verifies reopen, refusal and
exact collection. [Windows](evidence/m4-image-prepare-validation-windows-final.json)
and [Linux](evidence/m4-image-prepare-validation-linux-final.json) full checks pass
281/335 tests with 312 exact build inputs. These results do not establish
production gVisor or KVM placement; `image-prepare.yml` is a separate real-runsc
gate. The initial failed reports remain unchanged, and separate maintenance-only
records confirm their later collection without claiming runsc conversion.

The [first production runsc gate](evidence/m4-image-prepare-45920852191-archive.json)
at 46845ed remains Failed/Unknown: the host observes a non-live PID before
authorization, and no disk/manifest is accepted. All 315 source inputs verify,
but missing guest stderr prevents a diagnosis of its underlying cause. Portable
CI success cannot override that result. Failure handling now captures bounded
owner-checked state, host stat/cgroup and log digests/tails before collection,
without relaxing live-process, isolation, resource, authorization or success
checks. A trusted isolated kernel diagnostic records virtual status and an actual
refused root write; it grants no capability. The
[corrected local diagnostic/pipeline gate](evidence/m4-image-prepare-failure-observation-actual-runc-current.json)
passes nine retained groups and Complete collection. New runsc evidence with the
explicit Actions SHA is still required.

## Interface enumeration without sysfs

The [second runsc gate](evidence/m4-image-prepare-45924506330-archive.json)
at 6085bda records the converter exiting 1 without OOM before authorization,
with ENOENT on stderr. Its separate isolated kernel diagnostic observes PID1,
NNP1, CapEff0x1b and a refused root write, but `/sys/class/net` is absent.
The converter's isolation check read that path; these observations identify
the incompatible check without accepting a missing path as an empty network.
The failed report remains Failed/Unknown and no disk is accepted.

The check now uses libc
[if_nameindex](https://man7.org/linux/man-pages/man3/if_nameindex.3.html)
and still requires exactly the loopback name. This enumerates interface names,
including links without an IP address, with bounded names/counts and ownership
of the returned allocation. gVisor's pinned
[RTM_GETLINK implementation](https://github.com/gvisor/gvisor/blob/cc5b7474bf134432a4f41a47d37022fc4f05ede6/pkg/sentry/socket/netlink/route/protocol.go)
dumps all stack interface IDs. `/proc/net/dev` is retained only as diagnostic
output; link statistics are not an authority for a complete interface list.
Other PID, NNP, capability, read-only-root, host resource, live-process and
private-permit checks are unchanged. A real Linux test compares libc's returned
names with every actual sysfs link in the ordinary full-check environment.

[Windows checks](evidence/m4-image-builder-interface-validation-windows.json)
pass format, strict workspace/all-target Clippy and 281 tests;
[Linux checks](evidence/m4-image-builder-interface-validation-linux.json)
pass the same checks and 339 tests, then build the actual optimized host.
Both bind 313 exact build inputs. The
[actual local runc-development gate](evidence/m4-image-builder-interface-actual-runc.json)
passes all nine groups with 316 input bindings and Complete collection, raw
SHA256 `8d5c807409c5830f20b6181e40d5cc92ee535fbd9262d5e590c0ffa4276457ff`.
All fresh test resources and both owned build-image tags are absent. This
validates the revised converter locally; a new actual runsc gate and boot of a
produced disk remain required before production image acceptance.

## Actual authorized runsc failure and produced-disk guest gate

[Run45927939744](evidence/m4-image-prepare-45927939744-archive.json) at
fb1bdf3 verifies all 316 source inputs. Interface/isolation checks now complete
and the trusted parent records actual PID/cgroup enforcement of one GiB,
zero swap, 128 tasks and one CPU before delivering its private decision.
The converter then reports `Invalid argument (os error 22)`, exits 2 without
OOM, confirms its tools/staging collected, and produces no disk or manifest.
Its operation remains Failed, with Complete resource collection. Raw report
SHA256 is `11b520c2bc6b8abe35b381a59d157b45074f560865873756234618cadd91da19`.
The failing filesystem operation is not yet identified. The workflow records
runsc release-20261123.1; its upstream revision resolves to
`81f68cb7d4661a9313d891a1758a765abe8eb27e`.

Following the official [gVisor debugging procedure](https://gvisor.dev/docs/user_guide/debugging/)
and its [runtime-argument installer](https://github.com/gvisor/gvisor/blob/81f68cb7d4661a9313d891a1758a765abe8eb27e/runsc/cmd/install.go),
the independent runsc gate now records selected file/process syscalls.
Runtime isolation and converter authorization remain unchanged. The collector
retains bounded log tails and whole-file lengths/hashes under the exact Actions
source SHA. A private root-owned trace directory has an explicit source claim;
its logs are collected only after the primary report confirms fenced compute
collection. An uncertain writer leaves the trace directory retained and cleanup
Unknown. These diagnostic records grant no runtime capability.

The separate `image-prepared-guest.yml` gate is implemented but not accepted.
It requires default-runsc conversion of a 256-MiB workload disk, independently
checks every stored chunk and its whole digest, and consumes that disk only
after the source image is gone and a fresh process reopens the same Ready job.
It passes the identical disk digest to the real Rust jailed KVM bootstrap,
requires corrupt-disk refusal before launch, actual guest command/file checks
and confirmed VMM/jail/cgroup collection. Guest writes must leave both pinned
input copies unchanged. It neither unpacks source entries nor runs a second
mkfs on the host. Public snapshot/template capabilities remain unavailable.

The [local workload-base conversion](evidence/m4-image-prepared-guest-base-local-runc-current.json)
passes nine groups with 316 exact bindings and Complete collection, producing
a 268435456-byte disk. Its raw SHA256 is
`55ccab33fde38bc4d4cf7c7afb021400f60a18226892dcc7f8ad655cdf9504b1`.
This is explicit runc development evidence and accepts no KVM or runsc result.
The [initial fixture failure](evidence/m4-image-prepared-guest-base-local-runc.json)
remains Failed/Complete: BuildKit interpreted a bare local image ID in FROM as
a registry name. The corrected fixture resolves the exact owned local tag,
rechecks its immutable ID and verifies the generated image's inherited content
layers before dispatching the pinned final source ID. All fresh local fixture
resources and three owned build-image tags are absent. Production Rust inputs
are unchanged from the 281/339-test full checks above.

## Shared-volume publication

The [upstream review](evidence/m4-image-builder-shared-publication-upstream-review.json)
pins gVisor's shared-mount defaults and its Gofer RenameAt implementation:
`RENAME_NOREPLACE` on a shared mount returns EINVAL. The original converter used
that operation for directory publication. This establishes a necessary
compatibility defect in the default production path. The exact syscall from the
earlier failed conversions was not retained and is not reconstructed.

[Run45930383149](evidence/m4-image-prepare-45930383149-archive.json) at 4004da9
again retains a Failed/Complete primary report with all 316 source bindings,
raw SHA256 `ab075b1d9aad30c488185eab88d0609d69580b277e35007103b64166759cccaf`.
Its separate diagnostic report verifies two inputs but remains Unknown: the
collector hit an unannotated assertion before retaining any logs. The original
report and its uncertainty remain unchanged. The revised collector records
root/claim metadata, a bounded file inventory and failure locations, and can
retain bounded regular-file observations before stricter deletion guards.
Root ownership/private mode, claimed source, file ownership and fenced compute
are still required for deletion. Literal unexpanded filename placeholders are
handled without changing path or file-type confinement.

The converter now uses the no-clobber hard-link pattern from
[tempfile 3.27.0](https://docs.rs/tempfile/3.27.0/src/tempfile/file/imp/unix.rs.html).
It first validates and syncs the three root-owned single-link files. Atomic
mkdir refuses an existing generation, including an empty directory. Data names
are linked without overwrite and their directory/parent are synced before
linking the complete manifest. Descriptor-bound inode/length/link observations
must match. The committed directory is synced, staging must actually disappear,
its parent is synced again and final link counts must be one. A partial target
directory or an error after manifest linking cannot establish successful
conversion; the parent still requires zero exit, exact manifest/storage readback
and confirmed provider collection. Failed publication leaves its error and
requires the existing fenced parent/volume collection. Interrupted publication
is not silently adopted or replayed.

Two actual filesystem groups cover successful content/inode retention and
staging collection, existing-directory preservation and refusal of a source
file with another link. Linux Docker executes their root branch; unprivileged
checks verify refusal before target allocation. Fresh
[Windows](evidence/m4-image-builder-manifest-publication-validation-windows-current.json)
and [Linux](evidence/m4-image-builder-manifest-publication-validation-linux-current.json)
format/strict workspace-all-target lint/full test checks pass 281/341 tests,
each with 314 exact build inputs. The initial Linux check's unused import
failure remains recorded; the corrected checks use the current frozen source.
The [actual local runc-development gate](evidence/m4-image-builder-manifest-publication-actual-runc.json)
passes nine groups with 317 bindings and Complete collection, raw SHA256
`55c62604f37d2fb409f1e82b9198df83c788e4d27e21f1d41f2ec6e30f8112f8`.
All its fresh containers/volumes/images/temp context are absent.
The [Linux collector contract](evidence/m4-runsc-trace-collector-local-current.json)
passes five groups with two exact input bindings and Complete fixture collection.
Its inputs are explicitly synthetic: bounded tails/digests, literal placeholders,
foreign source refusal, unfenced-writer retention and readable diagnostics with
refused nonprivate-directory collection. It establishes collector behavior,
not actual runsc conversion. New real runsc and produced-disk KVM gates remain
required.
