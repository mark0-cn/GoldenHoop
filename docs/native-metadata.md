# Native installation and metadata ownership

The native manager holds an exclusive installation lock for its lifetime. A
private directory's mode alone does not authorize adopting its existing files.
Before writing a missing installation marker, the driver now refuses every
occupied unmarked root except its exact lock file, which must itself prove a
matching durable installation/root claim. A foreign, partial or empty existing
unmarked lock is ambiguous and remains untouched. Non-root callers refuse before
creating a native root.

Fresh initialization writes and syncs an installation UUID and absolute data-root
binding into the new root-owned 0600, single-link lock, then syncs its directory.
Only after that claim persists is the installation marker published with
`renameat2(RENAME_NOREPLACE)`. A matching claim can resume a missing-marker gap;
a different installation/path cannot. The held file lock prevents a second live
manager from acquiring the same installation. A valid legacy marker authorizes
upgrading its empty lock in place, preserving its inode and existing ownership.
Malformed or conflicting claims never reset state or choose another installation.

The root protocol was compared with runc's
[validated fresh state-directory creation and saved-state loading](https://github.com/opencontainers/runc/blob/6d20d9cbe0da9cba22ebc08e559f24c0afa749c7/libcontainer/factory_linux.go).
GoldenHoop additionally needs an installation-level claim because one persistent
manager controls multiple durable VM generations. Upstream behavior guides that
boundary; it is not evidence that a GoldenHoop recovery path works.

Atomic JSON publication retains the descriptor of the actual create-new
temporary. If creation collides, failure cleanup has no authority over the
pre-existing path. After a later failure, cleanup compares device/inode from the
retained descriptor with no-follow path metadata; substitution refuses deletion.
Only the actual created file is removed. File sync, atomic publication and parent
directory sync remain required. A failed final sync remains an uncertain write;
absence of a temporary does not establish successful publication. Initial markers
cannot overwrite existing targets.

The [tempfile security/resource-leak documentation](https://docs.rs/tempfile/3.27.0/tempfile/struct.NamedTempFile.html)
also distinguishes a file from a reusable pathname and notes that process death
can bypass destructor cleanup. The same constraints apply here: hard crashes can
leave pending metadata, and this increment does not delete an unknown pending
file merely because its name resembles a temporary. Full interrupted-writer and
hard-manager recovery remain M4 requirements.

Three actual filesystem tests check collision/substitution preservation, failed
rename/no-replace cleanup, live lock exclusion, foreign/occupied/ambiguous-root
refusal, matching durable claim recovery and legacy lock migration. The root
branch executes in the actual Linux Docker full check; an unprivileged test run
instead verifies refusal before allocation. This is filesystem evidence, not a
new KVM or SIGKILL recovery acceptance result.

[Windows validation](evidence/m4-native-metadata-validation-windows.json) passes
format, strict workspace/all-target Clippy and 281 tests. The
[Linux full check](evidence/m4-native-metadata-validation-linux-first.json) passes
the same checks and 338 tests, then builds the static musl guest/rootfs. Both bind
312 exact Cargo/crate/SQL/JSON/image inputs in the feature checkout based on
46845ed. Linux construction is cache-only, creating no service container or image
tag; all test-owned temporary directories are positively removed. Integration
and actual native lifecycle checks are required before treating this as complete
M4 ownership/recovery acceptance.

Fresh combined canonical-main [Windows](evidence/m4-native-metadata-canonical-validation-windows.json)
and [Linux](evidence/m4-native-metadata-canonical-validation-linux.json) checks
pass 281/338 tests with format/strict lint and 313 exact source bindings, including
the diagnostic parent and both Dockerfiles. Linux builds the actual optimized
host service. These are canonical repository bytes; the separate newline review
in the progress log qualifies earlier diagnostic-checkout evidence. Actual native
KVM lifecycle verification of this ownership change now passes in
[run 45926123930](https://github.com/mark0-cn/GoldenHoop/actions/runs/45926123930)
at b3fa14d. The [archive](evidence/m4-native-45926123930-archive.json) verifies
all 337 source inputs against that immutable commit and retains the raw report
SHA256 `12b226603c1ef61f7717c2bbd61553e4ab0e729b503b6b79e4475e7cb97fca35`.
All 23 retained bootstrap/private/public groups pass with Complete collection,
including worker restart and expiry. This accepts the existing lifecycle under
the new root/atomic boundary; hard-manager death, abandoned pending-file
reconciliation, snapshots and complete M4 remain unaccepted.

## Same-boot installation manager recovery

The same-boot manager implementation holds the existing installation lease before
recovery. It checks the prior manager's installation, epoch, executable and
exact declared/persisted configuration before writing configuration or replacing
control metadata. The original PID/start identity must be gone; a zombie still
refuses recovery. A reused PID only establishes read-only absence of the old
identity and grants no signal/reap authority over its replacement.

Manager socket and cgroup records now retain device/inode receipts. Existing
unrecorded objects and replacements are preserved. The prior epoch remains on
disk until its replacement is durably published, so restart cannot erase the
only manager fence while generations remain. A fresh marker uses no-replace
publication. Every live manager client checks those control-object identities
and authenticates the actual root process and epoch.

| Observation | Restart behavior |
| --- | --- |
| Previous manager identity is present | Refuse without taking control |
| Configuration, socket or cgroup identity differs | Preserve and refuse |
| Acknowledged running/paused supervisor authenticates | Reconnect to the same supervisor/VMM and record the observed state |
| Valid generation is unconfirmed or unresponsive | Retain its journal/reservation; no replacement launch or guessed success |
| Pre-existing unacknowledged creation | Wait for its original effect; never replay create |
| Adopted early supervisor lacks direct-child authority | Retain until its original effect settles; no forced early signal |

Supervisor observations are independent, limited to eight concurrent exchanges
and three seconds each. The supervisor retains journal writes and actual VMM
parenthood. Every control request checks the pinned executable, root PID/start,
generation cgroup membership, socket peer and owner. Graceful collection still
requires actual VMM/supervisor process absence and owned cgroup/jail removal.
The new manager rotates its own epoch; VM identity and guest state are preserved.
Its Ready flag publishes control readiness, while runtime capabilities still
require a successful actual probe.

This follows the reconnect/independent-runtime-parent pattern in the
[pinned containerd shim loader](https://github.com/containerd/containerd/blob/59228e1af476a2b67cd80319e7e7249842413a05/core/runtime/v2/shim.go).
The [upstream applicability review](evidence/m4-manager-recovery-upstream-review.json)
records the additional GoldenHoop ownership fences.

The [current validation summary](evidence/m4-manager-recovery-acceptance-summary.json)
verifies Windows281/Linux-root348 tests with formatting, strict all-target
workspace Clippy and 316 byte-exact inputs each. Root tests execute real socket
replacement/refusal and PID kill/zombie/reap checks. An unacknowledged-reservation
test exercises actual dispatch code under a bounded wait and proves no helper,
provider path, journal rewrite or runtime advertisement. It does not use KVM.
The earlier successful check and test-module-placement lint failure are retained;
the final checks use the fenced source. Both temporary check tags are
ownership-verified and collected; useful caches remain.

The dedicated `firecracker-manager-recovery.yml` gate passes actual KVM
acceptance at ef8c360. It covers public command continuation, manager SIGKILL, live-owner
exclusion, changed configuration/control objects/supervisor identity, stale
epoch refusal, paused state and expiry while both worker and manager are dead.
Host/configuration migration, earlier abandoned allocation/metadata recovery,
snapshots/restore/templates/production placement, complete M4 and M5-M6 remain
unaccepted.

The first actual gate at d54ac1b is retained as Failed/Unknown in
[its source-verified archive](evidence/m4-manager-recovery-45949925668-archive.json).
Its fixture attempted cgroup-v2 rename, which Linux does not implement. The
corrected fixture removes only the receipt-verified empty old group and creates
a different real kernel inode at the same path, requiring refusal/preservation
before collecting that exact fixture replacement. Failure cleanup restores only
an intentionally killed fixture manager before generation collection and samples
old PID/start and scoped-path absence. Historical cleanup is not rewritten.

Create-error cleanup also uses the same `remove_owned` fences as explicit stop;
a rejected retry has no extra signalling authority over an adopted supervisor.
The [corrective Windows281](evidence/m4-manager-recovery-validation-windows-signal-fenced.json)
and [Linux-root348](evidence/m4-manager-recovery-validation-linux-signal-fenced.json)
full checks include a real unregistered sleep process preserved after rejection,
then killed/waited by its fixture parent. This does not establish actual nonchild
or KVM recovery by itself; the corrected dedicated hardware gate supplies that
separate evidence below.

[Actual KVM run45951829900](https://github.com/mark0-cn/GoldenHoop/actions/runs/45951829900)
passes all 32 groups with Complete collection. Its
[archive](evidence/m4-manager-recovery-45951829900-archive.json) verifies 342 inputs
against ef8c360 and preserves raw SHA256
`0ba600dbaf4c48090a67920161d7ebe10488675029b48ea4c93940a891cdbfd7`.
Three actual manager SIGKILLs preserve running-command identity/once semantics,
paused state and independent expiry. Six generation records are resampled after
collection with actual old PID/start and scoped-path absence. The fixture,
manager, export carrier and run-owned image are collected. This is same-boot,
exact-configuration acceptance; earlier unacknowledged metadata/allocation,
migration, snapshots/restore/templates and complete M4 remain unaccepted.

## Interrupted metadata publication

The interrupted-publication implementation writes into O_TMPFILE descriptors, attaches a complete
bounded `user.goldenhoop.metadata.v1` receipt and syncs the file before giving it
a pending name. Unsupported local filesystem/xattr operations refuse without
switching to the old named-only algorithm. The ordinary JSON body remains readable
by existing clients; the receipt stays on its inode after publication.

Each target has a permanent `.gh-meta-<target-sha256>.lock` inode. Its complete
parent/name binding is also published from an unnamed file. These useful store
coordination files remain while the store exists; they are collected with the
owned store after runtime collection. Separate target locks allow other generations
to make progress while one writer is stopped.

The receipt binds the actual parent and mutex inodes, canonical target/transaction,
producer PID/start/boot/namespace/executable and complete new file identity/hash.
The previous target additionally binds content, inode, ctime and receipt digest,
so identical replacement bytes do not grant authority. Relative syscalls use the
pinned directory descriptor. Copied directories/mutexes, changed data, hardlinks,
symlinks and replacement pending files refuse and are preserved.

| Cut | Recovery |
| --- | --- |
| Before a pending name exists | The kernel collects the unnamed inode after its last descriptor closes |
| Complete receipt/data at a pending name | Verify context, original producer absence and target preimage; publish that same inode |
| After final rename | Observe the complete JSON and its retained inode receipt; no runtime effect is replayed |
| Context/object/preimage differs | Preserve objects and retain an unconfirmed result |

New installation locks publish complete claims rather than empty files that are
filled in place. Recovery of an initial claim requires its exact requested
installation/root identity; marker recovery follows validation of that durable
claim and acquisition of its lease. Manager/config recovery validates their
declared configuration. Journal recovery validates canonical IDs/artifacts and
retains independently unconfirmed targets. Reads alone do not replay writes.
Only a same-process failed-call retry can finish its own prior metadata publication
while still live, after reacquiring the original per-target kernel mutex.

The [source review](evidence/m4-metadata-recovery-upstream-review.json) applies
atomic-write-file, Linux and SQLite requirements to this single-file protocol.
Actual local filesystem tests kill real writers at six initial/replacement cuts,
recover original pending inodes, exercise copied/replaced object refusals and
recover interrupted installation-lock/marker publication. These are filesystem
and process checks, not a claim of hardware-backed lifecycle or host power-loss
durability. The dedicated `firecracker-metadata-recovery.yml` release gate adds
five syscall cuts in the actual manager plus the retained 32 real KVM groups;
its acceptance is pending. Earlier unacknowledged allocation effects and the full
remaining M4-M6 scope are unchanged.

The [validation summary](evidence/m4-metadata-recovery-acceptance-summary.json)
binds Windows281/Linux-root351 full checks to 318 inputs each, plus the targeted
actual local filesystem checks. Owned check-image tags are collected. Earlier
failed checks remain unchanged; the final tests use private 0700 fixture
directories, and production ownership/lint requirements are not relaxed.
