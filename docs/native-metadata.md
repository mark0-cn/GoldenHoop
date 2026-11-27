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
