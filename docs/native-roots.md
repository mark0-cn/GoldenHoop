# Native VM root ownership and collection

Each new root receives a complete `user.goldenhoop.vmroot.v1` directory attribute
before any marker, descendant or artifact effect. Its receipt binds generation,
path, parent and root device/inode, kernel creation time, nonce, creating process
identity and PID namespace. The persistent generation journal acknowledges that
receipt before later effects. Stores must be trusted local ext4/XFS/Btrfs/overlay/
tmpfs directories with birth-time and xattr support; unsupported operations refuse.
There is no named-directory or timestamp-only ownership fallback.

Recovery opens the same root through its verified parent descriptor. Existing
unrecorded/replaced/copied roots, changed creation evidence, wrong context and
symlink roots are preserved. A live or unreaped original writer retains authority;
read-only recovery does not promote a missing marker to an available VM. An
acknowledged prelaunch root can be collected after writer fencing without
continuing its create. Unacknowledged allocation remains Unknown with its reservation.

Collection durably records intent before destructive effects. It preserves the
original VMM identity even when no live observation exists. A retry rechecks
original process absence or authenticates actual owned processes; a PID file alone
does not authorize adoption or a signal. Existing acknowledged cgroup fences apply.
The collector confirms child reaping/group emptiness before deleting root entries.

Traversal enumerates pinned directories using the existing cap-std dependency and
opens descendants with constrained `openat2`. It unlinks relative to those
descriptors, refuses unexpected mount crossings and checks root ownership throughout.
The final removal is relative to the original trusted parent and requires both
original inode unlink and no-follow path absence. The host's private parent and
producer fencing exclude concurrent legitimate writers; this does not claim an
atomic unlink operation against a malicious privileged host administrator.

The implementation deliberately removes a marker before other root entries.
The durable directory receipt and collection intent, followed by fresh runtime
observations, authorize resuming a partial deletion. They do not claim runtime
absence by themselves. A failed collection remains unconfirmed. `Machine::Drop`
uses the root and cgroup fences and cannot convert a failure into Complete.

The [source review](evidence/m4-root-recovery-upstream-review.json) distinguishes
cap-std's handle-based enumeration from its recursive removal, whose default does
not supply the required mount-crossing guard. The code reuses the former and adds
the required descriptor-resolution and caller-ownership checks.

The [validation summary](evidence/m4-root-recovery-acceptance-summary.json) binds
Windows281/Linux-root357 full checks to 323 inputs. Earlier six actual Linux-root
filesystem/process checks exercise real SIGKILL/reap before a marker and after its
unlink, live/zombie refusal, same-inode resumption and copied/replaced/link refusal.
That targeted report precedes the final mount guard; full checks bind the current
source. The explicitly ignored real bind-mount test is compiled but remains
verified by the dedicated release gate below.

`firecracker-root-recovery.yml` requires two actual mount groups, four release
supervisor/manager recovery or refusal groups, and all 41 retained groups. Pre-ack
refusal is distinct from the observer's separately witnessed empty-fixture rollback.
[Run45980384093](https://github.com/mark0-cn/GoldenHoop/actions/runs/45980384093)
at 2038512 passes all 47 with Complete collection. Its [archive](evidence/m4-root-recovery-45980384093-archive.json)
verifies 355 runtime inputs; separate build-only evidence verifies 325 inputs and
claims no runtime result. The ignored test binary binds 321 compiled inputs.
The actual pre-ack case preserves its original root/reservation, refuses same-intent
recreate, admits an independent VM and refuses a third reservation. Only the
separately witnessed empty fixture is manually rolled back. The pending receipt
and partial-delete cases retain the original root inode; actual replacement refusal
preserves both directories before normal original-root collection.
Host power loss/migration, public prepared-image
placement, snapshots/restore/templates, complete M4 and all M5-M6 remain open.
