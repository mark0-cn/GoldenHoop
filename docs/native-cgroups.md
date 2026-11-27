# Native generation cgroup receipts

VM and supervisor journals now acknowledge each actual cgroup inode before
writing limits, joining processes or launching the next runtime component.
The receipt is part of the existing exact installation/generation journal;
recovery also requires the same host boot. Existing objects without a receipt,
or with a different inode, are preserved as unconfirmed. A missing receipt does
not authorize reconstruction or replay of a create.

The implementation pins the verified cgroup directory descriptor. Its control
files use `openat2` with BENEATH, NO_SYMLINKS, NO_MAGICLINKS and NO_XDEV;
unsupported kernels refuse. The actual descriptor must refer to cgroup v2.
This applies the descriptor and filesystem constraints in
[OpenContainers cgroups at 866dd224](https://github.com/opencontainers/cgroups/blob/866dd224e3dce8f7afaff77a4ddd38087d520c33/file.go)
to GoldenHoop's acknowledged object ownership. It does not assume that an
upstream pathname manager supplies GoldenHoop's journal recovery semantics.

Budget, membership, enumeration, empty observation and `cgroup.kill` operations
use this handle. Collection checks it before direct VMM signals as well.
`Machine::Drop` uses the same fence, so a failed collection cannot be followed
by an unrestricted pathname kill of a replacement. Supervisor collection only
removes the acknowledged empty object. The
[Linux contract](https://docs.kernel.org/admin-guide/cgroup-v2.html) makes
`cgroup.kill` a whole-tree SIGKILL operation; inode ownership must precede it.
An empty group alone does not prove child reaping or complete VM collection.

The [validation summary](evidence/m4-cgroup-receipts-acceptance-summary.json)
binds passing Windows281/Linux-root353 full checks to 320 inputs. Two ordinary
Linux tests verify actual descriptor resolution, link/escape refusal and
ordinary-directory refusal. They do not prove actual cgroup mutation.

The explicitly ignored Rust test in `machine/cgroup_tests.rs` requires a separate
root/writable-cgroup gate. It creates only its UUID-owned group and sleep
processes, verifies missing/changed/old-boot refusal with the child alive,
confirms real scoped SIGKILL/reap/removal, recreates that same path with a new
inode and a new child, and checks stale reads/kills/removal plus actual
`Machine::Drop` preserve that replacement. Normal fixture cleanup then kills
and reaps its own child and removes its acknowledged empty replacement group.
The Python observer independently samples final group and original PID/start
absence; it implements no runtime mutation.

`firecracker-cgroup-receipts.yml` requires these four groups plus all 37 retained
metadata/KVM groups. [Run45971316239](https://github.com/mark0-cn/GoldenHoop/actions/runs/45971316239)
at 75bda2b passes all 41 with Complete collection; its [archive](evidence/m4-cgroup-receipts-45971316239-archive.json)
verifies 350 runtime inputs. The separate source-fenced build-only report verifies 320
inputs and records no runtime result. The actual root test binary binds 318 compiled
inputs, while ordinary full checks bind 320 Rust/build inputs. The observer confirms
the final group and original PID/start are absent. The old failed build remains
Failed/NotExecuted. VM-root inode receipts,
irreducible effects before allocation acknowledgement, public prepared-image
placement, snapshots/restore/templates, combined M4 and all M5-M6 remain open.
