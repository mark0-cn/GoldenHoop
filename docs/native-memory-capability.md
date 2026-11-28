# Native memory capability

`local-firecracker` advertises `memory_snapshot` only when checkpoint storage is
configured and an actual native continuation probe has passed for the exact
configuration, host boot and PID namespace. Basic command/file/pause support does
not imply memory support. A failed or uncollected probe leaves memory support
absent while preserving independently verified basic support.

For the reference baseline image, enable storage in the existing native driver
configuration with `"checkpoints": {"max_bytes": 4294967296, "max_checkpoints": 2}`.
Size the byte budget for both captured files and restored target backing, and
the count budget for concurrent captures. A setting alone does not grant support:
the worker must complete its real startup probe. Operators can inspect the private
probe receipt's bounded `error` field when memory support remains absent.

The manager publishes a private probe intent before allocating anything. It
starts one original guest command that generates a random token in guest RAM,
writes a one-time disk marker, and waits for a release file. It captures the live
source, positively collects that source, and restores one new native generation.
The restored original command must keep its ID and start time, see the disk
payload and single marker, and print the original RAM token after release. The
manager never sends Start to that target. Execution completion requires explicit
success, exit code zero and completed descendant cleanup.

Support is recorded only after positive source and target collection, permanent
target closure and snapshot object/quota collection. Completed receipts are
private evidence under `memory-probes`; they contain no workload launch authority.
An interrupted probe is recovered by collecting its original owners, without
continuing the interrupted experiment. An exact completed receipt can be reused
on the same configuration/boot only after re-observing physical collection,
closure and zero snapshot reservation. Probes are serialized within the manager.

Public restore requests preserve the expected original native source handle in
their private target binding and request digest. A validly encoded handle for
another generation fails against the captured manifest before target allocation
or claim. Optional absent bindings preserve legacy private request serialization
and digest; they do not acquire stronger public source proof.

Temporary native VM capacity and capture validation slot pressure keep the
original pending target, operation and references. They can reconcile on the
same idempotency key until TTL or cancellation. Invalid identity, unsupported
constraints and missing retained executions still fail and require collection.
Host artifact retention remains a composed worker capability; it does not become
a native guest capability during restoration.

`firecracker-memory-public.yml` is the separate actual KVM gate. It exercises the
real API, Python SDK and Rust CLI: probed capability, capture source fencing,
explicit source collection, foreign generation refusal, all-resource restoration
creation, exact new-target grants, stable retry, retained execution IDs/events/
cancel, manager SIGKILL/reconnect, RAM/disk continuation and physical VM/object
collection. Its evidence binds the source and all runtime inputs. A skipped or
failed run is unverified; compilation and synthetic fixtures are not KVM evidence.

This gate covers public memory continuation. Rootfs/volume snapshots, templates,
combined M4 acceptance and complete M5-M6 remain separate required work.
