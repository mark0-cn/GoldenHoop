# Verification

Record the commit, profile, runtime/image versions, host/kernel, resource limits, inputs, expected result and observations.

Result categories: passed, failed, unknown, environment unavailable, capability unsupported. Do not count skipped runtime tests as release passes. Mock drivers test orchestration only.

Gates:
- Protocol/state/capability unit tests.
- Identical core create/execute/file/expiry/delete contract on actual runtime families.
- Crash, retry, race, reconciliation, and confirmed cleanup scenarios.
- File traversal/symlink races; process cleanup; cross-session isolation; DNS/IP/IPv6/UDP/QUIC; credential and snapshot hygiene.
- Fixed-environment P50/P95 startup, throughput, resource usage, normal-task completion and policy false positives.

The current developer host has Windows Rust and a Linux Docker Desktop engine. The initial probe reported no runsc runtime. gVisor, Firecracker/KVM and Kubernetes need their own actual environments; Docker success alone does not verify them.
