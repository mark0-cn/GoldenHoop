# Milestones and acceptance

The objective is the complete platform described in design.md. An early milestone does not redefine v1.0 completion.

M0-M3 have accepted evidence for the tested Linux runc-development/gVisor profiles and retained S3-compatible regression. [M3 Stage acceptance](evidence/m3-native-45839996451-archive.json) passes all seven jobs and 63 source-verified reports with Complete collection. M4-M6 remain unaccepted; the Firecracker/KVM, Kubernetes and release objectives below are unchanged.

| Milestone | Deliverable | Required evidence |
| --- | --- | --- |
| M0 | Domain/API models, state machine, capability/driver interfaces, repository CI and test framework | Format, lint, protocol and invariant tests |
| M1 | Rust API and agent, Docker/gVisor lifecycle, commands, files, TTL, CLI, Rust/Python SDKs | Real create/execute/file/delete cycle, expiry/restart recovery, explicit unavailable-profile refusal |
| M2 | Shell sessions, PTY, code contexts, isolated sessions, diagnostics, artifacts | Actual interaction, retained state and isolation tests |
| M3 | Default-deny egress, dynamic policy, credential broker, audit | Actual filesystem/network/credential boundary and failure-path tests |
| M4 | Firecracker driver, image preparation, disk/memory snapshots, templates | Real KVM driver suite and restore/identity tests |
| M5 | Rust Kubernetes operator, Pod and node-VM workloads, pools, batches, volumes | Real cluster suite, allocation hygiene and recovery tests |
| M6 | Installation/upgrades, documentation, benchmarks, complete support matrix, release | Requirement-by-requirement audit of all supported capabilities |

## v1.0 gates

Every implemented reference feature must work on at least one profile. Each of the three runtime families must pass the shared execution contract. A capability that lacks runtime evidence stays unverified, even if its implementation compiles. Unimplemented placeholder APIs in the reference are not existing functionality.

## Out of the initial deployment scope

Multi-tenant public hosting, native Windows/macOS execution hosts, custom hypervisors, and upstream API/SDK migration. These exclusions do not remove the runtime families or feature groups above.
