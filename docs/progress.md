# Progress

## Active objective

Implement the complete M0-M6 design in the dedicated mark0-cn/GoldenHoop repository and push staged, verified commits.

## Current stage

M0 is implemented and pushed in commit 94cb4e75f07e6df447d9beca6b0453a0e6014012: independent repository, domain contracts, state/capability invariants, driver boundary, schema export and CI definition.

- cargo test --workspace: 13 integration tests passed (8 orchestration invariants, 5 wire-contract tests).
- cargo fmt --all --check: passed.
- cargo clippy --workspace --all-targets -- -D warnings: passed.
- Developer environment: Windows Rust 1.99.1; Linux Docker Desktop 29.9.2; gVisor absent; KVM not exposed by the Docker Desktop WSL host.
- GitHub CI: Ubuntu and Windows passed in [run 45316934899](https://github.com/mark0-cn/GoldenHoop/actions/runs/45316934899).

M1 is in progress. The Rust sandbox agent now supports a private Unix RPC bridge, literal commands, execution events, binary files, output bounds, cancellation and timeout descendant collection. Normal commands run sequentially as UID 1000 with zero effective capabilities. File operations are constrained by directory capabilities.

- Windows Rust 1.99.1: formatting, clippy with warnings denied, and 14 tests passed.
- Linux Rust 1.100.0 inside the image build: formatting, clippy with warnings denied, and 15 tests passed.
- The actual Docker/runc agent contract passed all 10 cases on Docker Desktop. [Evidence](evidence/m1-agent-runc-windows-docker.json) records source hashes, runtime versions, individual results and confirmed container cleanup.
- A separate CI matrix exercises runc and gVisor. gVisor results are pending until observed; the local host has no runsc runtime.
- No M1 API/CLI/SDK release is claimed yet. Firecracker/KVM and Kubernetes remain unverified and unimplemented.

## Next actions

Push the agent increment, observe both CI workflows, then implement M1's Docker driver, persistent API, CLI and Rust/Python SDK execution loop. Missing gVisor/KVM evidence remains a release gate; it does not narrow M1-M6.
