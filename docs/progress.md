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
- The agent increment is pushed in commit 65c559aa57756a447c9a5d391e097bb2e993ab77. [CI run 45319722824](https://github.com/mark0-cn/GoldenHoop/actions/runs/45319722824) passed on Windows and Ubuntu.
- Both runc and actual gVisor agent suites passed all 10 cases with confirmed cleanup in [run 45319722773](https://github.com/mark0-cn/GoldenHoop/actions/runs/45319722773). [Raw CI evidence](evidence/ci-45319722773/agent-runsc/agent-runsc.json) records runsc release-20261116.0. The local host still has no runsc runtime.
- The Docker driver now provisions a trusted static musl agent into independent Linux workload images, validates ownership and create retries, reconnects through runtime labels, pauses/resumes and confirms removal. A separate Rust expiration worker scans absolute deadlines outside the workload.
- The local actual driver contract passed 14 cases, including a fixture with a conflicting entrypoint, environment and image health check. Image health checks are explicitly disabled so they cannot execute as supervisor root. [Driver evidence](evidence/m1-driver-runc-windows-docker.json) includes source hashes and image identities. All created containers and bundle volumes were removed, and the fixture image was deleted after validation.
- The static agent also passed all 10 actual local cases. [Static-agent evidence](evidence/m1-agent-static-runc-windows-docker.json). The expanded CI matrix will exercise the static agent and Rust driver on gVisor before that driver profile is counted as verified.
- The expanded matrix has now passed: [run 45321663501](https://github.com/mark0-cn/GoldenHoop/actions/runs/45321663501) verified both runc and gVisor with 10 agent cases and 14 driver cases each, including cleanup of test containers, bundle volumes and the fixture image. [Raw gVisor driver evidence](evidence/ci-45321663501/agent-runsc/driver-runsc.json). [Windows/Ubuntu CI 45321663515](https://github.com/mark0-cn/GoldenHoop/actions/runs/45321663515) also passed for Docker increment 83d4aa1ef1099f5fd5d31185b517c2dc2c5f14b7.
- A SQLx/SQLite store now persists installation identity, desired/observed lifecycle, operations, idempotency, cancellation, execution results and event cursors. Seven durability/race tests pass locally, in addition to the existing domain/agent tests. They include real database close/reopen and confirmed removal of the temporary database directory. [Persistence design](store.md).
- Persistence commit e1c27d23daac141080610fcd983c3b9ea3b69284 passed [Windows/Ubuntu CI 45324136552](https://github.com/mark0-cn/GoldenHoop/actions/runs/45324136552). In [runtime run 45324136353](https://github.com/mark0-cn/GoldenHoop/actions/runs/45324136353), both agent suites and the runc driver suite passed, while the gVisor driver returned a backend error. Both cleanup gates passed. Its cause is still unknown; [the failed-step log](evidence/ci-45324136353/failed-step.json) is retained with its raw-content hash, and contract phase/backend diagnostics are being added before the next run. This run is not counted as a gVisor driver pass.
- Diagnostics in [run 45326463769](https://github.com/mark0-cn/GoldenHoop/actions/runs/45326463769) reproduced a gVisor paused-expiry deletion failure: Docker returned HTTP 500 because the runtime PID was a zombie. Final cleanup on a subsequent attempt succeeded. [Diagnostic log](evidence/ci-45326463769/failed-step.json). Deletion now serializes requests per sandbox, uses canonical IDs, retries bounded transient responses and still requires confirmed absence. The fix awaits actual-runtime CI evidence.
- No M1 API/CLI/SDK release is claimed yet. Firecracker/KVM and Kubernetes remain unverified and unimplemented.

## Next actions

Push the persistence increment, observe CI, then implement the independent API/worker services, CLI and Rust/Python SDK execution loop. Missing Firecracker/KVM and Kubernetes evidence remains a release gate; it does not narrow M1-M6.
