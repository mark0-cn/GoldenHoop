# GoldenHoop

A Rust agent sandbox platform with explicit runtime capabilities, independent APIs, and auditable execution.

## Project status

**M0-M1 are implemented and verified; M2 is in progress. The agent, driver, API/worker, Rust/Python SDKs and Rust CLI pass actual runc/gVisor contracts. Live runtime diagnostics are implemented and locally tested; their expanded gVisor gate is next.**

The full target includes local containers, Firecracker microVMs, and Kubernetes; command and file execution; terminals and code contexts; network policy and credential brokering; snapshots, templates, warm pools, batches, and diagnostics.

Runtime support is declared per profile and checked against the host. Missing isolation must fail closed. A successful unit test is not evidence of a working isolation boundary.

## Development

    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace
    cargo run -p goldenhoop-protocol --example export_schema

- [Architecture and decisions](docs/design.md)
- [Milestones and acceptance](docs/roadmap.md)
- [Verification policy](docs/verification.md)
- [Implementation progress](docs/progress.md)
- [Agent execution and actual-runtime tests](docs/agent.md)
- [Local Docker driver and expiration worker](docs/docker.md)
- [Run the authenticated API and runtime worker](docs/control.md)
- [Rust/Python SDKs and client CLI](docs/clients.md)
- [Runtime diagnostics](docs/diagnostics.md)
- [中文说明](README.zh-CN.md)

## License

Apache-2.0. This is an independent project. OpenSandbox is a functional reference; its API and SDK compatibility are not project requirements.
