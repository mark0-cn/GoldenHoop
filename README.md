# GoldenHoop

A Rust agent sandbox platform with explicit runtime capabilities, independent APIs, and auditable execution.

## Project status

**M0 is implemented; M1 is in progress. The Rust agent passes actual runc/gVisor contracts, and the Docker driver passes local lifecycle/recovery tests. No complete API/SDK release is available yet.**

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
- [中文说明](README.zh-CN.md)

## License

Apache-2.0. This is an independent project. OpenSandbox is a functional reference; its API and SDK compatibility are not project requirements.
