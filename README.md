# GoldenHoop

A Rust agent sandbox platform with explicit runtime capabilities, independent APIs, and auditable execution.

## Project status

**M0-M1 are implemented and verified; M2 is in progress. Commands, files, diagnostics, retained artifacts, persistent shells, PTYs, Python code contexts and isolated child sandboxes pass actual runc/gVisor contracts through the API, Rust/Python SDKs and CLI. S3-compatible API/client tests also pass on Linux. Additional code languages remain part of M2 acceptance.**

Python code contexts have durable public APIs and Rust/Python/CLI bindings. Actual runc/gVisor and S3-compatible API/client loops pass, including restart recovery and cleanup. Enable contexts with an explicit cached kernel-probe image. [Isolated child sandboxes](docs/isolated-sessions.md) add reserved resources, inherited lifecycle and immutable feature ceilings, behind a separate actual runtime probe. See [current verification](docs/progress.md).

The [reference coverage checklist](docs/reference-coverage.md) retains the Java, Go, TypeScript, Bash and JavaScript context adapters and all M3-M6 gates. An installed interpreter or a skipped runtime test is not a completed feature.

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
- [Retained artifacts and storage](docs/artifacts.md)
- [Interactive sessions, terminal sockets and recovery](docs/sessions.md)
- [Code context implementation and remaining work](docs/code-contexts.md)
- [中文说明](README.zh-CN.md)

## License

Apache-2.0. This is an independent project. OpenSandbox is a functional reference; its API and SDK compatibility are not project requirements.
