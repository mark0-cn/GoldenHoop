# GoldenHoop

A Rust agent sandbox platform with explicit runtime capabilities, independent APIs, and auditable execution.

## Project status

**M0-M3 are accepted for the tested Linux runc-development and gVisor configurations. The combined Stage also preserves the S3-compatible API/artifact baseline. M3 includes protected five-level sandboxes, default-deny egress, live policy recovery, transparent bound HTTP/TLS credentials, scoped/revocable keys and durable redacted audit. Firecracker, Kubernetes and the M4-M6 release gates remain unaccepted.**

Code contexts have durable public APIs and Rust/Python/CLI bindings. Python's existing runc/gVisor and S3-compatible loops pass, including restart recovery and cleanup. New Python, Java, Go, TypeScript, Bash and JavaScript adapters use [explicitly probed language support](docs/code-languages.md) from a cached kernel image; support is disabled by default. [Isolated child sandboxes](docs/isolated-sessions.md) add reserved resources, inherited lifecycle and immutable feature ceilings, behind a separate actual runtime probe. See [current verification](docs/progress.md).

The [reference coverage checklist](docs/reference-coverage.md) retains the Java, Go, TypeScript, Bash and JavaScript context adapters and all M4-M6 release gates. An installed interpreter or a skipped runtime test is not a completed feature.

[Versioned network policy and optional protected creation](docs/network-policy.md) distinguish durable intent from actual native application. Without administrator network configuration, `NetworkPolicy` remains disabled. A configured worker publishes support only after actual application and confirmed probe collection. [M3 credentials and audit](docs/m3-delivery.md) require a private vault and an actual ordinary-UID HTTP/TLS receiver probe before advertising `SecretInjection`; missing or failed probes withhold it. The combined Stage accepts these native gates on the tested configurations; each deployment still needs its configured actual probes.

The full target includes local containers, Firecracker microVMs, and Kubernetes; command and file execution; terminals and code contexts; network policy and credential brokering; snapshots, templates, warm pools, batches, and diagnostics.

Runtime support is declared per profile and checked against the host. Missing isolation must fail closed. A successful unit test is not evidence of a working isolation boundary.

M4 implementation has started with [Rust KVM observations and private Firecracker control](docs/m4-delivery.md). Jailed guest/runtime, snapshots and template acceptance remain required; no Firecracker profile is advertised.

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
- [Code-language images and actual capability probes](docs/code-languages.md)
- [Runtime diagnostics](docs/diagnostics.md)
- [Retained artifacts and storage](docs/artifacts.md)
- [Interactive sessions, terminal sockets and recovery](docs/sessions.md)
- [Code context implementation and remaining work](docs/code-contexts.md)
- [中文说明](README.zh-CN.md)

## License

Apache-2.0. This is an independent project. OpenSandbox is a functional reference; its API and SDK compatibility are not project requirements.
