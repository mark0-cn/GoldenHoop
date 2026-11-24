# GoldenHoop architecture

## Confirmed decisions

GoldenHoop is an independent Rust implementation inspired by OpenSandbox's implemented functionality, with new APIs and Rust/Python SDKs. It does not require migration or upstream SDK compatibility. The reference revision inspected for the initial feature inventory is 8af823ed83f71209772d334df73626f90dd72496.

Target Linux x86_64 first. Serve personal/small-team, single-tenant deployments. Support local containers, Firecracker, and Kubernetes through explicit profiles; publish incrementally through M0-M6.

## Components

The API and gateway authenticate every operation. The core owns desired lifecycle, idempotency, quotas, operations, scheduling and reconciliation. Drivers own provisioning and observations. The sandbox agent owns command/file/session execution. The trusted egress component owns network enforcement and credentials.

Use Tokio/Axum/Serde, Bollard for Docker, kube-rs for Kubernetes, Tonic for remote internal RPC, SQLx for SQLite/PostgreSQL, and object_store for local/S3 artifacts.

Single-host deployments use one active control service, SQLite, and local artifacts. Cluster deployments use one active control service, PostgreSQL, S3-compatible artifacts, an operator, and workers. Host privilege is isolated in workers; remote internal connections require mutual TLS.

## Runtime abstraction

Placement (local/Kubernetes) and isolation (OCI/gVisor/Kata/Firecracker) are different concepts. A named RuntimeProfile binds an allowed combination to observed host capabilities and administrator limits. Drivers are registered at build time and accessed through a stable domain interface.

Required profiles:
- Local Docker with gVisor; an explicitly enabled ordinary-container development profile.
- Local Firecracker with jailer.
- Kubernetes Pod workloads using gVisor/Kata RuntimeClasses.
- Kubernetes Firecracker workloads placed on node workers.

Capabilities include execution, files, PTY, code contexts, isolated sessions, pause, rootfs/volume/memory snapshots, network policy, secret injection, and GPU. Effective support is the intersection of implemented driver behavior, probed environment, and policy. Unsupported requests fail before provisioning; weaker-runtime fallback is forbidden.

## Public surface

A versioned REST API under /v1 exposes profiles, sandboxes, commands, files/directories, sessions, terminals, code contexts, snapshots, templates, volumes, artifacts, pools, batches, network policies, credential bindings, diagnostics and operations. SSE carries resumable execution events. WebSocket carries interactive terminal data. Clients only connect to the gateway; agent ports are not public by default.

Use stable IDs and typed errors. Long operations return operation IDs and support idempotency. Rust/Python SDKs expose synchronous waiting, async waiting, streaming, file transfer and automatic cleanup.

## Lifetimes and execution

Desired state is persisted; actual runtime state is observed and reconciled. Expiration is an absolute timestamp and continues while paused. Workers/operator retain expiry enforcement when the API is down.

Cleanup is separate from business state. A missing worker produces Unknown, not proof of termination. A command's completion requires a terminal result with explicit success/failure; output EOF does not establish success. Disconnected observers do not cancel tasks. Cancellation must collect the process tree; otherwise terminate the sandbox and record escalation.

Persistent shells retain environment/cwd. PTY supports resize and reconnect. Rust adapters use Jupyter services and existing language kernels for stateful code contexts. Isolated sessions use child sandboxes with permissions intersected with their parent and resources charged to the parent.

## Boundaries

Default network is denied. External egress, DNS, direct IPs, IPv6, UDP/QUIC, host/private/link-local/metadata addresses require enforcement outside the workload. Policy must be installed before the workload starts; tightening revokes affected connections.

Credentials stay in the trusted broker, bound to destination/method/path. Workload images, snapshots and logs do not receive host API keys. File operations use authorized roots and directory-handle-based resolution to resist symlink races. Administrator-owned declarations control host mounts.

Snapshots distinguish rootfs, volumes and memory, include content digests and format versions, and validate CPU/VMM compatibility where applicable. Restores rotate identities/tokens/network allocation. Existing network connections are not promised to survive VM restore.

Warm pools allocate clean instances and destroy or rebuild used allocations. Browser/desktop functionality is supplied by workload images and authorized endpoints.

## Defaults

1 CPU, 1 GiB memory, a 256 PID/task budget, 30-minute TTL. Accounting is profile-specific; Docker/gVisor budgets include runtime/supervisor overhead and bound host tasks rather than promising a guest process count (see docker.md). The administrator may set profile-specific defaults/limits. API binds loopback by default; remote exposure requires TLS. API keys are scoped and revocable. Apache-2.0 license.
