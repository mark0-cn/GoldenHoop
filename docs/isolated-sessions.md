# Isolated child sandboxes

This is the implementation contract for the next M2 increment. Protocol, validation and schema-5 reservation primitives are implemented; runtime/worker/API/client integration and actual isolation gates remain pending. IsolatedSessions is not advertised. Python code contexts retain separate interpreter state inside one shared source sandbox; an isolated session will use a separate child sandbox and the existing sandbox command/file/context interfaces.

## Allocation and inheritance

A parent reserves an additional `child_budget` at creation. Its own `resources` remain its workload's hard limits. The installation charges their sum to that parent, including the unused reservation. Each direct child reserves its own workload limits plus any budget for grandchildren from the parent's child reservation. Allocation uses durable transactions and counts uncollected/unknown children until confirmed absence.

For example, a parent with 1 CPU/1 GiB/256 tasks and a child reservation of 1 CPU/1 GiB/256 tasks charges 2 CPU/2 GiB/512 tasks. The parent keeps its original workload limits. One child can consume the reservation, or several children can share it within those bounds. The global live-sandbox count also includes children. Child creation is subject to both the reservation and live-object quota.

The sum of actual workload limits in a tree cannot exceed its root's charged envelope. No live parent cgroup resize is required. A child allocation is reusable only after its runtime and descendants are confirmed removed. Failed provisioning and crash recovery use the same collection gate. The bounded initial hierarchy is at most four edges deep, with at most 64 historical direct children per parent and the existing global limit of 16 live/uncollected sandbox records.

Children inherit their parent's runtime profile and default image. Profile substitution is refused. Each child has a fresh workspace, temporary tree, PID/IPC/network namespaces and agent endpoint; the trusted agent bundle can remain a shared read-only installation artifact. Workspace content is transferred explicitly through the file/artifact interfaces. Each child uses its own runtime cgroup and receives no parent/host API credentials or management sockets.

An optional immutable `feature_limit` restricts callable platform capabilities. Effective child features intersect the parent ceiling, requested ceiling and currently verified profile support. This controls API operations; it does not make a writable workspace read-only when code execution is granted. Filesystem and network security continue to require actual runtime enforcement. The current child network policy inherits default denial; broader policy requests fail. M3 must preserve ancestor constraints when dynamic egress/credential policies are added.

## Lifetime and recovery

Child expiry is at most its parent's original absolute expiry. A parent pause blocks new work in its descendants and pauses their runtimes. A child's own desired pause state is retained, so resuming an ancestor does not resume a child the caller paused separately. TTL continues while paused and while the API is offline.

Parent termination, expiry or confirmed unexpected loss closes the subtree. A parent cleanup result cannot become Complete while a direct child remains uncollected; the same rule applies recursively. User termination is known cancellation after collection, expiry can confirm timeout, and unexpected runtime loss cannot synthesize successful code results. Previously dispatched work never replays into a replacement runtime.

Hierarchy, reservations, request identities and desired state survive worker/API restart. Unknown runtime or collection observations remain charged. The independent runtime reaper uses the bounded child deadline too. Host/daemon downtime and destruction latency affect final acknowledgement, as for ordinary sandbox TTL.

## Planned public surface

Root create adds optional child_budget and feature_limit fields. Empty defaults preserve current request fingerprints and ordinary sandbox behavior. These non-default controls are refused until the complete implementation and actual capability gate are available.

- POST /v1/sandboxes/{parent}/isolated-sessions creates an idempotent child and returns its sandbox/create operation.
- GET /v1/sandboxes/{parent}/isolated-sessions pages its direct children.
- GET /v1/sandboxes/{id}/scope returns parent/root identity, immutable ceiling and reservation/usage observations.
- Existing sandbox commands, files, sessions, contexts, diagnostics and deletion use the child sandbox UUID.

CreateIsolatedSession defaults to the parent's profile/image and the normal workload resources; callers select a smaller child allocation when needed. Its optional child_budget reserves part of this allocation for the next generation as an additional amount, subject to the parent's available reservation. Capabilities, deadline and quotas are checked before provisioning. Unsupported profile changes or broader feature/policy requests fail without allocating a runtime.

## Required evidence

File-backed tests must cover concurrent reservation, rollback, stable create replay, root charging without double counting, child limits/history/depth, unknown collection charging, ancestor pause/termination and schema-4 migration preserving all existing records. Effective feature checks must cover every workload entry point before the capability can be advertised.

Actual runc and gVisor tests must prove separate files/processes/IPC, denied egress, resource limits, parent/child failure independence, child cancellation, cascade deletion, expiry while paused/offline, restart recovery without duplicate execution and cleanup after failed provisioning. Rust, Python sync/async and CLI must execute a real child loop. Capability advertisement requires the complete host path and an actual runtime gate; unsupported or skipped observations do not count as passes.
