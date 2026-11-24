# Code context implementation plan

Code contexts are the next M2 increment and are not implemented or advertised yet. This plan preserves the Rust production-code requirement while using existing language kernels as workload dependencies. It does not mark M2 complete.

The initial goldenhoop-jupyter crate implements bounded request framing and JSON-frame HMAC verification. Three portable tests cover an independently computed Python-stdlib signature vector, exact-byte verification, unsigned/tampered/wrong-key refusal, bounds and the protocol's unsigned routing/buffer scope.

A Linux-only experimental Rust peer now connects over IPC to an actual IPyKernel workload. The [local runc experiment](evidence/m2-kernel-ipc-runc-windows-docker.json) observed authenticated kernel-info plus matching output-idle readiness, two snippets retaining state and returning 42, and a third snippet reporting the expected ValueError. Completion requires both the matching execute reply and output idle. Shutdown observed process exit 0 and private-file absence; the harness confirmed container and fixture-image removal. The workload used UID 1000, no network, a read-only root, dropped capabilities and bounded cgroup resources. The actual kernel reported Jupyter protocol 5.3. This experiment is not the production agent context lifecycle, scoped UID collection, durable execution or public API. The expanded gVisor experiment remains pending.

## Execution boundary

A context owns one long-lived Jupyter-compatible kernel inside its source sandbox. The Rust agent owns startup, authenticated transport, queues, deadlines, observations and cleanup. The host worker only uses typed private agent requests and persists observations; it does not connect to workload-selected URLs. Kernel dependencies belong to the workload image. Missing dependencies must fail explicitly without changing runtime or interpreter.

Contexts retain interpreter state across snippets. They share the source workspace and its CPU/memory/task limits. They provide separate interpreter namespaces; isolated child sandboxes remain the separate M2 feature for a stronger execution boundary.

Normal commands/shells currently use UID 1000 and serialize because cleanup collects that UID's descendants. Kernels need a bounded agent-assigned UID pool with shared workspace GID 1000, so collecting one context cannot terminate another context or a normal command. Callers cannot select a UID. Launches still clear inherited environment, drop supplementary groups/capabilities and preserve no-new-privileges. Slots remain reserved until descendant and private-file cleanup is actually confirmed. Unconfirmed cleanup escalates to whole-sandbox removal.

## Private kernel transport

Use a Rust Jupyter wire adapter with a pure Rust ZeroMQ transport. Kernel sockets use generated Unix paths in a private per-context directory. A root-owned parent under the sandbox's /tmp allows traversal but prevents workloads from renaming context directories; each child is mode 0700 and owned by its kernel UID. Connection files are mode 0600 and contain only a fresh guest-local HMAC key. The existing private agent socket directory keeps its 0700/0600 boundary.

The adapter accepts only its generated IPC paths, fixed channel assignments and hmac-sha256. It verifies signatures over the original serialized JSON frames before parsing, correlates parent request IDs and tracks the kernel session epoch. Frame counts, bytes, JSON and output spools are bounded. Unknown optional protocol messages cannot establish readiness or completion. No host API/provider credential enters the kernel image, environment, connection file or output.

Startup must observe an authenticated kernel-info reply and usable output subscription. A kernel launch or connection-file write alone is insufficient. The actual implementation must handle subscription readiness without assuming a sleep proves delivery. Protocol-version negotiation must support the selected real fixture and reject incompatible versions explicitly.

The [Jupyter messaging specification](https://jupyter-client.readthedocs.io/en/stable/messaging.html) defines the channel/framing/authentication contract. The [zeromq crate API](https://docs.rs/zeromq/latest/zeromq/) exposes the Rust socket roles. The experiment uses zeromq 0.7 with only Tokio and IPC transport enabled. Production review must still establish transport allocation bounds before advertising them; codec checks after message assembly alone do not establish a preallocation bound. [IPyKernel connection documentation](https://ipykernel.readthedocs.io/en/stable/api/ipykernel.html) describes kernel connection files. The linked specifications support the design; actual runtime observations support the narrower experiment described above.

## Results and lifetimes

Code-run results are separate domain types from OS command executions. A kernel-reported successful reply is an interpreter observation, not process exit, malicious-code detection or independent correctness verification. A normal run completes only after matching authenticated execute-reply and output-idle observations. The kernel process remains alive and its resource cleanup remains a context-lifetime concern.

Context events have a durable, resumable context-wide cursor and optional originating run ID. This permits late/background output without mutating an already completed run result. A run's collected output is bounded by its observed idle cursor; subsequent output remains visible through context events with provenance. Unknown/mismatched messages, stream EOF and transport errors cannot synthesize success.

Cancellation and deadline expiry initially terminate the whole context and collect its UID's descendants. This deliberately discards that interpreter's state and must be visible in the result. A graceful interrupt cannot be called complete while escaped background children remain unaccounted for. Other contexts and the source sandbox may continue only after confirmed scoped collection.

## Durable control and validation

Create, run, delete and cancellation intent need stable IDs, idempotency and bounded queues before delivery. Agent-side request memoization prevents replay after a worker restart; a missing previously running kernel cannot be silently relaunched. Desired close wins over late kernel replies. Successful context deletion requires actual process and private-directory absence; unknown cleanup stays charged.

Required tests include two snippets sharing state, independent context namespaces, command/context coexistence, concurrent contexts, real stdout/stderr/results/errors, authenticated message and parent-ID refusal, bounded output, actual worker/API downtime, no duplicate snippet execution, kernel crash, timeout/cancel with setsid descendants, context deletion races, and source pause/expiry. All supported clients must execute a real loop. Actual runc and gVisor gates precede capability advertisement as verified. Fixture images, private connection files, containers, volumes and temporary directories must be collected on both successful and failed runs. Unsupported kernels and missing runtime evidence remain unverified.
