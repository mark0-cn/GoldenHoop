# Local Docker driver

The Rust driver uses Bollard over the local Docker socket or Windows named pipe. The execution engine must be Linux x86_64. Images must already be cached locally; pulling images and registry credentials belong to administrator-managed image preparation.

Profiles are `local-gvisor` (runsc) and `local-runc-dev` (runc). Ordinary containers require explicit development opt-in. Probe verifies the installed runtime, provisions an actual sandbox, checks effective runtime/resource settings, executes a non-root command with no capabilities and no external network, then pauses, resumes and removes it. A failed probe yields no available capabilities. It never selects another runtime.

The optional native `probe_code_contexts(image)` gate must follow the mandatory probe. It uses an administrator-selected cached kernel image in a fresh owned sandbox, checks the kernel UID, state across snippets, non-duplicated replay, stdout/rich result, expected exception and matching completion/collection events, then confirms whole-sandbox absence. Missing images/dependencies, ambiguous results or incomplete collection leave CodeContexts absent. A failed re-probe withdraws the prior optional capability while preserving independently verified mandatory capabilities. Probes serialize per driver; `profile_snapshot` reads cached observations without running a new check. The current worker does not invoke this optional gate or expose public context routes yet.

The agent image is an administrator-trusted build input. Its static musl agent is copied through a short-lived, labeled bootstrap container into a versioned bundle volume. Workloads mount that volume read-only. The worker overrides image entrypoints, commands and environment values. Image health checks are explicitly disabled; inheriting them would execute image-provided commands as the supervisor identity. Workload image-declared volumes are rejected until an explicit volume policy is supported. Workloads receive no Docker socket, worker credentials or public agent listener.

Every owned resource carries an installation UUID, profile and role. Sandboxes also carry the sandbox UUID, absolute expiration and create-request fingerprint. Inspect/delete/transport verify ownership; create retries verify request identity and cannot restart exited sandboxes. Discovered resources and serialized runtime handles allow worker reconnect without recreating the workload.

CPU, RAM and PIDs are bounded. The agent requires at least 64 MiB and 16 PIDs. Workspace storage is a 128 MiB tmpfs at this stage; temporary files have a separate 32 MiB tmpfs. The root filesystem is read-only. The supervisor has only the six capabilities documented in agent.md; workload processes have no effective capabilities.

Resource budgets apply to the whole runtime cgroup, including supervisor/runtime overhead. `pids` is a host task budget, not a promise of that many guest processes. gVisor represents guest tasks with goroutines and, depending on its platform, additional host threads/address-space stubs; see its [resource model](https://gvisor.dev/docs/architecture_guide/resources/). Runtime-specific overhead can exhaust a host task budget before a guest reaches the same process count. An observed unexpected runtime exit records its exit code and Docker OOM flag before removal; an absent flag is not evidence of an OOM.

Hard task pressure can also terminate the gVisor runtime itself. In the 128-task/1-GiB [actual CI case](evidence/ci-45333147552/agent-runsc/api-runsc.json), Docker recorded exit code 2 with OOMKilled=false. The worker reported execution failure and confirmed whole-sandbox removal. This is a resource-exhaustion failure, not graceful guest fork refusal or successful command cancellation. Do not size a task budget as if it excluded runtime overhead.

## Expiration and cleanup

Run `goldenhoop-reaper --installation-id <uuid>` as an independent host service alongside the control service. It scans both local profiles and removes expired containers even when paused or when the API is unavailable. It also collects expired bootstrap containers. The scan interval defaults to one second; enforcement is subject to host/daemon availability and scan delay. A daemon error is reported as unconfirmed cleanup, never as successful removal.

Do not expose the Docker socket to untrusted users. The reaper runs in the trusted worker boundary and needs Docker management access. The API/worker integration is implemented; deployment service units remain part of M6.

Bootstrap containers are removed after successful and failed runs. Bundle volumes are useful installation artifacts; `remove_agent_bundle` is an explicit uninstall/test cleanup operation and refuses while owned sandboxes remain. Tests use fresh installation UUIDs and remove their bundle volumes too. Removal is followed by a runtime absence check. Never run a global Docker prune for GoldenHoop cleanup.

Sandbox deletion is serialized per resource within a driver and uses its canonical Docker ID after checking labels. Docker can transiently report a zombie runtime process or concurrent removal during gVisor destruction. The driver makes at most four removal attempts for 404/409/500 responses and confirms actual absence after each attempt. It does not resume a paused guest to delete it and does not treat an error as successful cleanup.

## Actual contract

The optional gate has a separate actual contract:

    docker build -f images/kernel/Dockerfile -t goldenhoop-kernel-fixture:test .
    cargo run --locked -p goldenhoop-docker --example context_probe

Its five cases cover the default unadvertised state, missing cached image without pulling/fallback, missing dependencies with cleanup, an actual state/result/error loop, and withdrawal after failed re-probe. The local runc suite passes with owned containers/bundle volumes removed; its task-created fixture image was separately removed after verifying its label and absence of consumers. Actual gVisor optional-probe CI is a separate pending gate. The fixture is an administrator-side test dependency; the library does not delete caller-selected cached images.

    docker build --label dev.goldenhoop.build=local-agent -f images/agent/Dockerfile -t goldenhoop-agent:test .
    docker pull debian:bookworm-slim
    cargo run -p goldenhoop-docker --example contract

Set `GOLDENHOOP_TEST_RUNTIME=runsc` only on a gVisor host. Set `GOLDENHOOP_EVIDENCE` to save the JSON evidence. CI builds tests/fixtures/image-policy.Dockerfile and sets `GOLDENHOOP_WORKLOAD_IMAGE` to that image to verify hostile image defaults are overridden. The suite checks an independent workload, command/events/files, opt-in, retries/conflicts, worker reconnect, ownership refusal, pause/resume, repeated deletion and absolute expiration while paused. Cleanup follows returned errors and test panics. Remove the labeled fixture image after the suite.
