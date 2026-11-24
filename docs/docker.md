# Local Docker driver

The Rust driver uses Bollard over the local Docker socket or Windows named pipe. The execution engine must be Linux x86_64. Images must already be cached locally; pulling images and registry credentials belong to administrator-managed image preparation.

Profiles are `local-gvisor` (runsc) and `local-runc-dev` (runc). Ordinary containers require explicit development opt-in. Probe verifies the installed runtime, provisions an actual sandbox, checks effective runtime/resource settings, executes a non-root command with no capabilities and no external network, then pauses, resumes and removes it. A failed probe yields no available capabilities. It never selects another runtime.

The agent image is an administrator-trusted build input. Its static musl agent is copied through a short-lived, labeled bootstrap container into a versioned bundle volume. Workloads mount that volume read-only. The worker overrides image entrypoints, commands and environment values. Image health checks are explicitly disabled; inheriting them would execute image-provided commands as the supervisor identity. Workload image-declared volumes are rejected until an explicit volume policy is supported. Workloads receive no Docker socket, worker credentials or public agent listener.

Every owned resource carries an installation UUID, profile and role. Sandboxes also carry the sandbox UUID, absolute expiration and create-request fingerprint. Inspect/delete/transport verify ownership; create retries verify request identity and cannot restart exited sandboxes. Discovered resources and serialized runtime handles allow worker reconnect without recreating the workload.

CPU, RAM and PIDs are bounded. The agent requires at least 64 MiB and 16 PIDs. Workspace storage is a 128 MiB tmpfs at this stage; temporary files have a separate 32 MiB tmpfs. The root filesystem is read-only. The supervisor has only the six capabilities documented in agent.md; workload processes have no effective capabilities.

## Expiration and cleanup

Run `goldenhoop-reaper --installation-id <uuid>` as an independent host service alongside the control service. It scans both local profiles and removes expired containers even when paused or when the API is unavailable. It also collects expired bootstrap containers. The scan interval defaults to one second; enforcement is subject to host/daemon availability and scan delay. A daemon error is reported as unconfirmed cleanup, never as successful removal.

Do not expose the Docker socket to untrusted users. The reaper runs in the trusted worker boundary and needs Docker management access. Deployment service units and the persistent API integration are still in progress.

Bootstrap containers are removed after successful and failed runs. Bundle volumes are useful installation artifacts; `remove_agent_bundle` is an explicit uninstall/test cleanup operation and refuses while owned sandboxes remain. Tests use fresh installation UUIDs and remove their bundle volumes too. Removal is followed by a runtime absence check. Never run a global Docker prune for GoldenHoop cleanup.

## Actual contract

    docker build --label dev.goldenhoop.build=local-agent -f images/agent/Dockerfile -t goldenhoop-agent:test .
    docker pull debian:bookworm-slim
    cargo run -p goldenhoop-docker --example contract

Set `GOLDENHOOP_TEST_RUNTIME=runsc` only on a gVisor host. Set `GOLDENHOOP_EVIDENCE` to save the JSON evidence. CI builds tests/fixtures/image-policy.Dockerfile and sets `GOLDENHOOP_WORKLOAD_IMAGE` to that image to verify hostile image defaults are overridden. The suite checks an independent workload, command/events/files, opt-in, retries/conflicts, worker reconnect, ownership refusal, pause/resume, repeated deletion and absolute expiration while paused. Cleanup follows returned errors and test panics. Remove the labeled fixture image after the suite.
