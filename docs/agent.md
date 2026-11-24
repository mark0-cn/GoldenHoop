# Sandbox execution agent

The Rust agent runs as the sandbox supervisor. Its root-owned Unix socket is under /run/goldenhoop (0700 directory, 0600 socket). The worker uses a root Docker exec bridge to issue a bounded JSON request. No agent TCP port or host daemon socket is mounted in the workload.

Normal commands use literal argv, a cleared environment with a small baseline, a workspace directory capability, UID/GID 1000, empty supplementary groups, and no-new-privileges from the runtime. They execute sequentially within each sandbox, while distinct sandboxes run independently. This preserves ordinary file ownership and enables complete descendant collection by workload UID, including children that change process groups.

The runtime must provide a private PID namespace, drop all capabilities except SETUID, SETGID, KILL, CHOWN, FOWNER and DAC_OVERRIDE for the trusted supervisor, limit CPU/memory/PIDs, deny networking, protect the rootfs, and mount dedicated runtime/workspace tmpfs filesystems. Ownership and file access capabilities allow the file broker to operate on workload-owned directories. Commands drop to UID 1000 with zero effective capabilities. The environment marker prevents accidental host invocation; it is not an isolation boundary.

Commands have bounded output, cancellation and timeout results. The worker persists events outside the sandbox. An internal after cursor acknowledges already-persisted events, allowing the agent to reclaim its bounded spool. Public replay must use the worker/control event store.

File operations use cap-std directory handles under /workspace, bounded binary transfers and atomic replacement. Escaping symlinks and hard-link exports are rejected. This file API restriction does not prevent a command from reading its sandbox image filesystem.

A clean result requires descendant collection. Unknown cleanup must cause the worker to terminate the whole sandbox.

## Actual backend test

    docker build -f images/agent/Dockerfile -t goldenhoop-agent:test .
    python tests/agent_contract.py --image goldenhoop-agent:test --runtime runc

Use --runtime runsc only on a host with gVisor installed. The test inspects the runtime setting and validates actual process, file and network outcomes. Its output is a JSON evidence record, not a sandbox-escape certification.
