# Runtime diagnostics

`GET /v1/sandboxes/{id}/diagnostics` returns the durable sandbox record together with a fresh worker observation. The Rust/Python SDKs provide `diagnostics(id)`; the CLI provides `goldenhoop diagnostics <uuid>`. Authentication and ownership checks also apply to diagnostics. The API does not open a Docker connection.

`runtime` is null only after the worker confirms that no owned runtime exists. A stale/unreachable worker returns BackendUnavailable; it does not return a zero resource sample or claim the sandbox is gone. Runtime inspection and usage collection have separate timestamps because they are separate observations.

The runtime record includes running/paused flags, an exit code only after observed exit, and Docker's OOM flag. These do not prove why a runtime failed internally. The durable sandbox reason retains an observed unexpected exit after removal.

Usage fields are cumulative CPU nanoseconds, cgroup-accounted memory bytes and host task count. They include supervisor/runtime overhead, as described by the [Docker stats API](https://docs.docker.com/reference/api/engine/version/v1.53/) and [gVisor resource model](https://gvisor.dev/docs/architecture_guide/resources/). Memory is the raw cgroup usage, without the CLI's cache adjustment. Host tasks are not guest process counts.

Usage is not sampled for a paused or stopped runtime; it is null. A bounded metrics request failure leaves usage null and supplies `usage_error`. Missing counters remain null. No previous sample is presented as current, and missing data is never replaced with zero. Metrics are snapshots, not a retained time series.

The worker's actual startup probe only advertises Diagnostics when it can collect the three counters with a valid sample identity and timestamp. Supported runtime profiles may still encounter a later metrics error, which remains explicit in the response. Public diagnostics exclude Docker IDs, host PIDs, mount paths, daemon sockets, credentials and raw backend payloads.

The actual API suite allocates and touches 32 MiB, observes a memory/CPU increase, pauses and resumes the guest, cancels the workload, and verifies runtime absence after deletion. It also refuses fresh diagnostics while the worker heartbeat is stale. The driver suite verifies that another installation cannot inspect a resource's metrics. Each suite collects its own containers, volumes, processes and temporary files after both successful and failed runs.
