# Persistent control state

The SQLite store uses SQLx, WAL journaling, full synchronization and immediate write transactions. A stable installation UUID is initialized atomically and retained across restarts. Schema version 1 is embedded in the binary; unsupported versions are refused. PostgreSQL and cluster migrations remain part of M5.

The API commits desired state and idempotent requests before the worker acts. Observations update actual state without overwriting a concurrent desired-state change or extending the original absolute deadline. A terminated state requires confirmed cleanup. Failed resources with unconfirmed cleanup remain charged to the installation quota.

The initial installation limits are 16 live sandboxes, 16 CPU equivalents, 32 GiB memory and 4096 PIDs in total, with at most a one-day TTL and 256 executions per sandbox. Profile limits may be stricter. Image metadata, argv and environment sizes are bounded before storage or execution.

Commands have stable UUIDs and persisted cancellation intent. Events, their acknowledgement cursor and the public execution result commit in one transaction. Event sequences must be contiguous and duplicate sequences must retain the same content. Each stream has at most one completion event. A terminal result requires a matching explicit completion event and confirmed process cleanup; Unknown does not satisfy completion. Terminal results and completed streams are immutable.

Worker metadata contains a private loopback endpoint and authentication token. It is not a public response type. A stale heartbeat cannot advertise a live worker. New database files use mode 0600 and newly created parent directories use mode 0700 on Unix; existing database files with group/other permissions are refused. On Windows, access follows the owning user's directory ACLs. Do not share the state directory with workloads.

The durability suite covers concurrent idempotency, failed transaction rollback, resource charging until confirmed cleanup, desired-state races, absolute expiration, completion/cursor atomicity, terminal immutability, cancellation preservation, stale heartbeat refusal and actual SQLite close/reopen. Temporary database files are removed after the suite, including assertion failure paths.

The public API and worker reconciliation loop now use these primitives; see control.md. CLI and SDK integration is still in progress.
