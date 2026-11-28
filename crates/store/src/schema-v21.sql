CREATE TABLE snapshot_restorations (
    snapshot_id TEXT PRIMARY KEY REFERENCES snapshots(id),
    target_id TEXT NOT NULL UNIQUE REFERENCES sandboxes(id),
    operation_id TEXT NOT NULL UNIQUE REFERENCES operations(id),
    target_payload TEXT NOT NULL,
    dispatched INTEGER NOT NULL DEFAULT 0 CHECK(dispatched IN(0,1)),
    active INTEGER NOT NULL DEFAULT 0 CHECK(active IN(0,1)),
    collected INTEGER NOT NULL DEFAULT 0 CHECK(collected IN(0,1)),
    runtime_handle TEXT
);
CREATE TABLE restored_execution_bindings (
    execution_id TEXT PRIMARY KEY REFERENCES executions(id),
    target_id TEXT NOT NULL REFERENCES snapshot_restorations(target_id),
    source_execution_id TEXT NOT NULL REFERENCES executions(id),
    agent_id TEXT NOT NULL,
    agent_sandbox_id TEXT NOT NULL,
    event_offset INTEGER NOT NULL CHECK(event_offset>=0),
    UNIQUE(target_id,agent_id)
);
UPDATE meta SET value='21' WHERE key='schema_version';
