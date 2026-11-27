CREATE TABLE snapshots (
    id TEXT PRIMARY KEY,
    source_sandbox_id TEXT NOT NULL REFERENCES sandboxes(id),
    state TEXT NOT NULL,
    payload TEXT NOT NULL,
    request TEXT NOT NULL,
    source_handle TEXT NOT NULL,
    create_operation TEXT NOT NULL,
    dispatched INTEGER NOT NULL DEFAULT 0 CHECK (dispatched IN (0,1)),
    source_fenced INTEGER NOT NULL DEFAULT 1 CHECK (source_fenced IN (0,1)),
    source_collected INTEGER NOT NULL DEFAULT 0 CHECK (source_collected IN (0,1)),
    runtime_reference TEXT
);
CREATE INDEX snapshots_work ON snapshots(state,id);
CREATE UNIQUE INDEX snapshots_one_source_fence ON snapshots(source_sandbox_id) WHERE source_fenced=1;
-- This is the immutable admission inventory, not an assertion that an agent
-- execution was present in captured RAM or authority to replay its command.
CREATE TABLE snapshot_execution_candidates (
    snapshot_id TEXT NOT NULL REFERENCES snapshots(id),
    source_execution_id TEXT NOT NULL REFERENCES executions(id),
    payload TEXT NOT NULL,
    spec TEXT NOT NULL,
    cursor INTEGER NOT NULL CHECK (cursor >= 0),
    PRIMARY KEY (snapshot_id,source_execution_id)
);
UPDATE meta SET value='18' WHERE key='schema_version';
