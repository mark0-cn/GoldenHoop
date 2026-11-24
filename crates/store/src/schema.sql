CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sandboxes (
    id TEXT PRIMARY KEY,
    desired TEXT NOT NULL,
    state TEXT NOT NULL,
    cleanup TEXT NOT NULL,
    payload TEXT NOT NULL,
    request TEXT NOT NULL,
    handle TEXT,
    ever_running INTEGER NOT NULL DEFAULT 0,
    cpu_millis INTEGER NOT NULL,
    memory_bytes INTEGER NOT NULL,
    pids INTEGER NOT NULL,
    create_operation TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS operations (
    id TEXT PRIMARY KEY,
    resource_id TEXT NOT NULL REFERENCES sandboxes(id),
    kind TEXT NOT NULL,
    state TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS operations_pending ON operations(resource_id, kind, state);
CREATE TABLE IF NOT EXISTS idempotency (
    scope TEXT NOT NULL,
    client_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    PRIMARY KEY(scope, client_key)
);
CREATE TABLE IF NOT EXISTS executions (
    id TEXT PRIMARY KEY,
    sandbox_id TEXT NOT NULL REFERENCES sandboxes(id),
    state TEXT NOT NULL,
    payload TEXT NOT NULL,
    spec TEXT NOT NULL,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    cursor INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS executions_sandbox ON executions(sandbox_id, state);
CREATE TABLE IF NOT EXISTS events (
    execution_id TEXT NOT NULL REFERENCES executions(id),
    sequence INTEGER NOT NULL,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY(execution_id, sequence)
);
CREATE UNIQUE INDEX IF NOT EXISTS events_one_completion ON events(execution_id) WHERE kind='completed';
