CREATE TABLE code_contexts (
    id TEXT PRIMARY KEY,
    sandbox_id TEXT NOT NULL REFERENCES sandboxes(id),
    desired TEXT NOT NULL,
    state TEXT NOT NULL,
    cleanup TEXT NOT NULL,
    payload TEXT NOT NULL,
    dispatched INTEGER NOT NULL DEFAULT 0,
    ever_ready INTEGER NOT NULL DEFAULT 0,
    cursor INTEGER NOT NULL DEFAULT 0,
    event_cursor INTEGER NOT NULL DEFAULT 0,
    background_bytes INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX code_contexts_work ON code_contexts(sandbox_id,cleanup,id);
CREATE TABLE code_runs (
    id TEXT PRIMARY KEY,
    context_id TEXT NOT NULL REFERENCES code_contexts(id),
    state TEXT NOT NULL,
    payload TEXT NOT NULL,
    spec TEXT NOT NULL,
    dispatched INTEGER NOT NULL DEFAULT 0,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    settled INTEGER NOT NULL DEFAULT 0,
    pending_result TEXT,
    output_bytes INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX code_runs_work ON code_runs(context_id,settled,id);
CREATE TABLE code_context_sources (
    context_id TEXT NOT NULL REFERENCES code_contexts(id),
    sequence INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    PRIMARY KEY(context_id,sequence)
);
CREATE TABLE code_context_events (
    context_id TEXT NOT NULL REFERENCES code_contexts(id),
    sequence INTEGER NOT NULL,
    run_id TEXT,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY(context_id,sequence)
);
CREATE UNIQUE INDEX code_run_one_completion ON code_context_events(run_id) WHERE kind='run_completed';
CREATE UNIQUE INDEX code_context_one_closed ON code_context_events(context_id) WHERE kind='closed';
UPDATE meta SET value='4' WHERE key='schema_version';
