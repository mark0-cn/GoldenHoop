CREATE TABLE sessions (
    execution_id TEXT PRIMARY KEY REFERENCES executions(id),
    spec TEXT NOT NULL
);
CREATE TABLE session_controls (
    execution_id TEXT NOT NULL REFERENCES sessions(execution_id),
    sequence INTEGER NOT NULL,
    state TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    request TEXT NOT NULL,
    payload TEXT NOT NULL,
    input_bytes INTEGER NOT NULL,
    PRIMARY KEY(execution_id,sequence)
);
CREATE INDEX session_controls_work ON session_controls(execution_id,state,sequence);
UPDATE meta SET value='3' WHERE key='schema_version';
