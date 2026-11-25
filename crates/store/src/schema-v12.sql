-- User intent is separate from the effective layered configuration and from
-- historical native acknowledgements. No monotonic authority is stored here.
CREATE TABLE network_policy_users (
    sandbox_id TEXT PRIMARY KEY REFERENCES sandboxes(id),
    revision INTEGER NOT NULL CHECK(revision>0),
    policy TEXT NOT NULL
);
CREATE TABLE network_policy_changes (
    operation_id TEXT PRIMARY KEY REFERENCES operations(id),
    payload TEXT NOT NULL
);
CREATE TABLE network_policy_applied_sources (
    sandbox_id TEXT NOT NULL,
    source_id TEXT NOT NULL REFERENCES sandboxes(id),
    source_revision INTEGER NOT NULL CHECK(source_revision>=0),
    source_sha256 TEXT NOT NULL,
    control_revision INTEGER NOT NULL,
    PRIMARY KEY(sandbox_id, source_id, source_revision),
    FOREIGN KEY(sandbox_id, control_revision)
        REFERENCES network_policy_events(sandbox_id, revision)
);
UPDATE meta SET value='12' WHERE key='schema_version';
