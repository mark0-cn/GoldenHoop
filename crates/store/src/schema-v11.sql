-- Desired policy and controller ownership are historical control metadata.
-- They never serialize the worker's process-local monotonic packet lease.
CREATE TABLE network_policies (
    sandbox_id TEXT PRIMARY KEY REFERENCES sandboxes(id),
    allocation_generation TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision>=0),
    desired_revision INTEGER NOT NULL CHECK(desired_revision>=0),
    payload TEXT NOT NULL
);
CREATE TABLE network_policy_events (
    sandbox_id TEXT NOT NULL REFERENCES network_policies(sandbox_id),
    revision INTEGER NOT NULL CHECK(revision>=0),
    payload TEXT NOT NULL,
    PRIMARY KEY(sandbox_id, revision)
);
UPDATE meta SET value='11' WHERE key='schema_version';
