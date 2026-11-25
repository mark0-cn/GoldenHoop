-- Dispatched bridge/workload creation is not settled by an empty inventory. The
-- correlated daemon response or a matching materialized physical ID is needed.
CREATE TABLE network_create_dispatches (
    sandbox_id TEXT NOT NULL REFERENCES sandboxes(id),
    kind TEXT NOT NULL CHECK(kind IN('bridge','workload')),
    allocation_generation TEXT NOT NULL,
    attempt TEXT NOT NULL UNIQUE,
    payload TEXT NOT NULL,
    PRIMARY KEY(sandbox_id,kind)
);
UPDATE meta SET value='13' WHERE key='schema_version';
