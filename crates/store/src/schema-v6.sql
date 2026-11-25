CREATE TABLE network_allocations (
    sandbox_id TEXT PRIMARY KEY REFERENCES sandboxes(id),
    generation TEXT NOT NULL UNIQUE,
    phase TEXT NOT NULL CHECK(phase IN ('reserved','provisioning','bound','collecting','collected','unknown')),
    revision INTEGER NOT NULL CHECK(revision>=0),
    network_id TEXT UNIQUE,
    bridge TEXT NOT NULL,
    ifindex INTEGER,
    payload TEXT NOT NULL
);
CREATE UNIQUE INDEX network_live_bridge ON network_allocations(bridge) WHERE phase<>'collected';
CREATE UNIQUE INDEX network_live_ifindex ON network_allocations(ifindex) WHERE phase<>'collected';
CREATE TABLE network_allocation_events (
    sandbox_id TEXT NOT NULL REFERENCES network_allocations(sandbox_id),
    revision INTEGER NOT NULL CHECK(revision>=0),
    payload TEXT NOT NULL,
    PRIMARY KEY(sandbox_id,revision)
);
UPDATE meta SET value='6' WHERE key='schema_version';
