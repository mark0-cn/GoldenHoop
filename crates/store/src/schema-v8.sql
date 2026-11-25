-- Controller process epochs and dispatch fences are separate from network leases.
CREATE TABLE network_controllers (
    controller_generation TEXT PRIMARY KEY,
    sandbox_id TEXT NOT NULL REFERENCES sandboxes(id),
    allocation_generation TEXT NOT NULL,
    phase TEXT NOT NULL CHECK(phase IN ('reserved','creating','created','starting','running','collecting','collected')),
    revision INTEGER NOT NULL CHECK(revision>=0),
    container_id TEXT UNIQUE,
    payload TEXT NOT NULL
);
CREATE UNIQUE INDEX network_controller_live ON network_controllers(sandbox_id) WHERE phase<>'collected';
CREATE TABLE network_controller_events (
    controller_generation TEXT NOT NULL REFERENCES network_controllers(controller_generation),
    revision INTEGER NOT NULL CHECK(revision>=0),
    payload TEXT NOT NULL,
    PRIMARY KEY(controller_generation,revision)
);
UPDATE meta SET value='8' WHERE key='schema_version';
