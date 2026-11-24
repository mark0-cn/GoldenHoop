-- Operation resource identities are now polymorphic: sandbox or artifact UUIDs.
CREATE TABLE operations_v2 (
    id TEXT PRIMARY KEY,
    resource_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    state TEXT NOT NULL,
    payload TEXT NOT NULL
);
INSERT INTO operations_v2 SELECT id,resource_id,kind,state,payload FROM operations;
DROP TABLE operations;
ALTER TABLE operations_v2 RENAME TO operations;
CREATE INDEX operations_pending ON operations(resource_id,kind,state);
CREATE TABLE artifacts (
    id TEXT PRIMARY KEY,
    sandbox_id TEXT NOT NULL REFERENCES sandboxes(id),
    desired TEXT NOT NULL,
    state TEXT NOT NULL,
    cleanup TEXT NOT NULL,
    payload TEXT NOT NULL,
    request TEXT NOT NULL,
    create_operation TEXT NOT NULL
);
CREATE INDEX artifacts_sandbox ON artifacts(sandbox_id,id);
CREATE INDEX artifacts_work ON artifacts(state,cleanup);
UPDATE meta SET value='2' WHERE key='schema_version';
