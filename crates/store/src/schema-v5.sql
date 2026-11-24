CREATE TABLE sandbox_scopes (
    sandbox_id TEXT PRIMARY KEY REFERENCES sandboxes(id),
    parent_id TEXT REFERENCES sandboxes(id),
    root_id TEXT NOT NULL REFERENCES sandboxes(id),
    depth INTEGER NOT NULL CHECK(depth BETWEEN 0 AND 4),
    envelope_cpu INTEGER NOT NULL CHECK(envelope_cpu>0),
    envelope_memory INTEGER NOT NULL CHECK(envelope_memory>0),
    envelope_pids INTEGER NOT NULL CHECK(envelope_pids>0),
    child_cpu INTEGER NOT NULL DEFAULT 0 CHECK(child_cpu>=0),
    child_memory INTEGER NOT NULL DEFAULT 0 CHECK(child_memory>=0),
    child_pids INTEGER NOT NULL DEFAULT 0 CHECK(child_pids>=0),
    feature_limit TEXT,
    CHECK((parent_id IS NULL AND depth=0 AND root_id=sandbox_id) OR (parent_id IS NOT NULL AND depth>0 AND parent_id<>sandbox_id))
);
CREATE INDEX sandbox_scopes_parent ON sandbox_scopes(parent_id,sandbox_id);
CREATE INDEX sandbox_scopes_root ON sandbox_scopes(root_id,depth,sandbox_id);
INSERT INTO sandbox_scopes(sandbox_id,parent_id,root_id,depth,envelope_cpu,envelope_memory,envelope_pids)
    SELECT id,NULL,id,0,cpu_millis,memory_bytes,pids FROM sandboxes;
UPDATE meta SET value='5' WHERE key='schema_version';
