CREATE TABLE credential_epochs (
    sandbox_id TEXT PRIMARY KEY REFERENCES sandboxes(id),
    controller_generation TEXT NOT NULL REFERENCES network_controllers(controller_generation),
    payload TEXT NOT NULL
);
CREATE TABLE credential_audit_deliveries (
    id TEXT PRIMARY KEY,
    controller_generation TEXT NOT NULL REFERENCES network_controllers(controller_generation),
    sandbox_id TEXT NOT NULL REFERENCES sandboxes(id),
    fingerprint TEXT NOT NULL,
    audit_sequence INTEGER NOT NULL REFERENCES audit(sequence)
);
CREATE TABLE credential_controller_history (
    controller_generation TEXT PRIMARY KEY REFERENCES network_controllers(controller_generation),
    sandbox_id TEXT NOT NULL REFERENCES sandboxes(id),
    payload TEXT NOT NULL
);
-- Applied metadata is historical, and cannot survive a fenced source as Active.
-- Provider intent/revisions remain intact for fresh native convergence.
CREATE TRIGGER credential_policy_fenced AFTER UPDATE ON network_policies
WHEN json_extract(new.payload,'$.phase')<>'active' BEGIN
    UPDATE credential_bindings SET payload=json_set(payload,'$.state','pending','$.applied_revision',NULL)
        WHERE sandbox_id=new.sandbox_id AND json_extract(payload,'$.state')='active';
    DELETE FROM credential_epochs WHERE sandbox_id=new.sandbox_id;
END;
CREATE TRIGGER credential_controller_collecting AFTER UPDATE OF phase ON network_controllers
WHEN new.phase IN ('collecting','collected') BEGIN
    UPDATE credential_bindings SET payload=json_set(payload,'$.state','pending','$.applied_revision',NULL)
        WHERE sandbox_id=new.sandbox_id AND json_extract(payload,'$.state')='active';
    DELETE FROM credential_epochs WHERE sandbox_id=new.sandbox_id;
END;
UPDATE meta SET value='16' WHERE key='schema_version';
