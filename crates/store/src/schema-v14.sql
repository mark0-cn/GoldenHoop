CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    verifier BLOB NOT NULL CHECK(length(verifier)=32),
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS credential_bindings (
    id TEXT PRIMARY KEY,
    sandbox_id TEXT NOT NULL REFERENCES sandboxes(id),
    revision INTEGER NOT NULL CHECK(revision>0),
    fingerprint TEXT NOT NULL,
    payload TEXT NOT NULL,
    sealed TEXT
);
CREATE INDEX IF NOT EXISTS credentials_sandbox ON credential_bindings(sandbox_id,id);
CREATE TABLE IF NOT EXISTS audit (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    event TEXT NOT NULL,
    observation TEXT
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN
    SELECT RAISE(ABORT,'audit records are append only');
END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN
    SELECT RAISE(ABORT,'audit records are append only');
END;

CREATE TRIGGER IF NOT EXISTS audit_sandboxes_insert AFTER INSERT ON sandboxes BEGIN
    INSERT INTO audit(event,observation) VALUES(json_object('actor','system','key_id',NULL,'request_id',NULL,'target_id',new.id,'sandbox_id',new.id,'action','sandbox','phase','observed','http_status',NULL),json_object('state',new.state,'cleanup',new.cleanup,'desired',new.desired));
END;
CREATE TRIGGER IF NOT EXISTS audit_sandboxes_update AFTER UPDATE ON sandboxes WHEN old.state IS NOT new.state OR old.cleanup IS NOT new.cleanup OR old.desired IS NOT new.desired BEGIN
    INSERT INTO audit(event,observation) VALUES(json_object('actor','system','key_id',NULL,'request_id',NULL,'target_id',new.id,'sandbox_id',new.id,'action','sandbox','phase','observed','http_status',NULL),json_object('state',new.state,'cleanup',new.cleanup,'desired',new.desired));
END;
CREATE TRIGGER IF NOT EXISTS audit_operations_insert AFTER INSERT ON operations BEGIN
    INSERT INTO audit(event,observation) VALUES(json_object('actor','system','key_id',NULL,'request_id',NULL,'target_id',new.id,'sandbox_id',COALESCE((SELECT id FROM sandboxes WHERE id=new.resource_id),(SELECT sandbox_id FROM artifacts WHERE id=new.resource_id)),'action','operation','phase','observed','http_status',NULL),json_object('state',new.state));
END;
CREATE TRIGGER IF NOT EXISTS audit_operations_update AFTER UPDATE ON operations WHEN old.state IS NOT new.state BEGIN
    INSERT INTO audit(event,observation) VALUES(json_object('actor','system','key_id',NULL,'request_id',NULL,'target_id',new.id,'sandbox_id',COALESCE((SELECT id FROM sandboxes WHERE id=new.resource_id),(SELECT sandbox_id FROM artifacts WHERE id=new.resource_id)),'action','operation','phase','observed','http_status',NULL),json_object('state',new.state));
END;
CREATE TRIGGER IF NOT EXISTS audit_executions_insert AFTER INSERT ON executions BEGIN
    INSERT INTO audit(event,observation) VALUES(json_object('actor','system','key_id',NULL,'request_id',NULL,'target_id',new.id,'sandbox_id',new.sandbox_id,'action','execution','phase','observed','http_status',NULL),json_object('state',new.state,'cancel_requested',new.cancel_requested));
END;
CREATE TRIGGER IF NOT EXISTS audit_executions_update AFTER UPDATE ON executions WHEN old.state IS NOT new.state OR old.cancel_requested IS NOT new.cancel_requested BEGIN
    INSERT INTO audit(event,observation) VALUES(json_object('actor','system','key_id',NULL,'request_id',NULL,'target_id',new.id,'sandbox_id',new.sandbox_id,'action','execution','phase','observed','http_status',NULL),json_object('state',new.state,'cancel_requested',new.cancel_requested));
END;
CREATE TRIGGER IF NOT EXISTS audit_code_contexts_insert AFTER INSERT ON code_contexts BEGIN
    INSERT INTO audit(event,observation) VALUES(json_object('actor','system','key_id',NULL,'request_id',NULL,'target_id',new.id,'sandbox_id',new.sandbox_id,'action','context','phase','observed','http_status',NULL),json_object('state',new.state,'cleanup',new.cleanup,'desired',new.desired,'dispatched',new.dispatched));
END;
CREATE TRIGGER IF NOT EXISTS audit_code_contexts_update AFTER UPDATE ON code_contexts WHEN old.state IS NOT new.state OR old.cleanup IS NOT new.cleanup OR old.desired IS NOT new.desired OR old.dispatched IS NOT new.dispatched BEGIN
    INSERT INTO audit(event,observation) VALUES(json_object('actor','system','key_id',NULL,'request_id',NULL,'target_id',new.id,'sandbox_id',new.sandbox_id,'action','context','phase','observed','http_status',NULL),json_object('state',new.state,'cleanup',new.cleanup,'desired',new.desired,'dispatched',new.dispatched));
END;
CREATE TRIGGER IF NOT EXISTS audit_code_runs_insert AFTER INSERT ON code_runs BEGIN
    INSERT INTO audit(event,observation) VALUES(json_object('actor','system','key_id',NULL,'request_id',NULL,'target_id',new.id,'sandbox_id',(SELECT sandbox_id FROM code_contexts WHERE id=new.context_id),'action','code_run','phase','observed','http_status',NULL),json_object('state',new.state,'dispatched',new.dispatched,'cancel_requested',new.cancel_requested,'settled',new.settled));
END;
CREATE TRIGGER IF NOT EXISTS audit_code_runs_update AFTER UPDATE ON code_runs WHEN old.state IS NOT new.state OR old.dispatched IS NOT new.dispatched OR old.cancel_requested IS NOT new.cancel_requested OR old.settled IS NOT new.settled BEGIN
    INSERT INTO audit(event,observation) VALUES(json_object('actor','system','key_id',NULL,'request_id',NULL,'target_id',new.id,'sandbox_id',(SELECT sandbox_id FROM code_contexts WHERE id=new.context_id),'action','code_run','phase','observed','http_status',NULL),json_object('state',new.state,'dispatched',new.dispatched,'cancel_requested',new.cancel_requested,'settled',new.settled));
END;
CREATE TRIGGER IF NOT EXISTS audit_artifacts_insert AFTER INSERT ON artifacts BEGIN
    INSERT INTO audit(event,observation) VALUES(json_object('actor','system','key_id',NULL,'request_id',NULL,'target_id',new.id,'sandbox_id',new.sandbox_id,'action','artifact','phase','observed','http_status',NULL),json_object('state',new.state,'cleanup',new.cleanup,'desired',new.desired));
END;
CREATE TRIGGER IF NOT EXISTS audit_artifacts_update AFTER UPDATE ON artifacts WHEN old.state IS NOT new.state OR old.cleanup IS NOT new.cleanup OR old.desired IS NOT new.desired BEGIN
    INSERT INTO audit(event,observation) VALUES(json_object('actor','system','key_id',NULL,'request_id',NULL,'target_id',new.id,'sandbox_id',new.sandbox_id,'action','artifact','phase','observed','http_status',NULL),json_object('state',new.state,'cleanup',new.cleanup,'desired',new.desired));
END;
CREATE TRIGGER IF NOT EXISTS audit_network_policies_insert AFTER INSERT ON network_policies BEGIN
    INSERT INTO audit(event,observation) VALUES(json_object('actor','system','key_id',NULL,'request_id',NULL,'target_id',new.sandbox_id,'sandbox_id',new.sandbox_id,'action','network','phase','observed','http_status',NULL),json_object('revision',new.revision,'desired_revision',new.desired_revision));
END;
CREATE TRIGGER IF NOT EXISTS audit_network_policies_update AFTER UPDATE ON network_policies WHEN old.desired_revision IS NOT new.desired_revision OR json_extract(old.payload,'$.phase') IS NOT json_extract(new.payload,'$.phase') BEGIN
    INSERT INTO audit(event,observation) VALUES(json_object('actor','system','key_id',NULL,'request_id',NULL,'target_id',new.sandbox_id,'sandbox_id',new.sandbox_id,'action','network','phase','observed','http_status',NULL),json_object('revision',new.revision,'desired_revision',new.desired_revision));
END;
UPDATE meta SET value='14' WHERE key='schema_version';
