CREATE TABLE IF NOT EXISTS credential_cas (
    sandbox_id TEXT PRIMARY KEY REFERENCES sandboxes(id),
    public_pem TEXT NOT NULL,
    public_sha256 TEXT NOT NULL,
    sealed TEXT NOT NULL
);
-- Complete runtime collection already requires the owned broker/controller to
-- be absent. Retire private material in that same durable transaction.
CREATE TRIGGER IF NOT EXISTS credential_runtime_collected AFTER UPDATE OF cleanup ON sandboxes
WHEN new.cleanup='complete' AND old.cleanup<>'complete' BEGIN
    UPDATE credential_bindings SET sealed=NULL,fingerprint='',
        payload=json_set(payload,'$.state','revoked','$.applied_revision',revision)
        WHERE sandbox_id=new.id;
    INSERT INTO audit(event,observation)
        SELECT json_object('actor','system','key_id',NULL,'request_id',NULL,
            'target_id',id,'sandbox_id',new.id,'action','credential','phase','observed','http_status',NULL),
            json_object('state','revoked','revision',revision,'collection','sandbox_runtime')
        FROM credential_bindings WHERE sandbox_id=new.id;
    DELETE FROM credential_cas WHERE sandbox_id=new.id;
END;
UPDATE meta SET value='15' WHERE key='schema_version';
