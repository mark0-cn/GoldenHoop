CREATE TABLE image_jobs (
    id TEXT PRIMARY KEY,
    installation_id TEXT NOT NULL,
    generation TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    request_json TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 0),
    created_at TEXT NOT NULL,
    UNIQUE (installation_id, generation)
);
UPDATE meta SET value='17' WHERE key='schema_version';
