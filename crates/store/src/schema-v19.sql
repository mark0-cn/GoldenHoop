ALTER TABLE snapshots ADD COLUMN capture_refusal TEXT;
UPDATE meta SET value='19' WHERE key='schema_version';
