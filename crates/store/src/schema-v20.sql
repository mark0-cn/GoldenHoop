ALTER TABLE snapshots ADD COLUMN collect_operation TEXT;
UPDATE meta SET value='20' WHERE key='schema_version';
