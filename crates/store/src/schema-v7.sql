-- Native checkpoints use the existing network ID/ifindex uniqueness columns.
-- Version-6 complete bindings already carry their physical identity. Do not
-- rewrite immutable payload/history bytes merely to add the optional field.
UPDATE meta SET value='7' WHERE key='schema_version';
