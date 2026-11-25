-- Collection-purpose plans have independent bounded dispatch deadlines. Older
-- readers must refuse this version rather than misinterpret an expired grant.
-- Existing allocation/controller payload and event bytes are not rewritten.
UPDATE meta SET value='9' WHERE key='schema_version';
