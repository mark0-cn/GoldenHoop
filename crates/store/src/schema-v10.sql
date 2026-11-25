-- Host probes precede a positive native checkpoint and use distinct plans.
-- Historical native controller payload/event bytes are never rewritten.
UPDATE meta SET value='10' WHERE key='schema_version';
