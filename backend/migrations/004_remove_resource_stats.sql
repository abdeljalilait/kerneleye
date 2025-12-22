-- Migration to remove system metrics columns from servers table
ALTER TABLE servers DROP COLUMN cpu_usage;
ALTER TABLE servers DROP COLUMN memory_usage;
ALTER TABLE servers DROP COLUMN uptime_seconds;
