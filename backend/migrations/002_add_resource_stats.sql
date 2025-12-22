-- Add resource usage columns to servers table
ALTER TABLE servers ADD COLUMN cpu_usage DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE servers ADD COLUMN memory_usage BIGINT NOT NULL DEFAULT 0;
ALTER TABLE servers ADD COLUMN uptime_seconds BIGINT NOT NULL DEFAULT 0;
