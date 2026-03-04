-- Migration: Add enforcement_type to blocks table for escalating enforcement system
-- Created: 2026-03-04
--
-- enforcement_type distinguishes how an IP is being dealt with:
--   ratelimit  → rate-limited (temporary, low threat)
--   block      → hard blocked for a calculated duration
--   permanent  → permanent hard block, threat_level = 'malicious'

ALTER TABLE blocks
    ADD COLUMN IF NOT EXISTS enforcement_type TEXT NOT NULL DEFAULT 'block'
        CHECK (enforcement_type IN ('ratelimit', 'block', 'permanent'));

-- Backfill existing rows based on stored duration/expiry data
UPDATE blocks SET enforcement_type = 'permanent'
WHERE expires_at IS NULL AND duration_seconds = 0;

UPDATE blocks SET enforcement_type = 'ratelimit'
WHERE enforcement_type = 'block'
  AND duration_seconds > 0
  AND duration_seconds <= 1800;

CREATE INDEX IF NOT EXISTS idx_blocks_enforcement_type ON blocks(enforcement_type);
