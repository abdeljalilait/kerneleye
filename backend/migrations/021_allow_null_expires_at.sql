-- Migration: Allow NULL expires_at for permanent blocks
-- Created: 2026-02-26

-- Allow NULL in expires_at column to support permanent blocks (no expiry)
ALTER TABLE blocks ALTER COLUMN expires_at DROP NOT NULL;

-- Add comment to document the meaning of NULL
COMMENT ON COLUMN blocks.expires_at IS 'Block expiration time. NULL = permanent block (no expiry).';
