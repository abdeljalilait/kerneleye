-- ============================================
-- Migration: Add Trial Tracking
-- ============================================
-- Track whether user has used their free trial
-- Trial can only be used once per email

ALTER TABLE users ADD COLUMN IF NOT EXISTS has_used_trial BOOLEAN DEFAULT FALSE;

-- Index for quick lookup
CREATE INDEX IF NOT EXISTS idx_users_has_used_trial ON users(has_used_trial);
