-- Add refresh token support for secure token rotation
-- Allows HttpOnly cookie-based token refresh without exposing tokens to JavaScript

ALTER TABLE users ADD COLUMN IF NOT EXISTS refresh_token TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS refresh_token_expires_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_users_refresh_token ON users(refresh_token);
