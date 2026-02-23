-- ============================================
-- Migration: Remove Stripe References
-- ============================================
-- Remove legacy stripe_customer_id column (replaced by Polar)

ALTER TABLE users DROP COLUMN IF EXISTS stripe_customer_id;
DROP INDEX IF EXISTS idx_users_stripe_customer;
