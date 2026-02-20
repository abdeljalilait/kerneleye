-- ============================================
-- Migration: Add Polar Subscription Support
-- ============================================
-- 
-- IMPORTANT: Polar Setup Instructions
-- -----------------------------------
-- 1. Go to Polar Dashboard (https://polar.sh)
-- 2. Create Products with the following prices:
--    - Starter: $49/month with 7-day free trial
--    - Pro: $149/month with 7-day free trial
-- 3. Copy the Price IDs (format: price_xxx or UUID)
-- 4. Update the subscription_plans table:
--    UPDATE subscription_plans SET polar_price_id = 'your_price_id' WHERE name = 'starter';
--    UPDATE subscription_plans SET polar_price_id = 'your_price_id' WHERE name = 'pro';
-- 5. Set environment variables:
--    - POLAR_ACCESS_TOKEN (from Polar API settings)
--    - POLAR_WEBHOOK_SECRET (from Polar webhook settings)
--    - POLAR_WEBHOOK_URL should point to: https://your-api.com/api/v1/webhooks/polar
--
-- Note: The 7-day trial must be configured in Polar Dashboard
-- when creating the Price (enable "Free trial" and set to 7 days)

-- Update users table to support Polar subscriptions
ALTER TABLE users 
    ADD COLUMN IF NOT EXISTS polar_customer_id VARCHAR(255),
    ADD COLUMN IF NOT EXISTS polar_subscription_id VARCHAR(255),
    ADD COLUMN IF NOT EXISTS subscription_status VARCHAR(50) DEFAULT 'inactive', -- active, inactive, past_due, canceled
    ADD COLUMN IF NOT EXISTS subscription_current_period_start TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS subscription_current_period_end TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS subscription_cancel_at_period_end BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS trial_ends_at TIMESTAMPTZ;

-- Create indexes for subscription queries
CREATE INDEX IF NOT EXISTS idx_users_polar_customer ON users(polar_customer_id);
CREATE INDEX IF NOT EXISTS idx_users_polar_subscription ON users(polar_subscription_id);
CREATE INDEX IF NOT EXISTS idx_users_subscription_status ON users(subscription_status);

-- ============================================
-- Subscription Plans Table
-- ============================================
CREATE TABLE IF NOT EXISTS subscription_plans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(50) UNIQUE NOT NULL, -- starter, pro
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    price_cents INTEGER NOT NULL, -- Price in cents (e.g., 4900 for $49)
    currency VARCHAR(3) DEFAULT 'USD',
    billing_interval VARCHAR(20) NOT NULL DEFAULT 'month', -- month, year
    
    -- Plan limits
    max_servers INTEGER NOT NULL DEFAULT 1,
    data_retention_days INTEGER NOT NULL DEFAULT 7,
    
    -- Features (JSON for flexibility)
    features JSONB DEFAULT '{}',
    
    -- Polar product/price IDs
    polar_product_id VARCHAR(255),
    polar_price_id VARCHAR(255),
    
    -- Plan availability
    is_active BOOLEAN DEFAULT TRUE,
    is_default BOOLEAN DEFAULT FALSE,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for plan lookups
CREATE INDEX IF NOT EXISTS idx_plans_name ON subscription_plans(name);
CREATE INDEX IF NOT EXISTS idx_plans_polar_product ON subscription_plans(polar_product_id);

-- ============================================
-- Subscription Events Log (for webhook tracking)
-- ============================================
CREATE TABLE IF NOT EXISTS subscription_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    polar_event_id VARCHAR(255) UNIQUE,
    event_type VARCHAR(100) NOT NULL, -- subscription.created, subscription.updated, etc.
    
    -- Event payload
    payload JSONB NOT NULL,
    
    -- Processing status
    processed BOOLEAN DEFAULT FALSE,
    processed_at TIMESTAMPTZ,
    error_message TEXT,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_subscription_events_user ON subscription_events(user_id);
CREATE INDEX IF NOT EXISTS idx_subscription_events_type ON subscription_events(event_type);
CREATE INDEX IF NOT EXISTS idx_subscription_events_processed ON subscription_events(processed);

-- ============================================
-- Insert Plan Data
-- ============================================

-- Starter Plan: $49/month, 10 servers, 7-day retention
INSERT INTO subscription_plans (
    name, 
    display_name, 
    description, 
    price_cents, 
    currency,
    billing_interval,
    max_servers, 
    data_retention_days,
    features,
    is_active,
    is_default
) VALUES (
    'starter',
    'Starter',
    'For small teams getting started with security monitoring',
    4900,
    'USD',
    'month',
    10,
    7,
    '{
        "real_time_monitoring": true,
        "email_alerts": true,
        "slack_alerts": false,
        "pagerduty_alerts": false,
        "api_access": false,
        "custom_rules": false,
        "priority_support": false,
        "community_support": true
    }'::jsonb,
    TRUE,
    TRUE
)
ON CONFLICT (name) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    price_cents = EXCLUDED.price_cents,
    max_servers = EXCLUDED.max_servers,
    data_retention_days = EXCLUDED.data_retention_days,
    features = EXCLUDED.features,
    updated_at = NOW();

-- Pro Plan: $149/month, 50 servers, 90-day retention
INSERT INTO subscription_plans (
    name, 
    display_name, 
    description, 
    price_cents, 
    currency,
    billing_interval,
    max_servers, 
    data_retention_days,
    features,
    is_active,
    is_default
) VALUES (
    'pro',
    'Professional',
    'For growing security teams with advanced needs',
    14900,
    'USD',
    'month',
    50,
    90,
    '{
        "real_time_monitoring": true,
        "email_alerts": true,
        "slack_alerts": true,
        "pagerduty_alerts": true,
        "api_access": true,
        "custom_rules": true,
        "priority_support": true,
        "community_support": true,
        "advanced_threat_detection": true
    }'::jsonb,
    TRUE,
    FALSE
)
ON CONFLICT (name) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    price_cents = EXCLUDED.price_cents,
    max_servers = EXCLUDED.max_servers,
    data_retention_days = EXCLUDED.data_retention_days,
    features = EXCLUDED.features,
    updated_at = NOW();

-- ============================================
-- Update existing users to have proper defaults
-- ============================================

-- Set demo user to pro plan
UPDATE users 
SET plan = 'pro', 
    max_servers = 50,
    subscription_status = 'active'
WHERE email = 'demo@kerneleye.cloud';

-- Set any existing users without a plan to starter
UPDATE users 
SET plan = 'starter', 
    max_servers = 10 
WHERE plan IS NULL OR plan = 'free';

-- ============================================
-- Functions and Triggers
-- ============================================

-- Auto-update updated_at for subscription_plans
CREATE TRIGGER update_subscription_plans_updated_at 
    BEFORE UPDATE ON subscription_plans
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to auto-update user max_servers based on plan
CREATE OR REPLACE FUNCTION update_user_plan_limits()
RETURNS TRIGGER AS $$
BEGIN
    -- Handle 'none' plan (no active subscription)
    IF NEW.plan = 'none' OR NEW.plan IS NULL OR NEW.plan = '' THEN
        NEW.max_servers := 0;
        NEW.subscription_status := 'inactive';
        RETURN NEW;
    END IF;
    
    -- Update max_servers based on plan
    SELECT max_servers INTO NEW.max_servers
    FROM subscription_plans
    WHERE name = NEW.plan AND is_active = TRUE;
    
    -- If plan not found, set to none (no servers allowed)
    IF NEW.max_servers IS NULL THEN
        NEW.max_servers := 0;
        NEW.plan := 'none';
        NEW.subscription_status := 'inactive';
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to enforce plan limits
CREATE TRIGGER enforce_user_plan_limits
    BEFORE INSERT OR UPDATE OF plan ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_user_plan_limits();

-- ============================================
-- Views for convenience
-- ============================================

-- View: Active subscriptions with plan details
CREATE OR REPLACE VIEW user_subscriptions AS
SELECT 
    u.id AS user_id,
    u.email,
    u.plan,
    u.subscription_status,
    u.max_servers,
    u.subscription_current_period_start,
    u.subscription_current_period_end,
    u.subscription_cancel_at_period_end,
    u.trial_ends_at,
    p.display_name AS plan_display_name,
    p.price_cents,
    p.data_retention_days,
    p.features,
    (SELECT COUNT(*) FROM servers WHERE user_id = u.id) AS current_server_count
FROM users u
LEFT JOIN subscription_plans p ON u.plan = p.name;

-- ============================================
-- Post-Setup: Configure Polar Price IDs
-- ============================================
-- After creating products in Polar Dashboard, run these SQL commands:
--
-- UPDATE subscription_plans SET polar_price_id = 'price_xxx' WHERE name = 'starter';
-- UPDATE subscription_plans SET polar_price_id = 'price_xxx' WHERE name = 'pro';
--
-- To verify your setup:
-- SELECT name, display_name, price_cents, polar_price_id FROM subscription_plans;

-- ============================================
-- Comments
-- ============================================
COMMENT ON TABLE subscription_plans IS 'Available subscription plans with Polar integration. Set polar_price_id after creating products in Polar dashboard';
COMMENT ON TABLE subscription_events IS 'Webhook events from Polar for audit trail';
COMMENT ON VIEW user_subscriptions IS 'Convenience view of user subscription status';
