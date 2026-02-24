-- Whitelist table for IPs that should never be blocked
CREATE TABLE IF NOT EXISTS whitelist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip_address INET NOT NULL,
    ip_version INT NOT NULL DEFAULT 4,
    reason TEXT,
    is_manual BOOLEAN NOT NULL DEFAULT true, -- true = manually added, false = system added
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, ip_address)
);

-- Index for fast lookups
CREATE INDEX IF NOT EXISTS idx_whitelist_user_id ON whitelist(user_id);
CREATE INDEX IF NOT EXISTS idx_whitelist_ip ON whitelist(ip_address);
CREATE INDEX IF NOT EXISTS idx_whitelist_user_ip ON whitelist(user_id, ip_address);

-- Add comment
COMMENT ON TABLE whitelist IS 'Whitelisted IPs that should never be blocked';
