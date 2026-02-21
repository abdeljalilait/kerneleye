-- Migration: Block reporting with service and GeoIP details
-- Created: 2026-02-20

-- ============================================
-- Blocks Table (Auto-blocking reports from agents)
-- ============================================
CREATE TABLE blocks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- IP Information
    ip_address INET NOT NULL,
    ip_version INTEGER DEFAULT 4, -- 4 or 6
    
    -- Threat Details
    threat_score INTEGER NOT NULL,
    threat_level VARCHAR(20) NOT NULL, -- normal, suspicious, malicious, critical
    reasons TEXT[] DEFAULT '{}',
    
    -- Service Information (detected from port)
    target_port INTEGER,
    service_name VARCHAR(50), -- ssh, http, https, mysql, etc.
    protocol VARCHAR(10), -- tcp, udp, icmp
    
    -- GeoIP Information
    country_code VARCHAR(2),
    country_name VARCHAR(100),
    city VARCHAR(100),
    region VARCHAR(100),
    latitude FLOAT,
    longitude FLOAT,
    asn INTEGER,
    asn_org VARCHAR(255),
    is_vpn BOOLEAN DEFAULT FALSE,
    is_tor BOOLEAN DEFAULT FALSE,
    is_datacenter BOOLEAN DEFAULT FALSE,
    
    -- Timing
    blocked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    duration_seconds INTEGER NOT NULL,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    is_auto_blocked BOOLEAN DEFAULT TRUE, -- vs manual block
    
    -- Unblock tracking
    unblocked_at TIMESTAMPTZ,
    unblocked_by UUID REFERENCES users(id),
    unblock_reason TEXT,
    
    -- Agent Info
    agent_version VARCHAR(50),
    
    -- Metadata
    raw_metrics JSONB DEFAULT '{}', -- Store detailed metrics for debugging
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for common queries
CREATE INDEX idx_blocks_user_id ON blocks(user_id);
CREATE INDEX idx_blocks_server_id ON blocks(server_id);
CREATE INDEX idx_blocks_active ON blocks(user_id, is_active) WHERE is_active = TRUE;
CREATE INDEX idx_blocks_ip ON blocks(ip_address);
CREATE INDEX idx_blocks_country ON blocks(country_code);
CREATE INDEX idx_blocks_service ON blocks(service_name);
CREATE INDEX idx_blocks_expires ON blocks(expires_at);
CREATE INDEX idx_blocks_blocked_at ON blocks(blocked_at DESC);
CREATE INDEX idx_blocks_threat_score ON blocks(threat_score DESC);

-- Composite indexes for dashboard queries
CREATE INDEX idx_blocks_user_active_at ON blocks(user_id, is_active, blocked_at DESC);
CREATE INDEX idx_blocks_server_service ON blocks(server_id, service_name);

-- ============================================
-- Block Statistics (Materialized view for fast dashboard stats)
-- ============================================
CREATE MATERIALIZED VIEW block_stats_daily AS
SELECT 
    user_id,
    server_id,
    DATE(blocked_at) as date,
    COUNT(*) as total_blocks,
    COUNT(*) FILTER (WHERE is_active) as active_blocks,
    COUNT(*) FILTER (WHERE threat_level = 'critical') as critical_blocks,
    COUNT(DISTINCT ip_address) as unique_ips,
    COUNT(DISTINCT country_code) as unique_countries,
    COUNT(*) FILTER (WHERE service_name = 'ssh') as ssh_attacks,
    COUNT(*) FILTER (WHERE service_name = 'http') as http_attacks,
    COUNT(*) FILTER (WHERE service_name = 'https') as https_attacks,
    AVG(threat_score) as avg_score,
    MAX(threat_score) as max_score
FROM blocks
GROUP BY user_id, server_id, DATE(blocked_at);

CREATE INDEX idx_block_stats_user ON block_stats_daily(user_id, date DESC);

-- ============================================
-- Functions
-- ============================================

-- Update timestamp trigger
CREATE OR REPLACE FUNCTION update_block_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_blocks_updated_at BEFORE UPDATE ON blocks
    FOR EACH ROW EXECUTE FUNCTION update_block_updated_at();

-- Auto-cleanup expired blocks (run via cron or scheduled job)
CREATE OR REPLACE FUNCTION cleanup_expired_blocks()
RETURNS INTEGER AS $$
DECLARE
    count INTEGER;
BEGIN
    UPDATE blocks 
    SET is_active = FALSE 
    WHERE is_active = TRUE 
      AND expires_at < NOW();
    
    GET DIAGNOSTICS count = ROW_COUNT;
    RETURN count;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- Comments
-- ============================================
COMMENT ON TABLE blocks IS 'IP blocks reported by agents with threat details and GeoIP';
COMMENT ON COLUMN blocks.service_name IS 'Detected service based on target port (ssh, http, https, etc.)';
COMMENT ON COLUMN blocks.is_datacenter IS 'TRUE if IP is from known cloud provider (AWS, GCP, etc.)';
COMMENT ON MATERIALIZED VIEW block_stats_daily IS 'Pre-aggregated block statistics for dashboard performance';
