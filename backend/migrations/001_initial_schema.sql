-- KernelEye Database Schema v1.0
-- PostgreSQL 14+

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================
-- Users Table
-- ============================================
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    plan VARCHAR(50) NOT NULL DEFAULT 'free', -- free, starter, pro, team
    max_servers INTEGER NOT NULL DEFAULT 1,
    stripe_customer_id VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_stripe_customer ON users(stripe_customer_id);

-- ============================================
-- Servers Table (Monitored Hosts)
-- ============================================
CREATE TABLE servers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    hostname VARCHAR(255) NOT NULL,
    ip_address INET,
    api_key VARCHAR(64) UNIQUE NOT NULL, -- Agent authentication
    status VARCHAR(50) NOT NULL DEFAULT 'active', -- active, inactive, warning
    last_seen TIMESTAMPTZ,
    agent_version VARCHAR(50),
    metadata JSONB DEFAULT '{}', -- OS, kernel version, etc.
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_servers_user_id ON servers(user_id);
CREATE INDEX idx_servers_api_key ON servers(api_key);
CREATE INDEX idx_servers_status ON servers(status);
CREATE INDEX idx_servers_last_seen ON servers(last_seen);

-- ============================================
-- Traffic Events Table (Aggregated Data)
-- ============================================
CREATE TABLE traffic_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    source_ip INET NOT NULL,
    destination_port INTEGER NOT NULL,
    protocol VARCHAR(10) NOT NULL, -- TCP, UDP, ICMP
    
    -- Metrics
    syn_count INTEGER NOT NULL DEFAULT 0,
    ack_count INTEGER NOT NULL DEFAULT 0,
    failed_handshakes INTEGER NOT NULL DEFAULT 0,
    unique_ports INTEGER NOT NULL DEFAULT 0,
    bytes_in BIGINT NOT NULL DEFAULT 0,
    bytes_out BIGINT NOT NULL DEFAULT 0,
    
    -- Threat scoring
    threat_score INTEGER NOT NULL DEFAULT 0,
    threat_level VARCHAR(20) NOT NULL DEFAULT 'normal', -- normal, suspicious, malicious
    
    -- Timestamps
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_traffic_server_id ON traffic_events(server_id);
CREATE INDEX idx_traffic_source_ip ON traffic_events(source_ip);
CREATE INDEX idx_traffic_threat_level ON traffic_events(threat_level);
CREATE INDEX idx_traffic_threat_score ON traffic_events(threat_score DESC);
CREATE INDEX idx_traffic_created_at ON traffic_events(created_at DESC);
CREATE INDEX idx_traffic_server_created ON traffic_events(server_id, created_at DESC);

-- Composite index for common queries
CREATE INDEX idx_traffic_server_ip_time ON traffic_events(server_id, source_ip, created_at DESC);

-- ============================================
-- Alerts Table
-- ============================================
CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    source_ip INET NOT NULL,
    threat_score INTEGER NOT NULL,
    reason TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL, -- info, warning, critical
    status VARCHAR(20) NOT NULL DEFAULT 'active', -- active, acknowledged, resolved
    
    -- Metadata
    auto_blocked BOOLEAN DEFAULT FALSE, -- Phase 2 feature
    blocked_until TIMESTAMPTZ, -- Temporary blocks
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ
);

CREATE INDEX idx_alerts_server_id ON alerts(server_id);
CREATE INDEX idx_alerts_source_ip ON alerts(source_ip);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_created_at ON alerts(created_at DESC);

-- ============================================
-- IP Statistics (Aggregated per IP per Day)
-- ============================================
CREATE TABLE ip_stats (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    source_ip INET NOT NULL,
    date DATE NOT NULL,
    
    -- Daily aggregates
    total_connections INTEGER NOT NULL DEFAULT 0,
    total_syn INTEGER NOT NULL DEFAULT 0,
    total_ack INTEGER NOT NULL DEFAULT 0,
    total_failed_handshakes INTEGER NOT NULL DEFAULT 0,
    max_threat_score INTEGER NOT NULL DEFAULT 0,
    unique_ports_count INTEGER NOT NULL DEFAULT 0,
    total_bytes_in BIGINT NOT NULL DEFAULT 0,
    total_bytes_out BIGINT NOT NULL DEFAULT 0,
    
    -- Geo data (optional, Phase 2)
    country_code VARCHAR(2),
    city VARCHAR(100),
    asn INTEGER,
    asn_org VARCHAR(255),
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(server_id, source_ip, date)
);

CREATE INDEX idx_ip_stats_server_date ON ip_stats(server_id, date DESC);
CREATE INDEX idx_ip_stats_source_ip ON ip_stats(source_ip);
CREATE INDEX idx_ip_stats_threat_score ON ip_stats(max_threat_score DESC);

-- ============================================
-- Block List (Phase 2 - Manual/Auto Blocks)
-- ============================================
CREATE TABLE block_list (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    ip_address INET NOT NULL,
    action VARCHAR(20) NOT NULL, -- block, allow, rate_limit
    reason TEXT,
    auto_added BOOLEAN DEFAULT FALSE,
    expires_at TIMESTAMPTZ, -- NULL = permanent
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id), -- NULL if auto-added
    
    UNIQUE(server_id, ip_address)
);

CREATE INDEX idx_block_list_server_id ON block_list(server_id);
CREATE INDEX idx_block_list_ip ON block_list(ip_address);
CREATE INDEX idx_block_list_expires ON block_list(expires_at);

-- ============================================
-- Audit Log (User Actions)
-- ============================================
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action VARCHAR(100) NOT NULL, -- login, add_server, block_ip, etc.
    resource_type VARCHAR(50),
    resource_id UUID,
    metadata JSONB DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_user_id ON audit_log(user_id);
CREATE INDEX idx_audit_created_at ON audit_log(created_at DESC);

-- ============================================
-- Functions and Triggers
-- ============================================

-- Auto-update updated_at column
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_servers_updated_at BEFORE UPDATE ON servers
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_ip_stats_updated_at BEFORE UPDATE ON ip_stats
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================
-- Initial Data
-- ============================================

-- Create a demo user for testing
INSERT INTO users (email, password_hash, plan, max_servers)
VALUES ('demo@kerneleye.io', '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 'pro', 10)
ON CONFLICT (email) DO NOTHING;

-- ============================================
-- Comments
-- ============================================
COMMENT ON TABLE users IS 'KernelEye customer accounts';
COMMENT ON TABLE servers IS 'Monitored servers with agent installations';
COMMENT ON TABLE traffic_events IS 'Aggregated network traffic events from agents';
COMMENT ON TABLE alerts IS 'Threat alerts triggered by scoring system';
COMMENT ON TABLE ip_stats IS 'Daily aggregated statistics per IP address';
COMMENT ON TABLE block_list IS 'IPs to block or allow (Phase 2)';
COMMENT ON TABLE audit_log IS 'User action audit trail';
