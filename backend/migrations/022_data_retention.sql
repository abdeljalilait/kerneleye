-- ============================================
-- Data Retention: Archive old traffic events
-- ============================================

-- Create archived traffic events table (parquet-like structure for cold storage)
CREATE TABLE IF NOT EXISTS traffic_events_archive (
    id UUID PRIMARY KEY,
    server_id UUID NOT NULL,
    source_ip INET NOT NULL,
    destination_port INTEGER,
    protocol TEXT,
    direction TEXT,
    bytes_in BIGINT DEFAULT 0,
    bytes_out BIGINT DEFAULT 0,
    hit_count INTEGER DEFAULT 0,
    syn_count INTEGER DEFAULT 0,
    ack_count INTEGER DEFAULT 0,
    failed_handshakes INTEGER DEFAULT 0,
    threat_score INTEGER DEFAULT 0,
    threat_level TEXT,
    threat_type TEXT,
    country TEXT,
    country_code TEXT,
    city TEXT,
    isp TEXT,
    asn TEXT,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    archived_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index for efficient archival queries
CREATE INDEX IF NOT EXISTS idx_traffic_events_archive_server_id ON traffic_events_archive(server_id);
CREATE INDEX IF NOT EXISTS idx_traffic_events_archive_last_seen ON traffic_events_archive(last_seen);

-- ============================================
-- Archive function: Move old data to archive table
-- ============================================
CREATE OR REPLACE FUNCTION archive_traffic_events(p_server_id UUID, p_retention_days INTEGER)
RETURNS INTEGER AS $$
DECLARE
    v_archived_count INTEGER := 0;
    v_cutoff_date TIMESTAMPTZ;
BEGIN
    v_cutoff_date := NOW() - INTERVAL '1 day' * p_retention_days;
    
    -- Move old records to archive
    WITH archived AS (
        DELETE FROM traffic_events
        WHERE server_id = p_server_id
          AND last_seen < v_cutoff_date
          AND threat_level = 'normal'  -- Only archive non-threat traffic
        RETURNING *
    )
    INSERT INTO traffic_events_archive (
        id, server_id, source_ip, destination_port, protocol, direction,
        bytes_in, bytes_out, hit_count, syn_count, ack_count, failed_handshakes,
        threat_score, threat_level, threat_type,
        country, country_code, city, isp, asn,
        first_seen, last_seen, created_at
    )
    SELECT 
        id, server_id, source_ip, destination_port, protocol, direction,
        bytes_in, bytes_out, hit_count, syn_count, ack_count, failed_handshakes,
        threat_score, threat_level, threat_type,
        country, country_code, city, isp, asn,
        first_seen, last_seen, created_at
    FROM archived;
    
    GET DIAGNOSTICS v_archived_count = ROW_COUNT;
    
    RETURN v_archived_count;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- Cleanup function: Delete archived data older than 1 year
-- ============================================
CREATE OR REPLACE FUNCTION cleanup_old_archives()
RETURNS INTEGER AS $$
DECLARE
    v_deleted_count INTEGER := 0;
    v_cutoff_date TIMESTAMPTZ;
BEGIN
    v_cutoff_date := NOW() - INTERVAL '1 year';
    
    DELETE FROM traffic_events_archive
    WHERE archived_at < v_cutoff_date;
    
    GET DIAGNOSTICS v_deleted_count = ROW_COUNT;
    
    RETURN v_deleted_count;
END;
$$ LANGUAGE plpgsql;
