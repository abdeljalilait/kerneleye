-- Migration 023: Add ICMP counters, connection duration, and per-port byte maps
-- to traffic_events. These fields are populated by the agent from new BPF maps
-- (icmp_counters, ip_port_bytes) and connection window timing.

ALTER TABLE traffic_events
    ADD COLUMN IF NOT EXISTS icmp_packets_in       BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS icmp_packets_out      BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS connection_duration_ms BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS port_bytes_in         JSONB  NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS port_bytes_out        JSONB  NOT NULL DEFAULT '{}';

-- Also add to the archive table for consistency with data retention logic
ALTER TABLE traffic_events_archive
    ADD COLUMN IF NOT EXISTS icmp_packets_in       BIGINT DEFAULT 0,
    ADD COLUMN IF NOT EXISTS icmp_packets_out      BIGINT DEFAULT 0,
    ADD COLUMN IF NOT EXISTS connection_duration_ms BIGINT DEFAULT 0,
    ADD COLUMN IF NOT EXISTS port_bytes_in         JSONB  DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS port_bytes_out        JSONB  DEFAULT '{}';
