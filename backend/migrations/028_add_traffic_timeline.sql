-- Time-series table for per-IP per-hour traffic aggregation
-- Enables accurate attack timeline charts without relying on the upserted traffic_events table
CREATE TABLE IF NOT EXISTS traffic_timeline (
    server_id          UUID        NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    source_ip          INET        NOT NULL,
    bucket             TIMESTAMPTZ NOT NULL, -- truncated to hour at write time
    hit_count          INTEGER     NOT NULL DEFAULT 0,
    syn_count          INTEGER     NOT NULL DEFAULT 0,
    ack_count          INTEGER     NOT NULL DEFAULT 0,
    failed_handshakes  INTEGER     NOT NULL DEFAULT 0,
    bytes_in           BIGINT      NOT NULL DEFAULT 0,
    bytes_out          BIGINT      NOT NULL DEFAULT 0,
    threat_score       INTEGER     NOT NULL DEFAULT 0,
    PRIMARY KEY (server_id, source_ip, bucket)
);

CREATE INDEX idx_traffic_timeline_server_bucket  ON traffic_timeline(server_id, bucket DESC);
CREATE INDEX idx_traffic_timeline_source_ip       ON traffic_timeline(source_ip);
CREATE INDEX idx_traffic_timeline_bucket          ON traffic_timeline(bucket DESC);
