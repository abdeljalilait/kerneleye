-- Add threat_type column to traffic_events table
ALTER TABLE traffic_events ADD COLUMN threat_type VARCHAR(50) DEFAULT 'none';

CREATE INDEX idx_traffic_threat_type ON traffic_events(threat_type);
