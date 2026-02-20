-- Add ASN column to traffic_events for autonomous system tracking
ALTER TABLE traffic_events ADD COLUMN IF NOT EXISTS asn VARCHAR(50);

-- Add index for ASN queries
CREATE INDEX IF NOT EXISTS idx_traffic_asn ON traffic_events(asn);
