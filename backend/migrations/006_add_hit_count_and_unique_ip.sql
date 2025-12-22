-- Add hit_count column to traffic_events for tracking connection attempts
ALTER TABLE traffic_events ADD COLUMN IF NOT EXISTS hit_count INTEGER NOT NULL DEFAULT 1;

-- Add unique constraint for server + source_ip to enable upsert
-- First, we need to drop duplicates if any exist, keeping the most recent
DELETE FROM traffic_events a USING traffic_events b
WHERE a.id < b.id 
  AND a.server_id = b.server_id 
  AND a.source_ip = b.source_ip;

-- Create unique index for upsert
CREATE UNIQUE INDEX IF NOT EXISTS idx_traffic_server_source_ip_unique 
ON traffic_events(server_id, source_ip);
