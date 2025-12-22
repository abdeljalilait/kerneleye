-- Add direction column to traffic_events
ALTER TABLE traffic_events
ADD COLUMN IF NOT EXISTS direction VARCHAR(10) NOT NULL DEFAULT 'inbound';

-- Drop existing unique constraint if exists
ALTER TABLE traffic_events 
DROP CONSTRAINT IF EXISTS traffic_events_server_id_source_ip_destination_port_key;

-- Add new unique constraint including direction
ALTER TABLE traffic_events
ADD CONSTRAINT traffic_events_server_id_source_ip_port_dir_key 
UNIQUE (server_id, source_ip, destination_port, direction);

-- Add index for direction filtering
CREATE INDEX IF NOT EXISTS idx_traffic_direction ON traffic_events(direction);
