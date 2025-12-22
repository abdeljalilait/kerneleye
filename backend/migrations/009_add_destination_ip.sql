-- Add destination_ip column for proper source/destination tracking
-- For inbound: source_ip = remote caller, destination_ip = our server
-- For outbound: source_ip = our server, destination_ip = remote server

ALTER TABLE traffic_events ADD COLUMN IF NOT EXISTS destination_ip INET;

-- Index for querying by destination
CREATE INDEX IF NOT EXISTS idx_traffic_destination_ip ON traffic_events(destination_ip);

-- Update unique constraint to include destination_ip
-- First drop old constraint
ALTER TABLE traffic_events 
DROP CONSTRAINT IF EXISTS traffic_events_server_id_source_ip_port_dir_key;

-- Create new unique constraint including destination_ip
ALTER TABLE traffic_events 
ADD CONSTRAINT traffic_events_server_source_dest_port_dir_key 
UNIQUE (server_id, source_ip, destination_ip, destination_port, direction);
