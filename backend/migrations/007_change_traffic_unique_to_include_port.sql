-- Change unique constraint from (server_id, source_ip) to (server_id, source_ip, destination_port)
-- This allows tracking traffic per IP per port instead of per IP only

-- Drop the old unique index
DROP INDEX IF EXISTS idx_traffic_server_source_ip_unique;

-- Create new unique index including destination_port
CREATE UNIQUE INDEX IF NOT EXISTS idx_traffic_server_source_ip_port_unique 
ON traffic_events(server_id, source_ip, destination_port);
