-- Remove legacy traffic uniqueness indexes left from pre-direction schema.
-- Current upserts and constraints use:
--   UNIQUE (server_id, source_ip, destination_ip, destination_port, direction)
-- The older indexes below conflict with that model and can trigger duplicate
-- key errors before ON CONFLICT can resolve updates.

DROP INDEX IF EXISTS idx_traffic_server_source_ip_port_unique;
DROP INDEX IF EXISTS idx_traffic_server_source_ip_unique;
