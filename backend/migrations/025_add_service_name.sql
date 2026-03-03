-- Migration 025: Add service_name column to traffic_events
-- Stores the application-layer service name (e.g. SSH, HTTP, MySQL),
-- derived from the process name captured by the eBPF agent, with a port-based fallback.
-- This is separate from 'protocol' (which remains the L4 transport: TCP/UDP/ICMP).

ALTER TABLE traffic_events
    ADD COLUMN IF NOT EXISTS service_name VARCHAR(50) NOT NULL DEFAULT '';

-- Back-fill existing rows using port heuristics
UPDATE traffic_events SET service_name = 'SSH'        WHERE destination_port = 22    AND service_name = '';
UPDATE traffic_events SET service_name = 'HTTP'       WHERE destination_port IN (80, 8080, 8000, 3000) AND service_name = '';
UPDATE traffic_events SET service_name = 'HTTPS'      WHERE destination_port = 443   AND service_name = '';
UPDATE traffic_events SET service_name = 'DNS'        WHERE destination_port = 53    AND service_name = '';
UPDATE traffic_events SET service_name = 'MySQL'      WHERE destination_port = 3306  AND service_name = '';
UPDATE traffic_events SET service_name = 'PostgreSQL' WHERE destination_port = 5432  AND service_name = '';
UPDATE traffic_events SET service_name = 'Redis'      WHERE destination_port = 6379  AND service_name = '';
UPDATE traffic_events SET service_name = 'MongoDB'    WHERE destination_port = 27017 AND service_name = '';
UPDATE traffic_events SET service_name = 'FTP'        WHERE destination_port = 21    AND service_name = '';
UPDATE traffic_events SET service_name = 'SMTP'       WHERE destination_port IN (25, 587) AND service_name = '';
UPDATE traffic_events SET service_name = 'POP3'       WHERE destination_port = 110   AND service_name = '';
UPDATE traffic_events SET service_name = 'IMAP'       WHERE destination_port = 143   AND service_name = '';
UPDATE traffic_events SET service_name = 'RDP'        WHERE destination_port = 3389  AND service_name = '';
UPDATE traffic_events SET service_name = 'Telnet'     WHERE destination_port = 23    AND service_name = '';

-- For remaining unknown ports, use the L4 protocol as the service name fallback
UPDATE traffic_events SET service_name = UPPER(protocol) WHERE service_name = '';

-- Also normalize any old rows that stored service names directly in the protocol column
UPDATE traffic_events SET protocol = 'TCP'
WHERE protocol IN ('SSH', 'HTTP', 'HTTPS', 'FTP', 'SMTP', 'POP3', 'IMAP', 'RDP', 'Telnet',
                   'MySQL', 'PostgreSQL', 'Redis', 'MongoDB', 'HTTP-Alt');

UPDATE traffic_events SET protocol = 'UDP'
WHERE protocol IN ('DHCP', 'SNMP', 'NTP');
