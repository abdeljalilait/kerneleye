-- name: CreateUser :one
INSERT INTO users (email, password_hash, plan)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE email = $1;

-- name: GetUserByID :one
SELECT * FROM users
WHERE id = $1;

-- name: GetUserByRefreshToken :one
SELECT * FROM users
WHERE refresh_token = $1;

-- name: UpdateUserRefreshToken :one
UPDATE users
SET refresh_token = $2,
    refresh_token_expires_at = $3
WHERE id = $1
RETURNING *;

-- name: ClearUserRefreshToken :one
UPDATE users
SET refresh_token = NULL,
    refresh_token_expires_at = NULL
WHERE id = $1
RETURNING *;

-- name: CreateServer :one
INSERT INTO servers (user_id, hostname, api_key, last_seen)
VALUES ($1, $2, $3, NOW())
RETURNING *;

-- name: GetServerByAPIKey :one
SELECT * FROM servers
WHERE api_key = $1;

-- name: GetServerByID :one
SELECT * FROM servers
WHERE id = $1;

-- name: CreateServerPending :one
INSERT INTO servers (user_id, hostname, client_token, status, last_seen)
VALUES ($1, $2, $3, 'pending', NOW())
RETURNING *;

-- name: CreateServerWithAPIKey :one
INSERT INTO servers (user_id, hostname, api_key, client_token, ip_address, status, last_seen)
VALUES ($1, $2, $3, $4, $5, 'pending', NOW())
RETURNING *;

-- name: GetServerByUserAndIP :one
SELECT * FROM servers
WHERE user_id = $1 AND ip_address = $2;

-- name: UpdateServerForReenrollment :one
UPDATE servers
SET api_key = $2,
    hostname = $3,
    client_token = $4,
    status = 'active',
    last_seen = NOW()
WHERE id = $1
RETURNING *;

-- name: GetServerByClientToken :one
SELECT * FROM servers
WHERE client_token = $1;

-- name: UpdateServerStatus :exec
UPDATE servers
SET status = $2
WHERE id = $1;

-- name: ListServersByUser :many
SELECT * FROM servers
WHERE user_id = $1
ORDER BY created_at DESC;

-- name: UpdateServerHeartbeat :exec
UPDATE servers 
SET last_seen = NOW(), 
    agent_version = $1, 
    ip_address = COALESCE(ip_address, $2),
    status = 'active'
WHERE api_key = $3;

-- name: UpsertTrafficEvent :one
INSERT INTO traffic_events (
    server_id, source_ip, destination_ip, destination_port, protocol, direction,
    syn_count, ack_count, failed_handshakes, unique_ports,
    bytes_in, bytes_out, threat_score, threat_level, threat_type,
    first_seen, last_seen, country, country_code, city, isp, asn,
    icmp_packets_in, icmp_packets_out, connection_duration_ms,
    port_bytes_in, port_bytes_out, service_name,
    hit_count
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, 1)
ON CONFLICT (server_id, source_ip, destination_ip, destination_port, direction) DO UPDATE SET
    syn_count = traffic_events.syn_count + EXCLUDED.syn_count,
    ack_count = traffic_events.ack_count + EXCLUDED.ack_count,
    failed_handshakes = traffic_events.failed_handshakes + EXCLUDED.failed_handshakes,
    unique_ports = GREATEST(traffic_events.unique_ports, EXCLUDED.unique_ports),
    bytes_in = traffic_events.bytes_in + EXCLUDED.bytes_in,
    bytes_out = traffic_events.bytes_out + EXCLUDED.bytes_out,
    icmp_packets_in = traffic_events.icmp_packets_in + EXCLUDED.icmp_packets_in,
    icmp_packets_out = traffic_events.icmp_packets_out + EXCLUDED.icmp_packets_out,
    connection_duration_ms = GREATEST(traffic_events.connection_duration_ms, EXCLUDED.connection_duration_ms),
    port_bytes_in = EXCLUDED.port_bytes_in,
    port_bytes_out = EXCLUDED.port_bytes_out,
    -- Use the most recent threat score (allows scores to decrease over time)
    threat_score = EXCLUDED.threat_score,
    threat_level = EXCLUDED.threat_level,
    threat_type = EXCLUDED.threat_type,
    service_name = EXCLUDED.service_name,
    last_seen = EXCLUDED.last_seen,
    hit_count = traffic_events.hit_count + 1
RETURNING *;

-- name: ListThreats :many
SELECT te.* FROM traffic_events te
JOIN servers s ON te.server_id = s.id
WHERE s.user_id = $1 
  AND te.threat_level IN ('suspicious', 'malicious')
ORDER BY te.threat_score DESC, te.last_seen DESC
LIMIT $2;

-- name: CreateAlert :one
INSERT INTO alerts (server_id, source_ip, threat_score, reason, severity, status)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: ListAlerts :many
SELECT a.*, s.hostname as server_hostname
FROM alerts a
JOIN servers s ON a.server_id = s.id
WHERE s.user_id = $1
ORDER BY a.created_at DESC
LIMIT $2;

-- name: GetStatsServerCounts :one
SELECT 
    COUNT(*)::int as total_servers,
    COUNT(*) FILTER (WHERE status = 'active')::int as active_servers,
    COUNT(*) FILTER (WHERE status = 'inactive')::int as inactive_servers
FROM servers
WHERE user_id = $1;

-- name: GetStatsEventCounts :one
SELECT 
    COALESCE(SUM(hit_count), 0)::bigint as total_events,
    COUNT(DISTINCT te.source_ip)::int as unique_sources
FROM traffic_events te
JOIN servers s ON te.server_id = s.id
WHERE s.user_id = $1
  AND te.created_at >= NOW() - INTERVAL '24 hours';

-- name: GetStatsAlertCounts :one
SELECT 
    COUNT(*)::int as total_alerts,
    COUNT(*) FILTER (WHERE severity = 'critical')::int as critical_alerts,
    COUNT(*) FILTER (WHERE severity = 'warning')::int as warning_alerts
FROM alerts a
JOIN servers s ON a.server_id = s.id
WHERE s.user_id = $1
  AND a.created_at >= NOW() - INTERVAL '24 hours';

-- name: ListTrafficEventsByServer :many
SELECT * FROM traffic_events
WHERE server_id = $1
  AND ($2::text IS NULL OR $2 = '' OR source_ip::text ILIKE '%' || $2 || '%')
  AND ($3::text IS NULL OR $3 = '' OR threat_level = $3)
  AND ($4::timestamptz IS NULL OR last_seen >= $4)
  AND ($5::timestamptz IS NULL OR last_seen <= $5)
ORDER BY 
  CASE WHEN $8::text = 'threat_score' THEN threat_score END DESC,
  CASE WHEN $8::text = 'syn_count' THEN syn_count END DESC,
  CASE WHEN $8::text = 'hit_count' THEN hit_count END DESC,
  last_seen DESC
LIMIT $6 OFFSET $7;

-- name: CountTrafficEventsByServer :one
SELECT COUNT(*)::int as total_count FROM traffic_events
WHERE server_id = $1
  AND ($2::text IS NULL OR $2 = '' OR source_ip::text ILIKE '%' || $2 || '%')
  AND ($3::text IS NULL OR $3 = '' OR threat_level = $3)
  AND ($4::timestamptz IS NULL OR last_seen >= $4)
  AND ($5::timestamptz IS NULL OR last_seen <= $5);

-- name: GetServerStats :one
SELECT 
    COALESCE(SUM(hit_count), 0)::bigint as total_events,
    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours')::int as events_last_24h,
    COUNT(*) FILTER (WHERE threat_level = 'malicious')::int as threat_events,
    COALESCE(SUM(bytes_in), 0)::bigint as total_bytes_in,
    COALESCE(SUM(bytes_out), 0)::bigint as total_bytes_out
FROM traffic_events
WHERE server_id = $1;

-- name: ListPortTrafficByServer :many
-- Returns aggregated traffic data grouped by port and protocol with source IPs as JSON array
SELECT 
    destination_port,
    protocol,
    service_name,
    COUNT(DISTINCT source_ip) as unique_ips,
    SUM(bytes_in)::bigint as total_bytes_in,
    SUM(bytes_out)::bigint as total_bytes_out,
    SUM(hit_count)::int as total_hits,
    SUM(syn_count)::int as total_syn,
    SUM(ack_count)::int as total_ack,
    SUM(icmp_packets_in)::bigint as total_icmp_in,
    SUM(icmp_packets_out)::bigint as total_icmp_out,
    MAX(threat_score) as max_threat_score,
    MAX(threat_level) as max_threat_level,
    MAX(last_seen) as last_seen,
    COALESCE(
        jsonb_agg(
            DISTINCT jsonb_build_object(
                'source_ip', source_ip,
                'destination_ip', destination_ip,
                'bytes_in', bytes_in,
                'bytes_out', bytes_out,
                'syn_count', syn_count,
                'ack_count', ack_count,
                'hit_count', hit_count,
                'threat_score', threat_score,
                'threat_level', threat_level,
                'country', country,
                'city', city,
                'isp', isp,
                'last_seen', last_seen,
                'direction', direction
            )
        ) FILTER (WHERE source_ip IS NOT NULL),
        '[]'::jsonb
    ) as sources
FROM traffic_events
WHERE server_id = $1
  AND ($2::text IS NULL OR $2 = '' OR source_ip::text ILIKE '%' || $2 || '%')
  AND ($3::text IS NULL OR $3 = '' OR threat_level = $3)
  AND ($4::timestamptz IS NULL OR last_seen >= $4)
  AND ($5::timestamptz IS NULL OR last_seen <= $5)
GROUP BY destination_port, protocol, service_name
ORDER BY 
    CASE WHEN $6::text = 'threat_score' THEN MAX(threat_score) END DESC,
    CASE WHEN $6::text = 'hits' THEN SUM(hit_count) END DESC,
    CASE WHEN $6::text = 'bytes' THEN SUM(bytes_in) END DESC,
    MAX(last_seen) DESC
LIMIT $7 OFFSET $8;

-- name: CountPortTrafficByServer :one
-- Returns count of unique port/protocol/service combinations
SELECT COUNT(DISTINCT (destination_port, protocol, service_name))::int as total_count
FROM traffic_events
WHERE server_id = $1
  AND ($2::text IS NULL OR $2 = '' OR source_ip::text ILIKE '%' || $2 || '%')
  AND ($3::text IS NULL OR $3 = '' OR threat_level = $3)
  AND ($4::timestamptz IS NULL OR last_seen >= $4)
  AND ($5::timestamptz IS NULL OR last_seen <= $5);

-- name: ListProtocolTrafficByServer :many
-- Returns aggregated traffic data grouped by protocol with all source IPs
SELECT 
    protocol,
    COUNT(DISTINCT source_ip) as unique_ips,
    COUNT(DISTINCT destination_port) as unique_ports,
    SUM(bytes_in)::bigint as total_bytes_in,
    SUM(bytes_out)::bigint as total_bytes_out,
    SUM(hit_count)::int as total_hits,
    SUM(syn_count)::int as total_syn,
    SUM(ack_count)::int as total_ack,
    MAX(threat_score) as max_threat_score,
    MAX(threat_level) as max_threat_level,
    MAX(last_seen) as last_seen,
    COALESCE(
        jsonb_agg(
            DISTINCT jsonb_build_object(
                'source_ip', source_ip,
                'destination_port', destination_port,
                'destination_ip', destination_ip,
                'bytes_in', bytes_in,
                'bytes_out', bytes_out,
                'syn_count', syn_count,
                'ack_count', ack_count,
                'hit_count', hit_count,
                'threat_score', threat_score,
                'threat_level', threat_level,
                'country', country,
                'city', city,
                'isp', isp,
                'last_seen', last_seen,
                'direction', direction
            )
        ) FILTER (WHERE source_ip IS NOT NULL),
        '[]'::jsonb
    ) as sources
FROM traffic_events
WHERE server_id = $1
  AND ($2::text IS NULL OR $2 = '' OR source_ip::text ILIKE '%' || $2 || '%')
  AND ($3::text IS NULL OR $3 = '' OR threat_level = $3)
  AND ($4::timestamptz IS NULL OR last_seen >= $4)
  AND ($5::timestamptz IS NULL OR last_seen <= $5)
GROUP BY protocol
ORDER BY 
    CASE WHEN $6::text = 'threat_score' THEN MAX(threat_score) END DESC,
    CASE WHEN $6::text = 'hits' THEN SUM(hit_count) END DESC,
    CASE WHEN $6::text = 'bytes' THEN SUM(bytes_in) END DESC,
    MAX(last_seen) DESC
LIMIT $7 OFFSET $8;

-- name: CountProtocolTrafficByServer :one
-- Returns count of unique protocols
SELECT COUNT(DISTINCT protocol)::int as total_count
FROM traffic_events
WHERE server_id = $1
  AND ($2::text IS NULL OR $2 = '' OR source_ip::text ILIKE '%' || $2 || '%')
  AND ($3::text IS NULL OR $3 = '' OR threat_level = $3)
  AND ($4::timestamptz IS NULL OR last_seen >= $4)
  AND ($5::timestamptz IS NULL OR last_seen <= $5);

-- name: ListPortSourcesByServer :many
-- Returns paginated source IPs for a specific port/protocol combination
SELECT 
    source_ip,
    destination_ip,
    bytes_in,
    bytes_out,
    syn_count,
    ack_count,
    hit_count,
    threat_score,
    threat_level,
    country,
    city,
    isp,
    last_seen,
    direction,
    icmp_packets_in,
    icmp_packets_out,
    connection_duration_ms,
    port_bytes_in,
    port_bytes_out
FROM traffic_events
WHERE server_id = $1
  AND destination_port = $2
  AND protocol = $3
  AND ($4::text IS NULL OR $4 = '' 
       OR source_ip::text ILIKE '%' || $4 || '%' 
       OR country ILIKE '%' || $4 || '%' 
       OR city ILIKE '%' || $4 || '%')
ORDER BY 
    CASE WHEN $5::text = 'threat_score' AND $6::text = 'desc' THEN threat_score END DESC,
    CASE WHEN $5::text = 'threat_score' AND $6::text = 'asc' THEN threat_score END ASC,
    CASE WHEN $5::text = 'source_ip' AND $6::text = 'desc' THEN source_ip END DESC,
    CASE WHEN $5::text = 'source_ip' AND $6::text = 'asc' THEN source_ip END ASC,
    CASE WHEN $5::text = 'country' AND $6::text = 'desc' THEN country END DESC,
    CASE WHEN $5::text = 'country' AND $6::text = 'asc' THEN country END ASC,
    CASE WHEN $5::text = 'city' AND $6::text = 'desc' THEN city END DESC,
    CASE WHEN $5::text = 'city' AND $6::text = 'asc' THEN city END ASC,
    CASE WHEN $5::text = 'bytes_in' AND $6::text = 'desc' THEN bytes_in END DESC,
    CASE WHEN $5::text = 'bytes_in' AND $6::text = 'asc' THEN bytes_in END ASC,
    CASE WHEN $5::text = 'bytes_out' AND $6::text = 'desc' THEN bytes_out END DESC,
    CASE WHEN $5::text = 'bytes_out' AND $6::text = 'asc' THEN bytes_out END ASC,
    CASE WHEN $5::text = 'syn_count' AND $6::text = 'desc' THEN syn_count END DESC,
    CASE WHEN $5::text = 'syn_count' AND $6::text = 'asc' THEN syn_count END ASC,
    CASE WHEN $5::text = 'ack_count' AND $6::text = 'desc' THEN ack_count END DESC,
    CASE WHEN $5::text = 'ack_count' AND $6::text = 'asc' THEN ack_count END ASC,
    CASE WHEN $5::text = 'hit_count' AND $6::text = 'desc' THEN hit_count END DESC,
    CASE WHEN $5::text = 'hit_count' AND $6::text = 'asc' THEN hit_count END ASC,
    last_seen DESC
LIMIT $7 OFFSET $8;

-- name: CountPortSourcesByServer :one
-- Returns count of source IPs for a specific port/protocol combination
SELECT COUNT(*)::int as total_count
FROM traffic_events
WHERE server_id = $1
  AND destination_port = $2
  AND protocol = $3
  AND ($4::text IS NULL OR $4 = '' 
       OR source_ip::text ILIKE '%' || $4 || '%' 
       OR country ILIKE '%' || $4 || '%' 
       OR city ILIKE '%' || $4 || '%');

-- name: DeleteServer :exec
DELETE FROM servers
WHERE id = $1;

-- name: ListActivePlans :many
SELECT * FROM subscription_plans
WHERE is_active = true
ORDER BY price_cents ASC;

-- name: GetPlanByName :one
SELECT * FROM subscription_plans
WHERE name = $1;

-- name: GetPlanByPolarProductID :one
SELECT * FROM subscription_plans
WHERE polar_product_id = $1;

-- name: UpdateUserSubscription :exec
UPDATE users
SET plan = $2,
    polar_customer_id = COALESCE($3, polar_customer_id),
    polar_subscription_id = COALESCE($4, polar_subscription_id),
    subscription_status = COALESCE($5, subscription_status),
    subscription_current_period_start = COALESCE($6, subscription_current_period_start),
    subscription_current_period_end = COALESCE($7, subscription_current_period_end),
    subscription_cancel_at_period_end = COALESCE($8, subscription_cancel_at_period_end),
    trial_ends_at = COALESCE($9, trial_ends_at),
    has_used_trial = COALESCE($10, has_used_trial),
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateUserTrial :exec
UPDATE users
SET trial_ends_at = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: CreateSubscriptionEvent :one
INSERT INTO subscription_events (
    user_id, polar_event_id, event_type, payload, processed_at
) VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: CountServersByUser :one
SELECT COUNT(*)::int FROM servers
WHERE user_id = $1;

-- name: GetUserSubscriptionStatus :one
SELECT 
    u.id,
    u.email,
    u.plan,
    u.max_servers,
    u.subscription_status,
    u.subscription_current_period_start,
    u.subscription_current_period_end,
    u.subscription_cancel_at_period_end,
    u.trial_ends_at,
    p.display_name as plan_display_name,
    p.data_retention_days,
    p.features,
    (SELECT COUNT(*) FROM servers WHERE user_id = u.id) as current_server_count
FROM users u
LEFT JOIN subscription_plans p ON u.plan = p.name
WHERE u.id = $1;

-- ============================================
-- Reports & Analytics Queries
-- ============================================

-- name: GetDailyAttackStats :many
SELECT 
    DATE(te.created_at) as date,
    COUNT(*)::int as total_attacks,
    SUM(te.hit_count)::int as total_events,
    COUNT(DISTINCT te.source_ip)::int as unique_sources,
    SUM(CASE WHEN te.threat_level = 'malicious' THEN te.hit_count ELSE 0 END)::int as blocked,
    SUM(CASE WHEN te.destination_port = 22 THEN te.hit_count ELSE 0 END)::int as ssh_attacks,
    SUM(CASE WHEN te.destination_port IN (80, 443) THEN te.hit_count ELSE 0 END)::int as http_attacks,
    SUM(CASE WHEN te.destination_port NOT IN (22, 80, 443) THEN te.hit_count ELSE 0 END)::int as other_attacks
FROM traffic_events te
JOIN servers s ON te.server_id = s.id
WHERE s.user_id = $1
  AND te.created_at >= $2
  AND te.created_at <= $3
GROUP BY DATE(te.created_at)
ORDER BY date DESC;

-- name: GetDailyBlockStats :many
-- Get blocked IPs stats from blocks table (actually prevented attacks)
SELECT 
    DATE(b.blocked_at) as date,
    COUNT(*)::int as total_blocks,
    COUNT(DISTINCT b.ip_address)::int as unique_ips,
    SUM(CASE WHEN b.threat_level = 'malicious' THEN 1 ELSE 0 END)::int as malicious_blocks,
    SUM(CASE WHEN b.threat_level = 'suspicious' THEN 1 ELSE 0 END)::int as suspicious_blocks,
    SUM(CASE WHEN b.is_active = true AND (b.expires_at IS NULL OR b.expires_at > NOW()) THEN 1 ELSE 0 END)::int as active_blocks
FROM blocks b
WHERE b.user_id = $1
  AND b.blocked_at >= $2
  AND b.blocked_at <= $3
GROUP BY DATE(b.blocked_at)
ORDER BY date DESC;

-- name: GetAttackTypeBreakdown :many
SELECT 
    CASE 
        WHEN te.destination_port = 22 THEN 'SSH Bruteforce'
        WHEN te.destination_port = 80 THEN 'HTTP Attack'
        WHEN te.destination_port = 443 THEN 'HTTPS Attack'
        WHEN te.destination_port IN (21, 23, 25, 3306, 5432, 6379, 27017) THEN 'Service Attack'
        ELSE 'Port Scan'
    END as attack_type,
    SUM(te.hit_count)::int as count,
    COUNT(DISTINCT te.source_ip)::int as unique_sources
FROM traffic_events te
JOIN servers s ON te.server_id = s.id
WHERE s.user_id = $1
  AND te.created_at >= $2
  AND te.created_at <= $3
GROUP BY 
    CASE 
        WHEN te.destination_port = 22 THEN 'SSH Bruteforce'
        WHEN te.destination_port = 80 THEN 'HTTP Attack'
        WHEN te.destination_port = 443 THEN 'HTTPS Attack'
        WHEN te.destination_port IN (21, 23, 25, 3306, 5432, 6379, 27017) THEN 'Service Attack'
        ELSE 'Port Scan'
    END
ORDER BY count DESC;

-- name: GetTopSourceCountries :many
SELECT 
    COALESCE(te.country, 'Unknown') as country,
    COUNT(*)::int as attack_count,
    COUNT(DISTINCT te.source_ip)::int as unique_ips,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 1) as percentage
FROM traffic_events te
JOIN servers s ON te.server_id = s.id
WHERE s.user_id = $1
  AND te.created_at >= $2
  AND te.created_at <= $3
GROUP BY te.country
ORDER BY attack_count DESC
LIMIT $4;

-- name: GetHourlyAttackDistribution :many
-- Uses actual blocks from blocks table for accurate blocked_count
-- rather than estimating from traffic_events threat_level
SELECT 
    COALESCE(attack_data.hour, block_data.hour) as hour,
    COALESCE(attack_data.attack_count, 0)::int as attack_count,
    COALESCE(block_data.blocked_count, 0)::int as blocked_count
FROM (
    -- Get attack counts from traffic_events
    SELECT 
        EXTRACT(HOUR FROM te.created_at)::int as hour,
        SUM(te.hit_count)::int as attack_count
    FROM traffic_events te
    JOIN servers s ON te.server_id = s.id
    WHERE s.user_id = $1
      AND te.created_at >= $2
      AND te.created_at <= $3
    GROUP BY EXTRACT(HOUR FROM te.created_at)
) attack_data
FULL OUTER JOIN (
    -- Get actual block counts from blocks table
    SELECT 
        EXTRACT(HOUR FROM b.blocked_at)::int as hour,
        COUNT(*)::int as blocked_count
    FROM blocks b
    WHERE b.user_id = $1
      AND b.blocked_at >= $2
      AND b.blocked_at <= $3
      AND b.is_auto_blocked = true
    GROUP BY EXTRACT(HOUR FROM b.blocked_at)
) block_data ON attack_data.hour = block_data.hour
ORDER BY COALESCE(attack_data.hour, block_data.hour);

-- name: GetTopSourceIPs :many
SELECT 
    te.source_ip::text as ip,
    SUM(te.hit_count)::int as count,
    COUNT(DISTINCT te.destination_port)::int as unique_ports,
    MIN(te.first_seen) as first_seen,
    MAX(te.last_seen) as last_seen,
    COALESCE(te.country, 'Unknown') as country,
    COALESCE(te.isp, 'Unknown') as isp
FROM traffic_events te
JOIN servers s ON te.server_id = s.id
WHERE s.user_id = $1
  AND te.created_at >= $2
  AND te.created_at <= $3
GROUP BY te.source_ip, te.country, te.isp
ORDER BY count DESC
LIMIT $4;

-- name: GetSourceIPTimeline :many
SELECT 
    te.source_ip::text as ip,
    DATE_TRUNC('hour', te.created_at)::timestamp as time_bucket,
    SUM(te.hit_count)::int as count
FROM traffic_events te
JOIN servers s ON te.server_id = s.id
WHERE s.user_id = $1
  AND te.source_ip = $2::inet
  AND te.created_at >= NOW() - INTERVAL '24 hours'
GROUP BY te.source_ip, DATE_TRUNC('hour', te.created_at)
ORDER BY time_bucket;

-- name: GetTopASNs :many
SELECT 
    COALESCE(te.asn, 'Unknown') as asn,
    COALESCE(te.isp, 'Unknown') as isp_name,
    COALESCE(te.country, 'Unknown') as country,
    SUM(te.hit_count)::int as count,
    COUNT(DISTINCT te.source_ip)::int as unique_ips
FROM traffic_events te
JOIN servers s ON te.server_id = s.id
WHERE s.user_id = $1
  AND te.created_at >= $2
  AND te.created_at <= $3
  AND te.asn IS NOT NULL
GROUP BY te.asn, te.isp, te.country
ORDER BY count DESC
LIMIT $4;

-- name: GetThreatTrends :many
SELECT 
    DATE_TRUNC('day', te.created_at)::date as date,
    SUM(CASE WHEN te.threat_level = 'normal' THEN te.hit_count ELSE 0 END)::int as normal,
    SUM(CASE WHEN te.threat_level = 'suspicious' THEN te.hit_count ELSE 0 END)::int as suspicious,
    SUM(CASE WHEN te.threat_level = 'malicious' THEN te.hit_count ELSE 0 END)::int as malicious
FROM traffic_events te
JOIN servers s ON te.server_id = s.id
WHERE s.user_id = $1
  AND te.created_at >= $2
  AND te.created_at <= $3
GROUP BY DATE_TRUNC('day', te.created_at)
ORDER BY date DESC;

-- name: UpdateServerAPIKey :exec
UPDATE servers
SET api_key = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateServerConfig :exec
UPDATE servers
SET config = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: ListAllActiveServers :many
SELECT id, user_id, hostname, api_key, ip_address, status, agent_version, created_at, last_seen
FROM servers
WHERE status = 'active';

-- name: UpdateTrafficScore :exec
UPDATE traffic_events
SET threat_score = $3,
    threat_level = $4,
    threat_type = $5
WHERE server_id = $1 AND source_ip = $2 AND direction = 'inbound';

-- ============================================
-- Whitelist Queries
-- ============================================

-- name: AddToWhitelist :one
INSERT INTO whitelist (user_id, ip_address, ip_version, reason, is_manual, created_by)
VALUES ($1, $2, $3, $4, true, $1)
ON CONFLICT (user_id, ip_address) DO UPDATE SET
    reason = EXCLUDED.reason,
    updated_at = NOW(),
    is_manual = true
RETURNING *;

-- name: RemoveFromWhitelist :exec
DELETE FROM whitelist
WHERE user_id = $1 AND ip_address = $2;

-- name: GetWhitelistByUser :many
SELECT * FROM whitelist
WHERE user_id = $1
ORDER BY created_at DESC;

-- name: IsIPWhitelisted :one
SELECT EXISTS(
    SELECT 1 FROM whitelist
    WHERE user_id = $1 AND ip_address = $2
) as is_whitelisted;

-- name: IsIPAttackingUserServer :one
-- Check if an IP has attacked any of the user's servers
SELECT EXISTS(
    SELECT 1 FROM traffic_events te
    JOIN servers s ON te.server_id = s.id
    WHERE s.user_id = $1 AND te.source_ip = $2
    LIMIT 1
) as is_attacking;

-- name: ResetTrafficScoreForIP :exec
-- Reset threat score for an IP after unblock (keeps history for future calculations)
-- Sets score to 0 and level to normal, but preserves traffic counts
UPDATE traffic_events
SET threat_score = 0,
    threat_level = 'normal',
    threat_type = NULL
WHERE server_id = $1 AND source_ip = $2;

-- name: GetWhitelistedIPs :many
SELECT ip_address FROM whitelist
WHERE user_id = $1;

-- ============================================
-- Traffic Aggregation Queries for Backend Scoring
-- ============================================

-- name: GetTrafficAggregationByIP :many
-- Aggregates traffic by source_ip over a given time window for scoring
SELECT 
    te.source_ip,
    SUM(te.syn_count)::bigint as syn_count,
    SUM(te.ack_count)::bigint as ack_count,
    SUM(te.failed_handshakes)::bigint as failed_handshakes,
    COUNT(DISTINCT te.destination_port)::int as unique_ports,
    SUM(te.bytes_in)::bigint as bytes_in,
    SUM(te.bytes_out)::bigint as bytes_out,
    MAX(te.threat_score)::int as max_threat_score,
    COUNT(*)::int as event_count,
    MIN(te.first_seen) as window_start,
    MAX(te.last_seen) as window_end,
    te.server_id,
    COUNT(DISTINCT te.destination_port) as port_count
FROM traffic_events te
WHERE te.server_id = $1
  AND te.last_seen >= $2
  AND te.direction = 'inbound'
GROUP BY te.source_ip, te.server_id;

-- name: GetHighScoreTraffic :many
-- Gets IPs with scores above threshold for potential blocking
SELECT 
    te.source_ip,
    MAX(te.threat_score)::int as threat_score,
    MAX(te.threat_level)::text as threat_level,
    MAX(te.threat_type)::text as threat_type,
    COUNT(DISTINCT te.server_id)::int as server_count,
    MAX(te.last_seen) as last_seen,
    SUM(te.syn_count)::bigint as total_syn,
    SUM(te.failed_handshakes)::bigint as total_failed,
    COUNT(DISTINCT te.destination_port)::int as unique_ports
FROM traffic_events te
WHERE te.threat_score >= $1
  AND te.last_seen >= $2
GROUP BY te.source_ip
ORDER BY te.threat_score DESC;

-- name: GetIPTrafficHistory :many
-- Gets historical traffic for a specific IP across all servers
SELECT 
    te.source_ip,
    te.server_id,
    s.hostname as server_name,
    te.syn_count,
    te.ack_count,
    te.failed_handshakes,
    te.unique_ports,
    te.threat_score,
    te.threat_level,
    te.threat_type,
    te.destination_port,
    te.protocol,
    te.service_name,
    te.direction,
    te.first_seen,
    te.last_seen,
    te.country,
    te.city,
    te.isp
FROM traffic_events te
JOIN servers s ON te.server_id = s.id
WHERE te.source_ip = $1
  AND s.user_id = $2
ORDER BY te.last_seen DESC
LIMIT $3;

-- name: GetUserHighScoreTraffic :many
-- Gets high score traffic for all servers owned by user
SELECT 
    te.source_ip,
    MAX(te.threat_score)::int as threat_score,
    MAX(te.threat_level)::text as threat_level,
    MAX(te.threat_type)::text as threat_type,
    s.id as server_id,
    s.hostname as server_name,
    COUNT(DISTINCT te.destination_port)::int as unique_ports,
    SUM(te.syn_count)::bigint as total_syn,
    SUM(te.failed_handshakes)::bigint as total_failed,
    MAX(te.last_seen) as last_seen,
    te.country,
    te.city,
    te.isp
FROM traffic_events te
JOIN servers s ON te.server_id = s.id
WHERE s.user_id = $1
  AND te.threat_score >= $2
  AND te.last_seen >= $3
GROUP BY te.source_ip, te.server_id, s.hostname, te.country, te.city, te.isp
ORDER BY te.threat_score DESC
LIMIT $4;

-- name: GetRecentlyActiveIPs :many
-- Gets IPs that have been active within the time window
SELECT 
    te.source_ip,
    te.server_id,
    MAX(te.last_seen) as last_seen,
    COUNT(*)::int as event_count,
    SUM(te.syn_count)::bigint as total_syn,
    SUM(te.ack_count)::bigint as total_ack,
    SUM(te.failed_handshakes)::bigint as total_failed,
    COUNT(DISTINCT te.destination_port)::int as unique_ports
FROM traffic_events te
WHERE te.server_id = $1
  AND te.last_seen >= $2
GROUP BY te.source_ip, te.server_id;

-- name: GetBlockableIPs :many
-- Gets IPs that exceed the scoring threshold for potential blocking
-- Uses MAX for geo fields to avoid grouping issues and get most recent values
SELECT 
    te.source_ip,
    te.server_id,
    s.hostname as server_name,
    s.user_id,
    MAX(te.threat_score)::int as threat_score,
    MAX(te.threat_level)::text as threat_level,
    MAX(te.threat_type)::text as threat_type,
    SUM(te.syn_count)::bigint as total_syn,
    SUM(te.ack_count)::bigint as total_ack,
    SUM(te.failed_handshakes)::bigint as total_failed,
    COUNT(DISTINCT te.destination_port)::int as unique_ports,
    COUNT(DISTINCT te.server_id)::int as server_count,
    MAX(te.last_seen) as last_seen,
    MAX(te.country) as country,
    MAX(te.country_code) as country_code,
    MAX(te.city) as city,
    MAX(te.isp) as isp,
    MAX(te.asn) as asn,
    -- Get the most targeted port, protocol and service name (mode)
    MODE() WITHIN GROUP (ORDER BY te.destination_port)::int as top_target_port,
    MODE() WITHIN GROUP (ORDER BY te.protocol)::text as top_protocol,
    MODE() WITHIN GROUP (ORDER BY te.service_name)::text as top_service_name
FROM traffic_events te
JOIN servers s ON te.server_id = s.id
WHERE te.last_seen >= $1
  AND te.threat_score >= $2
  AND te.direction = 'inbound'
GROUP BY te.source_ip, te.server_id, s.hostname, s.user_id
ORDER BY MAX(te.threat_score) DESC;

-- name: GetActiveBlocksForServer :many
-- Gets active blocks for a specific server (for state reconciliation)
SELECT 
    id, server_id, user_id, ip_address, ip_version, threat_score, threat_level,
    reasons, target_port, service_name, protocol, country_code, country_name,
    city, region, latitude, longitude, asn, asn_org, is_vpn, is_tor, is_datacenter,
    blocked_at, expires_at, duration_seconds, is_active, is_auto_blocked,
    unblocked_at, unblocked_by, unblock_reason, agent_version, raw_metrics,
    enforcement_type,
    created_at, updated_at
FROM blocks
WHERE server_id = $1
  AND is_active = true
  AND (expires_at > NOW() OR expires_at IS NULL)
ORDER BY blocked_at DESC;

-- name: GetAllActiveBlocks :many
-- Gets all active blocks across all servers (for BlockManager state recovery).
-- Includes permanent blocks (expires_at IS NULL) which have no expiry.
SELECT 
    id, server_id, user_id, ip_address, ip_version, threat_score, threat_level,
    reasons, target_port, service_name, protocol, country_code, country_name,
    city, region, latitude, longitude, asn, asn_org, is_vpn, is_tor, is_datacenter,
    blocked_at, expires_at, duration_seconds, is_active, is_auto_blocked,
    unblocked_at, unblocked_by, unblock_reason, agent_version, raw_metrics,
    enforcement_type,
    created_at, updated_at
FROM blocks
WHERE is_active = true
  AND (expires_at > NOW() OR expires_at IS NULL)
ORDER BY blocked_at DESC;


-- ============================================
-- User Polar Integration Queries
-- ============================================

-- name: GetUserByPolarCustomerID :one
SELECT * FROM users
WHERE polar_customer_id = $1;

-- name: UpdateUserPolarCustomerID :exec
UPDATE users
SET polar_customer_id = $2,
    updated_at = NOW()
WHERE id = $1;

-- ============================================
-- Monthly Report Queries
-- ============================================

-- name: ListUsersForReports :many
-- Gets all users with email addresses for monthly reports
SELECT id, email, email as name
FROM users
WHERE email IS NOT NULL AND email != ''
  AND (subscription_status = 'active' OR subscription_status = 'trialing');

-- name: GetMonthlyTrafficStats :one
-- Gets total traffic event count for a user in a date range
SELECT COALESCE(SUM(te.hit_count), 0)::bigint as total_events
FROM traffic_events te
JOIN servers s ON te.server_id = s.id
WHERE s.user_id = $1
  AND te.last_seen >= $2
  AND te.last_seen <= $3;

-- name: GetMonthlyBlockStats :one
-- Gets total blocked connection count for a user in a date range
SELECT COUNT(*)::bigint as blocked_count
FROM blocks
WHERE user_id = $1
  AND blocked_at >= $2
  AND blocked_at <= $3;

-- name: GetMonthlyThreatStats :one
-- Gets count of threat-level traffic events (non-normal)
SELECT COALESCE(SUM(te.hit_count), 0)::bigint as threat_count
FROM traffic_events te
JOIN servers s ON te.server_id = s.id
WHERE s.user_id = $1
  AND te.last_seen >= $2
  AND te.last_seen <= $3
  AND te.threat_level != 'normal';

-- name: GetMonthlyUniqueThreatIPs :one
-- Gets count of unique threat IPs for a user in a date range
SELECT COUNT(DISTINCT te.source_ip)::bigint as unique_ips
FROM traffic_events te
JOIN servers s ON te.server_id = s.id
WHERE s.user_id = $1
  AND te.last_seen >= $2
  AND te.last_seen <= $3
  AND te.threat_level != 'normal';

-- name: GetMonthlyTopPorts :many
-- Gets top targeted ports for a user in a date range (top 5)
SELECT 
    te.destination_port as port,
    COALESCE(
        MODE() WITHIN GROUP (ORDER BY te.service_name),
        'unknown'::text
    ) as service_name,
    SUM(te.hit_count)::bigint as count
FROM traffic_events te
JOIN servers s ON te.server_id = s.id
WHERE s.user_id = $1
  AND te.last_seen >= $2
  AND te.last_seen <= $3
GROUP BY te.destination_port
ORDER BY count DESC
LIMIT 5;

-- name: GetMonthlyTopBlockedIPs :many
-- Gets top blocked IPs for a user in a date range (top 5)
SELECT 
    b.ip_address,
    COALESCE(MAX(b.country_name), 'Unknown') as country,
    COUNT(*)::bigint as count
FROM blocks b
WHERE b.user_id = $1
  AND b.blocked_at >= $2
  AND b.blocked_at <= $3
GROUP BY b.ip_address
ORDER BY count DESC
LIMIT 5;

-- name: GetMonthlyTopCountries :many
-- Gets top attacking countries for a user in a date range (top 5)
SELECT 
    COALESCE(te.country, 'Unknown') as country,
    SUM(te.hit_count)::bigint as count
FROM traffic_events te
JOIN servers s ON te.server_id = s.id
WHERE s.user_id = $1
  AND te.last_seen >= $2
  AND te.last_seen <= $3
  AND te.threat_level != 'normal'
  AND te.country IS NOT NULL
GROUP BY te.country
ORDER BY count DESC
LIMIT 5;


-- ============================================
-- Data Retention Queries
-- ============================================

-- name: ArchiveTrafficEvents :one
-- Archives old traffic events based on retention policy
SELECT archive_traffic_events($1, $2)::int as archived_count;

-- name: GetServerDataRetentionDays :one
-- Gets the data retention days for a server's user
SELECT p.data_retention_days
FROM servers s
JOIN users u ON s.user_id = u.id
JOIN subscription_plans p ON u.plan = p.name
WHERE s.id = $1;

-- name: GetAllServersWithRetention :many
-- Gets all servers with their data retention settings for archival job
SELECT 
    s.id as server_id,
    u.id as user_id,
    COALESCE(p.data_retention_days, 7) as retention_days
FROM servers s
JOIN users u ON s.user_id = u.id
LEFT JOIN subscription_plans p ON u.plan = p.name;

-- name: GetArchivedEventsCount :one
-- Returns count of archived events for a server
SELECT COUNT(*)::bigint as count
FROM traffic_events_archive
WHERE server_id = $1;

-- name: CleanupOldArchives :one
-- Deletes archived data older than 1 year
SELECT cleanup_old_archives()::int as deleted_count;
