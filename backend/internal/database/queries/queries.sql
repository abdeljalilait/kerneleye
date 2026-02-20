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
    bytes_in, bytes_out, threat_score, threat_level,
    first_seen, last_seen, country, city, isp, asn, hit_count
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, 1)
ON CONFLICT (server_id, source_ip, destination_ip, destination_port, direction) DO UPDATE SET
    syn_count = traffic_events.syn_count + EXCLUDED.syn_count,
    ack_count = traffic_events.ack_count + EXCLUDED.ack_count,
    failed_handshakes = traffic_events.failed_handshakes + EXCLUDED.failed_handshakes,
    unique_ports = GREATEST(traffic_events.unique_ports, EXCLUDED.unique_ports),
    bytes_in = traffic_events.bytes_in + EXCLUDED.bytes_in,
    bytes_out = traffic_events.bytes_out + EXCLUDED.bytes_out,
    threat_score = GREATEST(traffic_events.threat_score, EXCLUDED.threat_score),
    threat_level = CASE 
        WHEN EXCLUDED.threat_score > traffic_events.threat_score THEN EXCLUDED.threat_level 
        ELSE traffic_events.threat_level 
    END,
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
ORDER BY created_at DESC
LIMIT $2;

-- name: GetServerStats :one
SELECT 
    COALESCE(SUM(hit_count), 0)::bigint as total_events,
    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours')::int as events_last_24h,
    COUNT(*) FILTER (WHERE threat_level = 'malicious')::int as threat_events,
    COALESCE(SUM(bytes_in), 0)::bigint as total_bytes_in,
    COALESCE(SUM(bytes_out), 0)::bigint as total_bytes_out
FROM traffic_events
WHERE server_id = $1;

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
SELECT 
    EXTRACT(HOUR FROM te.created_at)::int as hour,
    SUM(te.hit_count)::int as attack_count,
    SUM(CASE WHEN te.threat_level = 'malicious' THEN te.hit_count ELSE 0 END)::int as blocked_count
FROM traffic_events te
JOIN servers s ON te.server_id = s.id
WHERE s.user_id = $1
  AND te.created_at >= $2
  AND te.created_at <= $3
GROUP BY EXTRACT(HOUR FROM te.created_at)
ORDER BY hour;

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
