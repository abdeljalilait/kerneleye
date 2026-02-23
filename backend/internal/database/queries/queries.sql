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
    first_seen, last_seen, country, city, isp, asn, hit_count
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, 1)
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
    threat_type = CASE 
        WHEN EXCLUDED.threat_score > traffic_events.threat_score THEN EXCLUDED.threat_type 
        ELSE traffic_events.threat_type 
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
    threat_type = $5,
    updated_at = NOW()
WHERE server_id = $1 AND source_ip = $2;

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
    te.country,
    te.city,
    te.isp,
    te.asn
FROM traffic_events te
JOIN servers s ON te.server_id = s.id
WHERE te.last_seen >= $1
  AND te.threat_score >= $2
GROUP BY te.source_ip, te.server_id, s.hostname, s.user_id, te.country, te.city, te.isp, te.asn
ORDER BY te.threat_score DESC;


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


