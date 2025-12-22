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
    first_seen, last_seen, country, city, isp, hit_count
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, 1)
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
ORDER BY te.threat_score DESC, te.created_at DESC
LIMIT $2;

-- name: CreateAlert :one
INSERT INTO alerts (
    server_id, source_ip, threat_score, reason, 
    severity, status, auto_blocked
) VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: ListAlerts :many
SELECT a.* FROM alerts a
JOIN servers s ON a.server_id = s.id
WHERE s.user_id = $1
ORDER BY a.created_at DESC
LIMIT $2;

-- name: GetStatsServerCounts :one
SELECT 
    COUNT(*)::int as total_servers,
    COUNT(*) FILTER (WHERE status = 'active')::int as active_servers
FROM servers 
WHERE user_id = $1;

-- name: GetStatsEventCounts :one
SELECT 
    COUNT(*)::bigint as total_events,
    COUNT(*) FILTER (WHERE te.created_at > NOW() - INTERVAL '24 hours')::bigint as events_last_24h
FROM traffic_events te
JOIN servers s ON te.server_id = s.id
WHERE s.user_id = $1;

-- name: GetStatsAlertCounts :one
SELECT 
    COUNT(*)::int as total_alerts,
    COUNT(*) FILTER (WHERE a.created_at > NOW() - INTERVAL '24 hours')::int as alerts_last_24h,
    COUNT(*) FILTER (WHERE a.status = 'active')::int as active_threats
FROM alerts a
JOIN servers s ON a.server_id = s.id
WHERE s.user_id = $1;

-- name: ListTrafficEventsByServer :many
SELECT * FROM traffic_events
WHERE server_id = $1
ORDER BY created_at DESC
LIMIT $2;

-- name: GetServerStats :one
SELECT 
    COUNT(*)::bigint as total_events,
    COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours')::bigint as events_last_24h,
    COUNT(*) FILTER (WHERE threat_level IN ('suspicious', 'malicious'))::int as threat_events,
    COALESCE(SUM(bytes_in), 0)::bigint as total_bytes_in,
    COALESCE(SUM(bytes_out), 0)::bigint as total_bytes_out
FROM traffic_events
WHERE server_id = $1;

-- name: DeleteServer :exec
DELETE FROM servers
WHERE id = $1 AND user_id = $2;
