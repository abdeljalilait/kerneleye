-- Blocks queries for the dashboard and API

-- name: CreateBlock :one
INSERT INTO blocks (
    server_id,
    user_id,
    ip_address,
    ip_version,
    threat_score,
    threat_level,
    reasons,
    target_port,
    service_name,
    protocol,
    country_code,
    country_name,
    city,
    region,
    latitude,
    longitude,
    asn,
    asn_org,
    is_vpn,
    is_tor,
    is_datacenter,
    blocked_at,
    expires_at,
    duration_seconds,
    is_auto_blocked,
    agent_version,
    raw_metrics,
    enforcement_type
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
    $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
    $21, $22, $23, $24, $25, $26, $27, $28
) RETURNING *;

-- name: GetIPEnforcementHistory :one
-- Returns aggregate prior enforcement counts for a given IP+user across all
-- time (including expired/unblocked records). Used by the escalation engine.
SELECT
    COUNT(*)::int                                                          AS total_prior,
    COUNT(*) FILTER (WHERE enforcement_type = 'ratelimit')::int            AS ratelimit_count,
    COUNT(*) FILTER (WHERE enforcement_type = 'block')::int                AS block_count,
    COUNT(*) FILTER (WHERE enforcement_type = 'permanent')::int            AS permanent_count,
    MAX(threat_score)::int                                                 AS max_prior_score
FROM blocks
WHERE user_id    = $1
  AND ip_address = $2;

-- name: ListBlocks :many
SELECT 
    b.*,
    s.hostname as server_name
FROM blocks b
JOIN servers s ON b.server_id = s.id
WHERE b.user_id = $1
  AND (b.server_id = $2 OR $2 IS NULL)
  AND (b.service_name = $3 OR $3 IS NULL)
  AND (b.country_code = $4 OR $4 IS NULL)
  AND (b.is_active = $5 OR $5 IS NULL)
  AND (
      ($6 = false AND b.unblocked_at IS NULL)
      OR ($6 = true AND b.unblocked_at IS NOT NULL)
      OR $6 IS NULL
  )
  AND (b.ip_address::text LIKE '%' || $7 || '%' OR $7 IS NULL)
ORDER BY b.blocked_at DESC
LIMIT $8 OFFSET $9;

-- name: CountBlocks :one
SELECT COUNT(*) FROM blocks
WHERE user_id = $1;

-- name: CountActiveBlocks :one
SELECT COUNT(*) FROM blocks
WHERE user_id = $1 AND is_active = true;

-- name: CountBlocksToday :one
SELECT COUNT(*) FROM blocks
WHERE user_id = $1 
  AND blocked_at >= DATE_TRUNC('day', NOW());

-- name: GetActiveBlockByIP :one
SELECT * FROM blocks
WHERE user_id = $1 
  AND ip_address = $2
  AND is_active = true
LIMIT 1;

-- name: GetBlockByID :one
SELECT b.*, s.hostname as server_name
FROM blocks b
JOIN servers s ON b.server_id = s.id
WHERE b.id = $1 AND b.user_id = $2;

-- name: UnblockIP :exec
UPDATE blocks SET
    is_active = false,
    unblocked_at = $2,
    unblocked_by = $3,
    unblock_reason = $4,
    updated_at = NOW()
WHERE id = $1;

-- name: IsIPBlocked :one
SELECT EXISTS(
    SELECT 1 FROM blocks
    WHERE user_id = $1 
      AND ip_address = $2
      AND is_active = true
);

-- name: GetBlockRemainingTime :one
SELECT EXTRACT(EPOCH FROM (expires_at - NOW()))::bigint as seconds
FROM blocks
WHERE user_id = $1 
  AND ip_address = $2
  AND is_active = true;

-- Statistics queries

-- name: GetBlockStatsByService :many
SELECT 
    COALESCE(service_name, 'unknown') as service_name,
    COUNT(*) as count
FROM blocks
WHERE user_id = $1
  AND blocked_at >= NOW() - INTERVAL '30 days'
GROUP BY service_name
ORDER BY count DESC;

-- name: GetBlockStatsByCountry :many
SELECT 
    COALESCE(country_code, 'unknown') as country_code,
    COUNT(*) as count
FROM blocks
WHERE user_id = $1
  AND blocked_at >= NOW() - INTERVAL '30 days'
GROUP BY country_code
ORDER BY count DESC
LIMIT 20;

-- name: GetBlockStatsByServer :many
SELECT 
    s.hostname as server_name,
    COUNT(*) as count
FROM blocks b
JOIN servers s ON b.server_id = s.id
WHERE b.user_id = $1
  AND b.blocked_at >= NOW() - INTERVAL '30 days'
GROUP BY s.hostname
ORDER BY count DESC;

-- name: GetBlockStatsByThreatLevel :many
SELECT 
    threat_level,
    COUNT(*) as count
FROM blocks
WHERE user_id = $1
  AND blocked_at >= NOW() - INTERVAL '30 days'
GROUP BY threat_level
ORDER BY count DESC;

-- name: GetRecentBlocks :many
SELECT 
    b.*,
    s.hostname as server_name
FROM blocks b
JOIN servers s ON b.server_id = s.id
WHERE b.user_id = $1
ORDER BY b.blocked_at DESC
LIMIT $2;

-- name: UpdateBlockExpiry :exec
UPDATE blocks SET
    expires_at = $2,
    blocked_at = COALESCE($3, blocked_at),
    duration_seconds = $4,
    enforcement_type = $5,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateBlockContext :exec
-- Backfill target_port / service_name / protocol on an existing block that was
-- created without context (e.g. startup-sync from XDP/ipset).
-- Only overwrites columns that are still NULL so we never clobber real data.
UPDATE blocks SET
    target_port   = CASE WHEN target_port IS NULL THEN $2 ELSE target_port END,
    service_name  = CASE WHEN service_name IS NULL THEN $3 ELSE service_name END,
    protocol      = CASE WHEN protocol IS NULL THEN $4 ELSE protocol END,
    updated_at    = NOW()
WHERE id = $1;

-- name: GetLatestBlockByIP :one
-- Returns the most recent block record for a given IP and user regardless of
-- active status – used as a context fallback during startup sync.
SELECT * FROM blocks
WHERE user_id = $1
  AND ip_address = $2
ORDER BY blocked_at DESC
LIMIT 1;


-- name: CleanupExpiredBlocks :exec
UPDATE blocks SET
    is_active = false
WHERE is_active = true
  AND expires_at < NOW();

-- name: UpdateServerMetadata :exec
UPDATE servers SET
    metadata = $2,
    updated_at = NOW()
WHERE id = $1;
