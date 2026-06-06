-- Migration 029: Index optimization — drop redundant indexes, create missing
-- performance indexes, and tune table storage parameters.
-- Created: 2026-06-06
--
-- Analysis: reviewed all 28 prior migrations and 177 query methods.
-- Drops 10 indexes that are never touched by any query path and replaces them
-- with 4 composite indexes that target the hottest access patterns.
-- Also backfills 6 indexes defined in migration 001 that may be absent.

-- ============================================================================
-- 1. DROP REDUNDANT INDEXES
-- ============================================================================

-- traffic_timeline: standalone indexes — all queries JOIN servers first,
-- so server_id is always known. The PK (server_id, source_ip, bucket) and
-- idx_traffic_timeline_server_bucket (server_id, bucket DESC) cover every pattern.
DROP INDEX IF EXISTS idx_traffic_timeline_bucket;       -- standalone bucket, 48 kB
DROP INDEX IF EXISTS idx_traffic_timeline_source_ip;    -- standalone source_ip, 40 kB

-- traffic_events: indexes on columns that are never used in WHERE or ORDER BY
DROP INDEX IF EXISTS idx_traffic_server_created;         -- (server_id, created_at DESC)
                                                         -- Every query uses last_seen, not created_at. 56 kB wasted.
DROP INDEX IF EXISTS idx_traffic_destination_ip;         -- no query filters this column
DROP INDEX IF EXISTS idx_traffic_threat_type;            -- no query filters this column
DROP INDEX IF EXISTS idx_traffic_country_code;           -- standalone; all geo queries JOIN servers first
DROP INDEX IF EXISTS idx_traffic_asn;                    -- standalone; only appears in GROUP BY after JOIN

-- blocks: standalone single-column indexes — useless without user_id/server_id prefix
DROP INDEX IF EXISTS idx_blocks_country;                 -- no query filters country_code alone
DROP INDEX IF EXISTS idx_blocks_service;                 -- no query filters service_name alone
DROP INDEX IF EXISTS idx_blocks_threat_score;            -- no query orders/filters by score alone

-- servers: never queried by last_seen alone (heartbeat uses api_key, listing uses user_id)
DROP INDEX IF EXISTS idx_servers_last_seen;

-- ============================================================================
-- 2. BACKFILL MISSING INDEXES FROM MIGRATION 001
-- ============================================================================
-- These are defined in 001_initial_schema.sql but may be absent from the live
-- database. They are essential for basic query performance.

CREATE INDEX IF NOT EXISTS idx_servers_user_id    ON servers(user_id);
CREATE INDEX IF NOT EXISTS idx_servers_status     ON servers(status);
CREATE INDEX IF NOT EXISTS idx_alerts_server_id   ON alerts(server_id);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at  ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_traffic_direction  ON traffic_events(direction);

-- ============================================================================
-- 3. NEW PERFORMANCE INDEXES
-- ============================================================================

-- traffic_events(server_id, last_seen DESC) — THE primary access pattern.
-- Used by: ListTrafficEventsByServer, GetTrafficAggregationByIP,
--          GetRecentlyActiveIPs, GetServerStats, GetMonthlyTrafficStats,
--          GetDailyAttackStats, GetThreatTrends, GetTopSourceIPs,
--          GetTopSourceCountries, GetAttackTypeBreakdown, GetTopASNs.
CREATE INDEX IF NOT EXISTS idx_traffic_server_last_seen
    ON traffic_events(server_id, last_seen DESC);

-- traffic_events(server_id, threat_level, last_seen DESC) — filtered listing.
-- Used by: ListTrafficEventsByServer (with threat_level filter),
--          ListThreats, GetMonthlyThreatStats, GetMonthlyUniqueThreatIPs.
CREATE INDEX IF NOT EXISTS idx_traffic_server_threat_last
    ON traffic_events(server_id, threat_level, last_seen DESC);

-- blocks(user_id, ip_address) — enforcement hot path.
-- Called on EVERY block decision and IP status check.
-- Used by: GetIPEnforcementHistory, IsIPBlocked, GetActiveBlockByIP,
--          GetBlockRemainingTime, GetLatestBlockByIP.
CREATE INDEX IF NOT EXISTS idx_blocks_user_ip
    ON blocks(user_id, ip_address);

-- blocks(server_id, is_active, expires_at) WHERE is_active = TRUE — partial
-- index for state reconciliation queries.
-- Used by: GetActiveBlocksForServer, GetAllActiveBlocks.
CREATE INDEX IF NOT EXISTS idx_blocks_server_active_expires
    ON blocks(server_id, is_active, expires_at)
    WHERE is_active = TRUE;

-- ============================================================================
-- 4. TABLE STORAGE TUNING
-- ============================================================================

-- traffic_events: heavy upserts (ON CONFLICT DO UPDATE). Lower fillfactor
-- reserves 20% free space per page for HOT (Heap-Only Tuple) updates,
-- dramatically reducing page splits.
ALTER TABLE traffic_events SET (fillfactor = 80);

-- traffic_timeline: also upsert-heavy with ON CONFLICT DO UPDATE.
ALTER TABLE traffic_timeline SET (fillfactor = 80);

-- blocks: moderate UPDATE activity on unblock and expiry refresh.
ALTER TABLE blocks SET (fillfactor = 85);

-- ============================================================================
-- 5. STATISTICS TARGETS
-- ============================================================================
-- Increase pg_statistic sample size for columns with high cardinality or
-- skewed distributions, so the planner picks better plans for mixed queries.

ALTER TABLE traffic_events ALTER COLUMN threat_level SET STATISTICS 500;
ALTER TABLE traffic_events ALTER COLUMN last_seen     SET STATISTICS 1000;
ALTER TABLE traffic_events ALTER COLUMN source_ip     SET STATISTICS 500;
ALTER TABLE blocks       ALTER COLUMN is_active       SET STATISTICS 100;
ALTER TABLE blocks       ALTER COLUMN user_id         SET STATISTICS 500;
ALTER TABLE blocks       ALTER COLUMN ip_address      SET STATISTICS 500;
