package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kerneleye/shared/scoring"
)

const defaultHistoryDBPath = "/var/lib/kerneleye/history.db"
const fallbackHistoryDBPath = "/tmp/kerneleye/history.db"

type HistoryStoreConfig struct {
	BucketSize     time.Duration
	LookbackWindow time.Duration
	Retention      time.Duration
}

func DefaultHistoryStoreConfig() HistoryStoreConfig {
	return HistoryStoreConfig{
		BucketSize:     1 * time.Minute,
		LookbackWindow: 30 * time.Minute,
		Retention:      24 * time.Hour,
	}
}

type HistorySignals struct {
	MaxThreatScore   int
	MaxPortHits      int
	TotalConnections int
	BucketCount      int
}

type HistoryStore struct {
	db     *sql.DB
	mu     sync.Mutex
	config HistoryStoreConfig
	writes int
}

func NewHistoryStore(dbPath string, cfg HistoryStoreConfig) (*HistoryStore, error) {
	if cfg.BucketSize <= 0 || cfg.LookbackWindow <= 0 || cfg.Retention <= 0 {
		cfg = DefaultHistoryStoreConfig()
	}

	if dbPath != "" {
		return openHistoryStore(dbPath, cfg)
	}

	candidates := []string{defaultHistoryDBPath, fallbackHistoryDBPath}
	var lastErr error
	for i, path := range candidates {
		store, err := openHistoryStore(path, cfg)
		if err == nil {
			if i > 0 {
				Logger.Warnf("⚠️  Using fallback history DB path %s (default %s unavailable)", path, defaultHistoryDBPath)
			}
			return store, nil
		}
		lastErr = err
		Logger.Warnf("⚠️  History DB path %s unavailable: %v", path, err)
	}

	return nil, fmt.Errorf("all history DB paths failed: %w", lastErr)
}

func openHistoryStore(dbPath string, cfg HistoryStoreConfig) (*HistoryStore, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL")
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS ip_metric_buckets (
			ip TEXT NOT NULL,
			direction INTEGER NOT NULL,
			bucket_start INTEGER NOT NULL,
			syn_count INTEGER NOT NULL DEFAULT 0,
			ack_count INTEGER NOT NULL DEFAULT 0,
			failed_handshakes INTEGER NOT NULL DEFAULT 0,
			unique_ports INTEGER NOT NULL DEFAULT 0,
			max_port_hits INTEGER NOT NULL DEFAULT 0,
			bytes_in INTEGER NOT NULL DEFAULT 0,
			bytes_out INTEGER NOT NULL DEFAULT 0,
			primary_port INTEGER NOT NULL DEFAULT 0,
			protocol INTEGER NOT NULL DEFAULT 0,
			process_name TEXT NOT NULL DEFAULT '',
			threat_score INTEGER NOT NULL DEFAULT 0,
			last_seen INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (ip, direction, bucket_start)
		);
		CREATE INDEX IF NOT EXISTS idx_ip_metric_buckets_ip_window
			ON ip_metric_buckets(ip, direction, bucket_start);
	`)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	// Migrate existing databases that pre-date added columns.
	// Ignore errors — SQLite returns "duplicate column name" if the column already exists.
	_, _ = db.Exec(`ALTER TABLE ip_metric_buckets ADD COLUMN protocol INTEGER NOT NULL DEFAULT 0`)
	_, _ = db.Exec(`ALTER TABLE ip_metric_buckets ADD COLUMN process_name TEXT NOT NULL DEFAULT ''`)

	return &HistoryStore{
		db:     db,
		config: cfg,
	}, nil
}

func (h *HistoryStore) LoadSignals(ip string, direction uint8, now time.Time) (HistorySignals, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	currentBucket := now.UTC().Truncate(h.config.BucketSize).Unix()
	sinceBucket := now.UTC().Add(-h.config.LookbackWindow).Truncate(h.config.BucketSize).Unix()

	var signals HistorySignals
	err := h.db.QueryRow(`
		SELECT
			COALESCE(MAX(threat_score), 0),
			COALESCE(MAX(max_port_hits), 0),
			COALESCE(SUM(syn_count + ack_count), 0),
			COUNT(*)
		FROM ip_metric_buckets
		WHERE ip = ?
		  AND direction = ?
		  AND bucket_start >= ?
		  AND bucket_start < ?
	`, ip, int(direction), sinceBucket, currentBucket).Scan(
		&signals.MaxThreatScore,
		&signals.MaxPortHits,
		&signals.TotalConnections,
		&signals.BucketCount,
	)

	return signals, err
}

func (h *HistoryStore) PersistBucket(ip string, direction uint8, protocol uint8, processName string, metrics scoring.IPMetrics, score scoring.ThreatScore, now time.Time) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	bucketStart := now.UTC().Truncate(h.config.BucketSize).Unix()
	lastSeen := now.UTC().Unix()
	_, err := h.db.Exec(`
		INSERT INTO ip_metric_buckets (
			ip, direction, bucket_start,
			syn_count, ack_count, failed_handshakes, unique_ports,
			max_port_hits, bytes_in, bytes_out, primary_port, protocol, process_name, threat_score, last_seen
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip, direction, bucket_start) DO UPDATE SET
			syn_count = ip_metric_buckets.syn_count + excluded.syn_count,
			ack_count = ip_metric_buckets.ack_count + excluded.ack_count,
			failed_handshakes = ip_metric_buckets.failed_handshakes + excluded.failed_handshakes,
			unique_ports = MAX(ip_metric_buckets.unique_ports, excluded.unique_ports),
			max_port_hits = MAX(ip_metric_buckets.max_port_hits, excluded.max_port_hits),
			bytes_in = ip_metric_buckets.bytes_in + excluded.bytes_in,
			bytes_out = ip_metric_buckets.bytes_out + excluded.bytes_out,
			primary_port = CASE
				WHEN excluded.max_port_hits >= ip_metric_buckets.max_port_hits THEN excluded.primary_port
				ELSE ip_metric_buckets.primary_port
			END,
			protocol = CASE
				WHEN excluded.protocol != 0 THEN excluded.protocol
				ELSE ip_metric_buckets.protocol
			END,
			process_name = CASE
				WHEN excluded.process_name != '' THEN excluded.process_name
				ELSE ip_metric_buckets.process_name
			END,
			threat_score = MAX(ip_metric_buckets.threat_score, excluded.threat_score),
			last_seen = MAX(ip_metric_buckets.last_seen, excluded.last_seen)
	`, ip, int(direction), bucketStart,
		metrics.SYNCount, metrics.ACKCount, metrics.FailedHandshakes, metrics.UniquePorts,
		metrics.MaxPortHits, int64(metrics.BytesIn), int64(metrics.BytesOut), metrics.PrimaryPort, int(protocol), processName, score.Score, lastSeen)
	if err != nil {
		return err
	}

	h.writes++
	if h.writes%120 == 0 {
		cutoff := now.UTC().Add(-h.config.Retention).Unix()
		if _, err := h.db.Exec(`DELETE FROM ip_metric_buckets WHERE bucket_start < ?`, cutoff); err != nil {
			Logger.Warnf("⚠️  History DB cleanup failed: %v", err)
		}
	}
	return nil
}

// GetContext returns the most-recently-seen primary_port, protocol, and process_name for an IP.
// port and protocol will be zero / 0 if no history is found.
func (h *HistoryStore) GetContext(ip string, direction uint8, now time.Time) (primaryPort uint16, protocol uint8, processName string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	sinceBucket := now.UTC().Add(-h.config.LookbackWindow).Truncate(h.config.BucketSize).Unix()

	// Pick the bucket with the highest max_port_hits within the lookback window.
	// Prefer stored protocol/process_name; fall back to TCP inference from syn_count
	// for rows written before the protocol column existed (value will be 0).
	var port, proto, totalSyn int
	var procName string
	err := h.db.QueryRow(`
		SELECT
			COALESCE((
				SELECT primary_port FROM ip_metric_buckets
				WHERE ip = ? AND direction = ? AND bucket_start >= ? AND primary_port > 0
				ORDER BY max_port_hits DESC, last_seen DESC LIMIT 1
			), 0),
			COALESCE((
				SELECT protocol FROM ip_metric_buckets
				WHERE ip = ? AND direction = ? AND bucket_start >= ? AND primary_port > 0
				ORDER BY max_port_hits DESC, last_seen DESC LIMIT 1
			), 0),
			COALESCE((
				SELECT process_name FROM ip_metric_buckets
				WHERE ip = ? AND direction = ? AND bucket_start >= ? AND process_name != ''
				ORDER BY last_seen DESC LIMIT 1
			), ''),
			COALESCE((
				SELECT SUM(syn_count) FROM ip_metric_buckets
				WHERE ip = ? AND direction = ? AND bucket_start >= ?
			), 0)
	`, ip, int(direction), sinceBucket,
		ip, int(direction), sinceBucket,
		ip, int(direction), sinceBucket,
		ip, int(direction), sinceBucket).Scan(&port, &proto, &procName, &totalSyn)
	if err != nil || port == 0 {
		// Fall back to all-time most recent entry for this IP
		_ = h.db.QueryRow(`
			SELECT COALESCE(primary_port, 0), COALESCE(protocol, 0),
			       COALESCE(process_name, ''), COALESCE(syn_count, 0)
			FROM ip_metric_buckets
			WHERE ip = ? AND direction = ? AND primary_port > 0
			ORDER BY last_seen DESC
			LIMIT 1
		`, ip, int(direction)).Scan(&port, &proto, &procName, &totalSyn)
	}
	if port > 0 {
		primaryPort = uint16(port)
		processName = procName
		if proto != 0 {
			protocol = uint8(proto)
		} else if totalSyn > 0 {
			protocol = 6 // TCP (legacy rows written before protocol column)
		}
	}
	return
}

func (h *HistoryStore) Close() error {
	return h.db.Close()
}
