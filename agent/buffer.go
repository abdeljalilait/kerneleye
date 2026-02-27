package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	pb "github.com/kerneleye/proto/kerneleye/v1"
	"google.golang.org/protobuf/proto"
	_ "modernc.org/sqlite"
)

const defaultDBPath = "/var/lib/kerneleye/pending.db"
const fallbackDBPath = "/tmp/kerneleye/pending.db"

// Buffer limits. These prevent unbounded SQLite growth during extended backend outages.
const (
	// BufferMaxBatches is the maximum number of pending batches to retain.
	// When exceeded, the oldest batches are FIFO-evicted before the new one is written.
	BufferMaxBatches = 500
	// DefaultBufferTTL is the maximum age of a buffered batch before it is expired
	// by the periodic maintenance goroutine (runBufferMaintenance in aggregator.go).
	DefaultBufferTTL = 24 * time.Hour
)

// BufferDB handles SQLite-based storage for pending events
type BufferDB struct {
	db *sql.DB
	mu sync.Mutex
}

// NewBufferDB creates a new buffer database
func NewBufferDB(dbPath string) (*BufferDB, error) {
	// If caller provides explicit path, only try that path.
	if dbPath != "" {
		return openBufferDB(dbPath)
	}

	// Auto mode: prefer persistent system path, then fallback to /tmp if not writable.
	candidates := []string{defaultDBPath, fallbackDBPath}
	var lastErr error
	for i, path := range candidates {
		buf, err := openBufferDB(path)
		if err == nil {
			if i > 0 {
				Logger.Warnf("⚠️  Using fallback buffer DB path %s (default %s unavailable)", path, defaultDBPath)
			}
			return buf, nil
		}
		lastErr = err
		Logger.Warnf("⚠️  Buffer DB path %s unavailable: %v", path, err)
	}

	return nil, fmt.Errorf("all buffer DB paths failed: %w", lastErr)
}

func openBufferDB(dbPath string) (*BufferDB, error) {
	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL")
	if err != nil {
		return nil, err
	}

	// Create table if not exists
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS pending_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			data BLOB NOT NULL,
			api_key TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_created_at ON pending_events(created_at);
	`)
	if err != nil {
		db.Close()
		return nil, err
	}

	// Verify that DB is writable now (catches readonly mounts / strict systemd paths early).
	tx, err := db.Begin()
	if err != nil {
		db.Close()
		return nil, err
	}
	if _, err := tx.Exec("INSERT INTO pending_events (data, api_key) VALUES (?, ?)", []byte{0x00}, "__rw_test__"); err != nil {
		_ = tx.Rollback()
		db.Close()
		return nil, fmt.Errorf("db not writable: %w", err)
	}
	if err := tx.Rollback(); err != nil {
		db.Close()
		return nil, err
	}

	return &BufferDB{db: db}, nil
}

// Save stores a batch of events to the SQLite buffer.
// It enforces BufferMaxBatches by FIFO-evicting the oldest rows when at capacity.
// On disk-full or other write errors the error is returned so the caller can
// preserve in-memory state rather than silently losing events.
func (b *BufferDB) Save(apiKey string, events []*pb.ConnectionEvent) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	batch := &pb.TrafficBatch{
		ApiKey: apiKey,
		Events: events,
	}

	data, err := proto.Marshal(batch)
	if err != nil {
		return fmt.Errorf("proto marshal: %w", err)
	}

	// Enforce capacity cap: count rows without acquiring a second lock (already held).
	var count int
	if err := b.db.QueryRow("SELECT COUNT(*) FROM pending_events").Scan(&count); err != nil {
		Logger.Warnf("⚠️  Buffer: could not count rows: %v", err)
	} else if count >= BufferMaxBatches {
		// Evict the oldest (count - BufferMaxBatches + 1) rows to make room.
		evictN := count - BufferMaxBatches + 1
		_, evictErr := b.db.Exec(
			`DELETE FROM pending_events WHERE id IN
			 (SELECT id FROM pending_events ORDER BY created_at ASC LIMIT ?)`,
			evictN,
		)
		if evictErr != nil {
			Logger.Warnf("⚠️  Buffer: FIFO eviction of %d rows failed: %v", evictN, evictErr)
		} else {
			Logger.Warnf("⚠️  Buffer at capacity (%d/%d): evicted %d oldest batches",
				count, BufferMaxBatches, evictN)
		}
	}

	if _, err = b.db.Exec(
		"INSERT INTO pending_events (data, api_key) VALUES (?, ?)", data, apiKey,
	); err != nil {
		// Distinguish disk-full from other errors for clearer operator messaging.
		errStr := err.Error()
		if isDiskFullError(errStr) {
			return fmt.Errorf("buffer write failed (disk full): %w", err)
		}
		return fmt.Errorf("buffer write failed: %w", err)
	}

	return nil
}

// isDiskFullError returns true for SQLite disk-full and readonly-filesystem errors.
func isDiskFullError(errMsg string) bool {
	// SQLite error codes embedded in error strings by the modernc.org/sqlite driver.
	return containsAny(errMsg, "disk", "SQLITE_FULL", "readonly", "read-only", "no space")
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 {
			// Simple substring check without importing strings at package level —
			// strings is already imported by other files in the package.
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

// PendingBatch represents a batch loaded from storage
type PendingBatch struct {
	ID    int64
	Batch *pb.TrafficBatch
	Age   time.Duration
}

// LoadAll retrieves all pending batches
func (b *BufferDB) LoadAll() ([]PendingBatch, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	rows, err := b.db.Query(`
		SELECT id, data, created_at FROM pending_events 
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var batches []PendingBatch
	for rows.Next() {
		var id int64
		var data []byte
		var createdAt time.Time

		if err := rows.Scan(&id, &data, &createdAt); err != nil {
			continue
		}

		batch := &pb.TrafficBatch{}
		if err := proto.Unmarshal(data, batch); err != nil {
			continue
		}

		batches = append(batches, PendingBatch{
			ID:    id,
			Batch: batch,
			Age:   time.Since(createdAt),
		})
	}

	return batches, nil
}

// Delete removes successfully sent batches by ID
func (b *BufferDB) Delete(ids []int64) error {
	if len(ids) == 0 {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	tx, err := b.db.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare("DELETE FROM pending_events WHERE id = ?")
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()

	for _, id := range ids {
		if _, err := stmt.Exec(id); err != nil {
			_ = tx.Rollback()
			return err
		}
	}

	return tx.Commit()
}

// EvictExpired removes buffered batches older than maxAge.
// Called by runBufferMaintenance in aggregator.go on a 1-hour interval.
func (b *BufferDB) EvictExpired(maxAge time.Duration) (int64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	result, err := b.db.Exec("DELETE FROM pending_events WHERE created_at < ?", cutoff)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// Cleanup is a back-compat alias for EvictExpired.
func (b *BufferDB) Cleanup(maxAge time.Duration) (int64, error) {
	return b.EvictExpired(maxAge)
}

// Count returns the number of pending batches (acquires lock).
func (b *BufferDB) Count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.countUnsafe()
}

// countUnsafe returns the row count without acquiring the mutex.
// Must be called with b.mu held.
func (b *BufferDB) countUnsafe() int {
	var count int
	_ = b.db.QueryRow("SELECT COUNT(*) FROM pending_events").Scan(&count)
	return count
}

// Close closes the database connection
func (b *BufferDB) Close() error {
	return b.db.Close()
}
