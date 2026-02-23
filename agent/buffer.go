package main

import (
	"database/sql"
	"fmt"
	"log"
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
				log.Printf("⚠️  Using fallback buffer DB path %s (default %s unavailable)", path, defaultDBPath)
			}
			return buf, nil
		}
		lastErr = err
		log.Printf("⚠️  Buffer DB path %s unavailable: %v", path, err)
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

// Save stores a batch of events to the buffer
func (b *BufferDB) Save(apiKey string, events []*pb.ConnectionEvent) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	batch := &pb.TrafficBatch{
		ApiKey: apiKey,
		Events: events,
	}

	data, err := proto.Marshal(batch)
	if err != nil {
		return err
	}

	_, err = b.db.Exec("INSERT INTO pending_events (data, api_key) VALUES (?, ?)", data, apiKey)
	if err != nil {
		return err
	}

	log.Printf("📦 Buffered %d events to SQLite", len(events))
	return nil
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

// Cleanup removes entries older than maxAge
func (b *BufferDB) Cleanup(maxAge time.Duration) (int64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	result, err := b.db.Exec("DELETE FROM pending_events WHERE created_at < ?", cutoff)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}

// Count returns the number of pending batches
func (b *BufferDB) Count() int {
	b.mu.Lock()
	defer b.mu.Unlock()

	var count int
	b.db.QueryRow("SELECT COUNT(*) FROM pending_events").Scan(&count)
	return count
}

// Close closes the database connection
func (b *BufferDB) Close() error {
	return b.db.Close()
}
