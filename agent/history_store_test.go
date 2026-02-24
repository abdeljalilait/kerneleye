package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/kerneleye/shared/scoring"
)

func TestHistoryStorePersistAndLoadSignals(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "history.db")

	store, err := NewHistoryStore(dbPath, HistoryStoreConfig{
		BucketSize:     1 * time.Minute,
		LookbackWindow: 30 * time.Minute,
		Retention:      24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewHistoryStore failed: %v", err)
	}
	defer store.Close()

	base := time.Unix(1700000000, 0).UTC()
	ip := "203.0.113.10"

	err = store.PersistBucket(ip, DirInbound, scoring.IPMetrics{
		SYNCount:         5,
		ACKCount:         4,
		FailedHandshakes: 1,
		UniquePorts:      1,
		MaxPortHits:      5,
		PrimaryPort:      22,
		BytesIn:          1024,
		BytesOut:         256,
	}, scoring.ThreatScore{Score: 15}, base.Add(10*time.Second))
	if err != nil {
		t.Fatalf("first PersistBucket failed: %v", err)
	}

	err = store.PersistBucket(ip, DirInbound, scoring.IPMetrics{
		SYNCount:         6,
		ACKCount:         6,
		FailedHandshakes: 0,
		UniquePorts:      1,
		MaxPortHits:      6,
		PrimaryPort:      22,
		BytesIn:          2048,
		BytesOut:         512,
	}, scoring.ThreatScore{Score: 23}, base.Add(20*time.Second))
	if err != nil {
		t.Fatalf("second PersistBucket failed: %v", err)
	}

	signals, err := store.LoadSignals(ip, DirInbound, base.Add(70*time.Second))
	if err != nil {
		t.Fatalf("LoadSignals failed: %v", err)
	}

	if signals.BucketCount != 1 {
		t.Fatalf("BucketCount=%d, want 1", signals.BucketCount)
	}
	if signals.MaxThreatScore != 23 {
		t.Fatalf("MaxThreatScore=%d, want 23", signals.MaxThreatScore)
	}
	if signals.MaxPortHits != 6 {
		t.Fatalf("MaxPortHits=%d, want 6", signals.MaxPortHits)
	}
	if signals.TotalConnections != 21 {
		t.Fatalf("TotalConnections=%d, want 21", signals.TotalConnections)
	}
}
