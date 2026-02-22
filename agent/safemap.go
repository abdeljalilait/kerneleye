package main

import (
	"log"
	"sync"
	"time"
)

const DefaultMaxStatsItems = 50000 // Max unique IPs to track before dropping oldest

// SafeStats is a thread-safe map for IP statistics with RWMutex for better read performance
type SafeStats struct {
	mu       sync.RWMutex
	items    map[string]*IPStats
	maxItems int
}

// IPStatsSnapshot is an immutable copy of IP statistics used during flush.
type IPStatsSnapshot struct {
	Protocol         uint8
	SYNCount         int
	ACKCount         int
	FailedHandshakes int
	UniquePorts      map[uint16]bool
	PortCounts       map[uint16]int
	BytesIn          uint64
	BytesOut         uint64
	Direction        uint8
	LocalIP          string
	FirstSeen        time.Time
	LastSeen         time.Time
}

// NewSafeStats creates a new SafeStats instance with default max items
func NewSafeStats() *SafeStats {
	return &SafeStats{
		items:    make(map[string]*IPStats),
		maxItems: DefaultMaxStatsItems,
	}
}

// Get retrieves stats for an IP (read lock)
func (s *SafeStats) Get(ip string) (*IPStats, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.items[ip]
	return v, ok
}

// Set stores stats for an IP (write lock)
func (s *SafeStats) Set(ip string, stats *IPStats) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[ip] = stats
}

// GetOrCreate returns existing stats or creates new ones atomically
// Enforces maxItems limit by evicting oldest entry if at capacity
func (s *SafeStats) GetOrCreate(ip string, creator func() *IPStats) *IPStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	if stats, ok := s.items[ip]; ok {
		return stats
	}

	// Enforce capacity limit
	if len(s.items) >= s.maxItems {
		// Find and evict oldest entry (simple O(n) eviction)
		var oldestIP string
		var oldestTime = time.Now()
		for k, v := range s.items {
			if v.FirstSeen.Before(oldestTime) {
				oldestTime = v.FirstSeen
				oldestIP = k
			}
		}
		if oldestIP != "" {
			delete(s.items, oldestIP)
			log.Printf("🗑️  SafeStats: Evicted oldest IP %s (at capacity: %d)", oldestIP, s.maxItems)
		}
	}

	stats := creator()
	s.items[ip] = stats
	return stats
}

// Len returns the number of entries (read lock)
func (s *SafeStats) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.items)
}

// Clear removes all entries and returns true if there were any
func (s *SafeStats) Clear() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	had := len(s.items) > 0
	s.items = make(map[string]*IPStats)
	return had
}

// ForEach iterates over all entries with read lock held
// The callback should not modify the map
func (s *SafeStats) ForEach(fn func(ip string, stats *IPStats)) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for ip, stats := range s.items {
		fn(ip, stats)
	}
}

// ForEachMutable iterates with write lock for mutations
func (s *SafeStats) ForEachMutable(fn func(ip string, stats *IPStats)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ip, stats := range s.items {
		fn(ip, stats)
	}
}

// Snapshot returns a copy of all entries (for safe iteration outside lock)
func (s *SafeStats) Snapshot() map[string]*IPStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	copy := make(map[string]*IPStats, len(s.items))
	for k, v := range s.items {
		copy[k] = v
	}
	return copy
}

// SnapshotDeep returns a deep, immutable copy safe for concurrent iteration.
func (s *SafeStats) SnapshotDeep() map[string]IPStatsSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make(map[string]IPStatsSnapshot, len(s.items))
	for ip, stats := range s.items {
		stats.mu.Lock()

		uniquePorts := make(map[uint16]bool, len(stats.UniquePorts))
		for p, seen := range stats.UniquePorts {
			uniquePorts[p] = seen
		}

		portCounts := make(map[uint16]int, len(stats.PortCounts))
		for p, count := range stats.PortCounts {
			portCounts[p] = count
		}

		out[ip] = IPStatsSnapshot{
			Protocol:         stats.Protocol,
			SYNCount:         stats.SYNCount,
			ACKCount:         stats.ACKCount,
			FailedHandshakes: stats.FailedHandshakes,
			UniquePorts:      uniquePorts,
			PortCounts:       portCounts,
			BytesIn:          stats.BytesIn,
			BytesOut:         stats.BytesOut,
			Direction:        stats.Direction,
			LocalIP:          stats.LocalIP,
			FirstSeen:        stats.FirstSeen,
			LastSeen:         stats.LastSeen,
		}

		stats.mu.Unlock()
	}

	return out
}
