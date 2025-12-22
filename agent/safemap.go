package main

import (
	"sync"
)

// SafeStats is a thread-safe map for IP statistics with RWMutex for better read performance
type SafeStats struct {
	mu    sync.RWMutex
	items map[string]*IPStats
}

// NewSafeStats creates a new SafeStats instance
func NewSafeStats() *SafeStats {
	return &SafeStats{
		items: make(map[string]*IPStats),
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
func (s *SafeStats) GetOrCreate(ip string, creator func() *IPStats) *IPStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	if stats, ok := s.items[ip]; ok {
		return stats
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
