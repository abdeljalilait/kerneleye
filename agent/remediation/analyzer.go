package remediation

import (
	"container/list"
	"context"
	"log"
	"sync"
	"time"
)

// AnalyzerConfig holds configuration for the TrafficAnalyzer
type AnalyzerConfig struct {
	SynFloodThreshold int
	SynFloodWindow    time.Duration
	PortScanThreshold int
	PortScanWindow    time.Duration
	MaxStates         int
}

// DefaultAnalyzerConfig returns standard defaults
func DefaultAnalyzerConfig() AnalyzerConfig {
	return AnalyzerConfig{
		SynFloodThreshold: 20,
		SynFloodWindow:    60 * time.Second,
		PortScanThreshold: 10,
		PortScanWindow:    30 * time.Second,
		MaxStates:         10000,
	}
}

type ipState struct {
	ip     string
	syns   []time.Time // Fixed-size ring buffer
	synIdx int         // Next insertion index
	synLen int         // Current number of items (up to cap)

	ports map[uint16]time.Time

	blocked     bool
	rateLimited bool      // Prevents port scan re-triggering
	lastLimited time.Time // When rate limit was applied (for expiration)

	mu sync.RWMutex
}

// getLastActivity returns the most recent timestamp from syns or ports
func (s *ipState) getLastActivity(_ time.Time) time.Time {
	latest := time.Time{}

	// Check SYN entries
	for i := 0; i < s.synLen; i++ {
		if t := s.syns[i]; !t.IsZero() && t.After(latest) {
			latest = t
		}
	}

	// Check port entries
	for _, t := range s.ports {
		if t.After(latest) {
			latest = t
		}
	}

	// If no activity found, return zero time (will be evicted)
	return latest
}

// Analyzer evaluates traffic events and returns remediation decisions.
//
// Lock ordering: always acquire a.mu before any ipState.mu.
// Never hold ipState.mu while acquiring a.mu — this would invert the
// ordering and risk deadlock.
type Analyzer struct {
	config AnalyzerConfig

	// LRU Cache implementation
	states map[string]*list.Element // Maps IP string to list element containing *ipState
	lru    *list.List               // Doubly linked list for LRU eviction

	mu sync.RWMutex
}

func NewAnalyzer(cfg AnalyzerConfig) *Analyzer {
	// Apply defaults if zero values
	if cfg.SynFloodThreshold == 0 {
		cfg = DefaultAnalyzerConfig()
	}

	return &Analyzer{
		config: cfg,
		states: make(map[string]*list.Element),
		lru:    list.New(),
	}
}

func (a *Analyzer) Evaluate(event TrafficEvent) *Decision {
	ipStr := event.SourceIP.String()
	now := event.Time

	// Acquire a.mu FIRST to ensure consistent lock ordering (a.mu before state.mu)
	// This prevents deadlock with prune() which holds a.mu then acquires state.mu
	a.mu.Lock()

	// Get or create state while holding a.mu
	state := a.getOrCreateStateLocked(ipStr)

	// Now acquire state.mu - we hold a.mu so lock ordering is consistent
	state.mu.Lock()
	defer state.mu.Unlock()
	defer a.mu.Unlock() // Release a.mu after state.mu is released

	if state.blocked {
		// IP already blocked, skip processing silently
		return nil
	}

	// Check SYN Flood
	if event.Protocol == 6 && (event.Flags&0x02 != 0) {
		// Add to ring buffer (pre-allocated in getOrCreateState to SynFloodThreshold+1)
		state.syns[state.synIdx] = now
		state.synIdx = (state.synIdx + 1) % len(state.syns)
		if state.synLen < len(state.syns) {
			state.synLen++
		}

		// Check count in window
		// Iterate all valid items in ring (index order doesn't matter for counting)
		count := 0
		for i := 0; i < state.synLen; i++ {
			t := state.syns[i]
			if t.IsZero() {
				continue
			}
			age := now.Sub(t)
			if age >= 0 && age < a.config.SynFloodWindow {
				count++
			}
		}

		if count > a.config.SynFloodThreshold {
			state.blocked = true
			log.Printf("🚨 Analyzer: SYN Flood detected from %s (%d SYNs in %v window) - BLOCKING",
				ipStr, count, a.config.SynFloodWindow)
			return &Decision{
				IP:       event.SourceIP,
				Action:   ActionBlock,
				Reason:   "SYN Flood Detected",
				Duration: 1 * time.Hour,
			}
		}
	}

	// Check Port Scan
	// Map access
	state.ports[event.DestPort] = now

	// Per-event pruning: Remove expired entries while counting
	uniquePorts := 0
	for p, t := range state.ports {
		age := now.Sub(t)
		if age < 0 || age >= a.config.PortScanWindow {
			delete(state.ports, p)
		} else {
			uniquePorts++
		}
	}

	// Double-check threshold with clean map

	if uniquePorts > a.config.PortScanThreshold {
		// RateLimit but don't hard block
		// Set rateLimited to prevent re-triggering on every packet
		if !state.rateLimited {
			state.rateLimited = true
			state.lastLimited = now
			log.Printf("⚠️  Analyzer: Port scan detected from %s (%d unique ports in %v window) - RATE LIMITING",
				ipStr, uniquePorts, a.config.PortScanWindow)
			return &Decision{
				IP:       event.SourceIP,
				Action:   ActionRateLimit,
				Reason:   "Port Scan Detected",
				Duration: 10 * time.Minute,
			}
		}
		// Already rate limited, skip generating duplicate decisions
		return nil
	}

	return nil
}

// getOrCreateStateLocked assumes a.mu is already held by the caller.
// This enables proper lock ordering when called from Evaluate.
func (a *Analyzer) getOrCreateStateLocked(ip string) *ipState {
	// Check exist
	if elem, ok := a.states[ip]; ok {
		a.lru.MoveToFront(elem)
		return elem.Value.(*ipState)
	}

	// Create new
	// Check capacity
	if a.lru.Len() >= a.config.MaxStates {
		// Evict LRU
		ent := a.lru.Back()
		if ent != nil {
			a.lru.Remove(ent)
			victim := ent.Value.(*ipState)
			delete(a.states, victim.ip)
			log.Printf("🗑️  Analyzer: Evicted LRU state for IP %s (capacity: %d)", victim.ip, a.config.MaxStates)
		}
	}

	newState := &ipState{
		ip:    ip,
		syns:  make([]time.Time, a.config.SynFloodThreshold+1),
		ports: make(map[uint16]time.Time),
	}
	elem := a.lru.PushFront(newState)
	a.states[ip] = elem
	return newState
}

// CleanupRoutine starts a background goroutine that periodically prunes stale IP states.
// The goroutine can be stopped by canceling the provided context.
func (a *Analyzer) CleanupRoutine(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				a.prune()
			case <-ctx.Done():
				log.Println("Analyzer: cleanup routine stopped")
				return
			}
		}
	}()
}

// prune removes IP states that have been inactive for longer than the eviction age.
// This frees up slots in the LRU cache for new active IPs.
func (a *Analyzer) prune() {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	evictionAge := 10 * time.Minute

	// Iterate from back (LRU) to front
	for elem := a.lru.Back(); elem != nil; {
		prev := elem.Prev()
		state := elem.Value.(*ipState)

		state.mu.RLock()
		lastActivity := state.getLastActivity(now)
		blocked := state.blocked
		rateLimited := state.rateLimited
		lastLimited := state.lastLimited
		state.mu.RUnlock()

		// Determine if state should be evicted
		shouldEvict := false

		// Evict if inactive for too long
		if !lastActivity.IsZero() && now.Sub(lastActivity) > evictionAge {
			shouldEvict = true
		}

		// Evict rate-limited entries after their duration expires
		if rateLimited && now.Sub(lastLimited) > 10*time.Minute {
			shouldEvict = true
		}

		// Note: Blocked entries are kept longer (1 hour block duration)
		if blocked && now.Sub(lastActivity) > time.Hour {
			shouldEvict = true
		}

		if shouldEvict {
			a.lru.Remove(elem)
			delete(a.states, state.ip)
			log.Printf("🗑️  Analyzer: Pruned stale state for IP %s (inactive for %v)",
				state.ip, now.Sub(lastActivity))
		}
		// Note: we do NOT break early here. Blocked/rate-limited entries
		// disrupt strict LRU ordering, so we must scan the entire list.
		// With a 10k max capacity, a full scan every 5 minutes is negligible.

		elem = prev
	}
}
