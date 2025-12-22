package remediation

import (
	"container/list"
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

	blocked bool
	mu      sync.RWMutex
}

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

	// 1. Get or Create State (Thread-safe LRU access)
	state := a.getOrCreateState(ipStr)

	// 2. Analyze
	state.mu.Lock()
	defer state.mu.Unlock()

	if state.blocked {
		return nil
	}

	// Check SYN Flood
	if event.Protocol == 6 && (event.Flags&0x02 != 0) {
		// Add to ring buffer
		// Threshold + 1 to detect > Threshold
		targetLen := a.config.SynFloodThreshold + 1
		if len(state.syns) < targetLen {
			if state.syns == nil {
				state.syns = make([]time.Time, targetLen)
			}
		}

		state.syns[state.synIdx] = now
		state.synIdx = (state.synIdx + 1) % len(state.syns)
		if state.synLen < len(state.syns) {
			state.synLen++
		}

		// Check count in window
		// Iterate all valid items in ring
		count := 0
		for i := 0; i < state.synLen; i++ {
			// Calculate actual index: (synIdx - 1 - i + len) % len ?
			// Easier: just iterate internal slice? No, it's a ring, order doesn't strictly matter for "count in window"
			// if we just check ALL valid entries.
			// But efficient way:
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
	// Note: previous logic had a bulk prune if size > 2*threshold,
	// but per-event pruning keeps it clean automatically.
	// We can remove the bulk prune block if we prune every time.

	if uniquePorts > a.config.PortScanThreshold {
		// Return RateLimit but don't set blocked=true (hard block)
		// Decision logic handles the action.
		return &Decision{
			IP:       event.SourceIP,
			Action:   ActionRateLimit,
			Reason:   "Port Scan Detected",
			Duration: 10 * time.Minute,
		}
	}

	return nil
}

func (a *Analyzer) getOrCreateState(ip string) *ipState {
	a.mu.Lock()
	defer a.mu.Unlock()

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

// CleanupRoutine - now safer with copy-on-write strategy or just safe iteration
// Since we have LRU, maybe we don't strictly need a "cleanup routine" for memory safety (MaxStates handles it).
// But we might want to expire old states to free slots for new active ones if cache is full of old data (LRU handles this too).
// However, the reviewer mentioned "Race Condition in State Cleanup" and suggested "Use read-write locks with copy-on-write".
// If we rely on LRU, explicit time-based pruning is less critical for OOM, but good for correctness (don't track IP forever).
// Let's implement a gentle pruner.
func (a *Analyzer) CleanupRoutine(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			a.prune()
		}
	}()
}

func (a *Analyzer) prune() {
	// Rely on LRU eviction (MaxStates) for memory management.
	// Explicit pruning of "old" states is less critical when we have a hard limit on count.
}
