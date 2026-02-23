// Package remediation provides automatic threat blocking
package remediation

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/kerneleye/shared/scoring"
)

// AutoBlockerConfig configures automatic blocking behavior
type AutoBlockerConfig struct {
	Enabled              bool
	BlockThreshold       int           // Minimum score to trigger block (default: 80)
	BaseBlockDuration    time.Duration // Default: 1 hour
	MaxBlockDuration     time.Duration // Cap at 24 hours
	EscalationMultiplier float64       // Duration x2 for repeat offenders
	MaxBlockedIPs        int           // Prevent memory exhaustion

	// Safety
	NeverBlockRanges []string // CIDRs to never block

	// Rate limiting of blocks (prevent block storms)
	MaxBlocksPerMinute int
}

// DefaultAutoBlockerConfig returns sensible defaults
func DefaultAutoBlockerConfig() AutoBlockerConfig {
	return AutoBlockerConfig{
		Enabled:              false, // Disabled by default - opt-in
		BlockThreshold:       80,
		BaseBlockDuration:    1 * time.Hour,
		MaxBlockDuration:     24 * time.Hour,
		EscalationMultiplier: 2.0,
		MaxBlockedIPs:        10000,
		NeverBlockRanges: []string{
			"127.0.0.0/8",
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"169.254.0.0/16", // Link-local
			"::1/128",
			"fe80::/10",
			"fc00::/7", // IPv6 private
		},
		MaxBlocksPerMinute: 60,
	}
}

// BlockEvent tracks a block for history/escalation
type BlockEvent struct {
	IP        string
	FirstSeen time.Time
	Count     int
	Duration  time.Duration
	LastScore int
}

// AutoBlocker automatically blocks IPs based on threat scores
type AutoBlocker struct {
	config     AutoBlockerConfig
	scorer     *scoring.ThreatScorer
	remediator *IPSetRemediator

	// Block history for escalation
	history   map[string]*BlockEvent
	historyMu sync.RWMutex

	// Rate limiting
	blocksThisMinute int
	lastMinute       time.Time
	rateMu           sync.Mutex

	// Safelist parsed from config
	safelist []*net.IPNet

	// Callback for reporting to backend
	onBlock func(ip string, duration time.Duration, score int, reasons []string)
}

// NewAutoBlocker creates a new auto-blocker
func NewAutoBlocker(config AutoBlockerConfig, scorer *scoring.ThreatScorer, remediator *IPSetRemediator) (*AutoBlocker, error) {
	ab := &AutoBlocker{
		config:     config,
		scorer:     scorer,
		remediator: remediator,
		history:    make(map[string]*BlockEvent),
		lastMinute: time.Now(),
	}

	// Parse safelist CIDRs
	for _, cidr := range config.NeverBlockRanges {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid safelist CIDR %s: %w", cidr, err)
		}
		ab.safelist = append(ab.safelist, ipnet)
	}

	return ab, nil
}

// SetBlockCallback sets the callback for block events
func (ab *AutoBlocker) SetBlockCallback(cb func(ip string, duration time.Duration, score int, reasons []string)) {
	ab.onBlock = cb
}

// ProcessScore evaluates a threat score and blocks if necessary
func (ab *AutoBlocker) ProcessScore(ip string, score scoring.ThreatScore) error {
	if !ab.config.Enabled {
		return nil
	}

	// Check threshold
	if score.Score < ab.config.BlockThreshold {
		return nil
	}

	// Check confidence (don't block on low confidence)
	if score.Confidence < 0.8 {
		log.Printf("🤔 IP %s has high score (%d) but low confidence (%.2f), not blocking",
			ip, score.Score, score.Confidence)
		return nil
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP: %s", ip)
	}

	// Check safelist
	if ab.isSafeListed(parsedIP) {
		log.Printf("🛡️  IP %s is safelisted, not blocking", ip)
		return nil
	}

	// Check if already blocked
	if ab.remediator.IsBlocked(parsedIP) {
		return nil
	}

	// Check rate limit (blocks per minute)
	if !ab.checkRateLimit() {
		log.Printf("⏱️  Block rate limit hit, queuing %s for later", ip)
		return nil
	}

	// Calculate block duration with escalation
	duration := ab.calculateDuration(ip, score)

	// Execute block
	if err := ab.remediator.Block(parsedIP, duration); err != nil {
		return fmt.Errorf("block failed: %w", err)
	}

	// Record in history
	ab.recordBlock(ip, score, duration)

	// Report to backend
	if ab.onBlock != nil {
		ab.onBlock(ip, duration, score.Score, score.Reasons)
	}

	log.Printf("🚫 Auto-blocked %s for %v (score: %d, reasons: %v)",
		ip, duration, score.Score, score.Reasons)

	return nil
}

// calculateDuration determines block time with escalation
func (ab *AutoBlocker) calculateDuration(ip string, score scoring.ThreatScore) time.Duration {
	ab.historyMu.Lock()
	defer ab.historyMu.Unlock()

	event, exists := ab.history[ip]
	if !exists {
		// First offense - base duration
		duration := ab.config.BaseBlockDuration

		// Scale by score severity (100 score = 2x duration)
		if score.Score > 100 {
			multiplier := float64(score.Score) / 100.0
			duration = time.Duration(float64(duration) * multiplier)
		}

		return minDuration(duration, ab.config.MaxBlockDuration)
	}

	// Repeat offender - escalate
	multiplier := 1.0
	for i := 0; i < event.Count; i++ {
		multiplier *= ab.config.EscalationMultiplier
	}

	duration := time.Duration(float64(ab.config.BaseBlockDuration) * multiplier)
	return minDuration(duration, ab.config.MaxBlockDuration)
}

// recordBlock tracks the block for future escalation
func (ab *AutoBlocker) recordBlock(ip string, score scoring.ThreatScore, duration time.Duration) {
	ab.historyMu.Lock()
	defer ab.historyMu.Unlock()

	if event, exists := ab.history[ip]; exists {
		event.Count++
		event.Duration = duration
		event.LastScore = score.Score
	} else {
		ab.history[ip] = &BlockEvent{
			IP:        ip,
			FirstSeen: time.Now(),
			Count:     1,
			Duration:  duration,
			LastScore: score.Score,
		}
	}

	// Cleanup old history entries every 100 blocks (not on every call)
	if len(ab.history)%100 == 0 {
		ab.cleanupHistoryLocked()
	}
}

// StartCleanupLoop starts periodic cleanup of history
func (ab *AutoBlocker) StartCleanupLoop(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				ab.historyMu.Lock()
				ab.cleanupHistoryLocked()
				ab.historyMu.Unlock()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// cleanupHistoryLocked removes entries older than 30 days (assumes lock is held)
func (ab *AutoBlocker) cleanupHistoryLocked() {
	cutoff := time.Now().Add(-30 * 24 * time.Hour)
	for ip, event := range ab.history {
		if event.FirstSeen.Before(cutoff) {
			delete(ab.history, ip)
		}
	}
}

// checkRateLimit enforces max blocks per minute
func (ab *AutoBlocker) checkRateLimit() bool {
	ab.rateMu.Lock()
	defer ab.rateMu.Unlock()

	now := time.Now()
	if now.Sub(ab.lastMinute) > time.Minute {
		// New minute
		ab.blocksThisMinute = 0
		ab.lastMinute = now
	}

	if ab.blocksThisMinute >= ab.config.MaxBlocksPerMinute {
		return false
	}

	ab.blocksThisMinute++
	return true
}

// isSafeListed checks if IP is in safelist
func (ab *AutoBlocker) isSafeListed(ip net.IP) bool {
	for _, ipnet := range ab.safelist {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// Unblock manually unblocks an IP
func (ab *AutoBlocker) Unblock(ip string) error {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP: %s", ip)
	}

	if err := ab.remediator.Unblock(parsedIP); err != nil {
		return err
	}

	// Remove from history (reset escalation)
	ab.historyMu.Lock()
	delete(ab.history, ip)
	ab.historyMu.Unlock()

	log.Printf("✅ Manually unblocked %s", ip)
	return nil
}

// GetBlockedIPs returns list of currently blocked IPs
func (ab *AutoBlocker) GetBlockedIPs() []BlockEvent {
	ab.historyMu.RLock()
	defer ab.historyMu.RUnlock()

	result := make([]BlockEvent, 0, len(ab.history))
	for _, event := range ab.history {
		result = append(result, *event)
	}
	return result
}

// GetStats returns auto-blocker statistics
func (ab *AutoBlocker) GetStats() map[string]interface{} {
	ab.historyMu.RLock()
	defer ab.historyMu.RUnlock()

	repeatOffenders := 0
	for _, event := range ab.history {
		if event.Count > 1 {
			repeatOffenders++
		}
	}

	return map[string]interface{}{
		"total_unique_ips":  len(ab.history),
		"repeat_offenders":  repeatOffenders,
		"enabled":           ab.config.Enabled,
		"block_threshold":   ab.config.BlockThreshold,
		"base_duration_min": ab.config.BaseBlockDuration.Minutes(),
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
