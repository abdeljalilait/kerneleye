package remediation

import (
	"fmt"
	"net"
	"time"
)

// XDP rate limiting configuration.
// SetRateLimit configures global PPS/BPS limits on the xdp_rate_config map
// and freezes it after the first write (immutable thereafter).

func (r *XDPRemediator) SetRateLimit(maxPPS, maxBPS uint64, blockDuration time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.attached {
		return errNotAttached
	}
	if r.objs.XdpRateConfig == nil {
		return errRLDisabled
	}

	// Check if map is already frozen (irreversible)
	if info, err := r.objs.XdpRateConfig.Info(); err == nil && info != nil {
		if info.Frozen() {
			logger.Warn("xdp_rate_config is frozen — rate limit cannot be changed without restart")
			return nil
		}
	}

	cfg := rateLimitConfig{maxPPS, maxBPS, uint64(blockDuration.Nanoseconds())}
	if err := r.objs.XdpRateConfig.Put(uint32(0), cfg); err != nil {
		return fmt.Errorf("set rate limit: %w", err)
	}

	// Freeze the map — irreversible, prevents future userspace writes
	if err := r.objs.XdpRateConfig.Freeze(); err != nil {
		logger.Warnf("Failed to freeze xdp_rate_config (kernel may not support BPF_MAP_FREEZE): %v", err)
	} else {
		logger.Infof("🔒 Frozen xdp_rate_config — rate limit config is now immutable")
		if r.mapSnapshots != nil {
			if snap, ok := r.mapSnapshots["xdp_rate_config"]; ok {
				snap.Frozen = true
			}
		}
	}
	auditMapWrite("xdp_rate_config", "update", "rate_config", "local_setup", true)

	// Clear existing state (holding mutex prevents races with Block/Unblock)
	if r.objs.XdpRateLimit != nil {
		r.clearRateLimitState()
	}
	logger.Infof("⚡ XDP rate limit: %d PPS, %d BPS", maxPPS, maxBPS)
	return nil
}

func (r *XDPRemediator) clearRateLimitState() {
	if r.objs.XdpRateLimit == nil {
		return
	}
	var key uint32
	var val rateLimitState // Use correct value type instead of empty struct
	iter := r.objs.XdpRateLimit.Iterate()
	keys := make([]uint32, 0, 1000)
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		r.objs.XdpRateLimit.Delete(k)
	}
}

// RateLimit per-IP - not supported, use iptables
func (r *XDPRemediator) RateLimit(ip net.IP, duration time.Duration) error {
	logger.Warnf("⚠️  XDP: Per-IP rate limiting not supported for %s", ip)
	// Return error instead of silently succeeding
	return fmt.Errorf("%w: XDP does not support per-IP rate limiting, use IPSetRemediator", errRLDisabled)
}

// Teardown detaches XDP
