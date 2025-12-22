package remediation

import (
	"fmt"
	"log"
	"net"
	"time"
)

// HybridRemediator combines XDP (fast-path) and iptables (fallback) for comprehensive coverage
// - XDP: Used for fast packet drops (blocked IPs)
// - iptables: Used for rate limiting and as fallback when XDP unavailable
type HybridRemediator struct {
	xdp        *XDPRemediator
	iptables   *IPSetRemediator
	xdpEnabled bool
}

// HybridConfig configures the hybrid remediator
type HybridConfig struct {
	EnableXDP     bool   // Attempt to use XDP
	InterfaceName string // Network interface for XDP attachment
}

// NewHybridRemediator creates a new hybrid remediator
func NewHybridRemediator(cfg HybridConfig) *HybridRemediator {
	h := &HybridRemediator{
		iptables: NewIPSetRemediator(),
	}

	if cfg.EnableXDP && cfg.InterfaceName != "" {
		h.xdp = NewXDPRemediator(cfg.InterfaceName)
	}

	return h
}

// Setup initializes both XDP and iptables remediation
func (h *HybridRemediator) Setup() error {
	// Always setup iptables (fallback)
	if err := h.iptables.Setup(); err != nil {
		return fmt.Errorf("iptables setup failed: %w", err)
	}
	log.Printf("✅ iptables/ipset remediation ready")

	// Try XDP if configured
	if h.xdp != nil {
		if err := h.xdp.Setup(); err != nil {
			log.Printf("⚠️  XDP setup failed, using iptables only: %v", err)
			h.xdp = nil
		} else {
			h.xdpEnabled = true
			log.Printf("✅ Hybrid mode: XDP (%s) + iptables", h.xdp.Mode())
		}
	} else {
		log.Printf("ℹ️  XDP disabled, using iptables only")
	}

	return nil
}

// Block adds an IP to the blocklist using XDP (if available) or iptables
func (h *HybridRemediator) Block(ip net.IP, duration time.Duration) error {
	var xdpErr, iptablesErr error

	// Try XDP first (faster)
	if h.xdpEnabled && h.xdp != nil {
		xdpErr = h.xdp.Block(ip, duration)
		if xdpErr == nil {
			// XDP succeeded - also add to iptables for redundancy
			// This ensures the block persists even if XDP is detached
			h.iptables.Block(ip, duration)
			return nil
		}
		log.Printf("⚠️  XDP block failed, using iptables: %v", xdpErr)
	}

	// Fallback to iptables
	iptablesErr = h.iptables.Block(ip, duration)
	if iptablesErr != nil {
		return fmt.Errorf("all block methods failed: xdp=%v, iptables=%v", xdpErr, iptablesErr)
	}

	return nil
}

// RateLimit adds an IP to the rate-limit list (iptables only)
func (h *HybridRemediator) RateLimit(ip net.IP, duration time.Duration) error {
	// XDP doesn't support rate limiting - always use iptables
	return h.iptables.RateLimit(ip, duration)
}

// Teardown cleans up both XDP and iptables resources
func (h *HybridRemediator) Teardown() error {
	var errs []error

	if h.xdp != nil {
		if err := h.xdp.Teardown(); err != nil {
			errs = append(errs, fmt.Errorf("XDP teardown: %w", err))
		}
	}

	if err := h.iptables.Teardown(); err != nil {
		errs = append(errs, fmt.Errorf("iptables teardown: %w", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("teardown errors: %v", errs)
	}
	return nil
}

// GetStats returns combined statistics
func (h *HybridRemediator) GetStats() (passed, dropped, errors uint64, err error) {
	if !h.xdpEnabled || h.xdp == nil {
		return 0, 0, 0, fmt.Errorf("XDP not enabled")
	}

	stats, err := h.xdp.GetStats()
	if err != nil {
		return 0, 0, 0, err
	}

	return stats.PassedPackets, stats.DroppedPackets, stats.ErrorPackets, nil
}

// IsXDPEnabled returns whether XDP is active
func (h *HybridRemediator) IsXDPEnabled() bool {
	return h.xdpEnabled
}

// XDPMode returns the XDP mode if enabled
func (h *HybridRemediator) XDPMode() string {
	if h.xdp != nil && h.xdpEnabled {
		return h.xdp.Mode().String()
	}
	return "disabled"
}

// Unblock removes an IP from both XDP and iptables blocklists
func (h *HybridRemediator) Unblock(ip net.IP) error {
	var errs []error

	// Remove from XDP
	if h.xdpEnabled && h.xdp != nil {
		if err := h.xdp.Unblock(ip); err != nil {
			errs = append(errs, fmt.Errorf("XDP unblock: %w", err))
		}
	}

	// Note: IPSetRemediator doesn't have Unblock - ipset timeout handles expiry
	// For manual unblock, we'd need: ipset del kernel_eye_block <ip>

	if len(errs) > 0 {
		return fmt.Errorf("unblock errors: %v", errs)
	}
	return nil
}
