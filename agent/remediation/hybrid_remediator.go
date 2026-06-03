package remediation

import (
	"fmt"
	"net"
	"time"
)

// HybridRemediator combines XDP (fast-path) and iptables (fallback) for comprehensive coverage
// - XDP: Used for fast packet drops (blocked IPs)
// - iptables: Used for rate limiting and as fallback when XDP unavailable
type HybridRemediator struct {
	xdp             *XDPRemediator
	iptables        *IPSetRemediator
	xdpEnabled      bool
	OnBlock         BlockCallback         // Called when an IP is blocked
	OnBlockedPacket BlockedPacketCallback // Called when XDP logs a blocked packet
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
	logger.Info("✅ iptables/ipset remediation ready")

	// Try XDP if configured
	if h.xdp != nil {
		if err := h.xdp.Setup(); err != nil {
			logger.Warnf("⚠️  XDP setup failed, using iptables only: %v", err)
			h.xdp = nil
		} else {
			h.xdpEnabled = true
			logger.Infof("✅ Hybrid mode: XDP (%s) + iptables", h.xdp.Mode())
			// Initialize rate limiting with sensible defaults and freeze the config map
			if err := h.xdp.SetRateLimit(10000, 100000000, 5*time.Minute); err != nil {
				logger.Warnf("⚠️  XDP rate limit initialization failed: %v", err)
			}
			// Start periodic cleanup of expired XDP entries (every 5 minutes)
			h.xdp.StartCleanup(5 * time.Minute)
		}
	} else {
		logger.Info("ℹ️  XDP disabled, using iptables only")
	}

	return nil
}

// Block adds an IP to the blocklist using XDP (if available) or iptables
func (h *HybridRemediator) Block(ip net.IP, duration time.Duration) error {
	var xdpErr, iptablesErr error
	var reason string

	// Try XDP first (faster)
	if h.xdpEnabled && h.xdp != nil {
		xdpErr = h.xdp.Block(ip, duration)
		if xdpErr == nil {
			// XDP succeeded - also add to iptables for redundancy
			// This ensures the block persists even if XDP is detached
			if err := h.iptables.Block(ip, duration); err != nil {
				logger.Warnf("⚠️  XDP succeeded but iptables redundancy failed: %v", err)
				// Don't fail - XDP block is active
			}
			reason = "XDP_BLOCK"
			if h.OnBlock != nil {
				h.OnBlock(ip, ActionBlock, reason, duration)
			}
			return nil
		}
		logger.Warnf("⚠️  XDP block failed, using iptables: %v", xdpErr)
	}

	// Fallback to iptables
	iptablesErr = h.iptables.Block(ip, duration)
	if iptablesErr != nil {
		return fmt.Errorf("all block methods failed: xdp=%v, iptables=%v", xdpErr, iptablesErr)
	}

	reason = "IPTABLES_BLOCK"
	if h.OnBlock != nil {
		h.OnBlock(ip, ActionBlock, reason, duration)
	}
	return nil
}

// IsBlocked checks if an IP is already blocked
func (h *HybridRemediator) IsBlocked(ip net.IP) bool {
	// Check iptables (most reliable and always available)
	if h.iptables != nil {
		return h.iptables.IsBlocked(ip)
	}
	return false
}

// RateLimit adds an IP to the rate-limit list (iptables only)
func (h *HybridRemediator) RateLimit(ip net.IP, duration time.Duration) error {
	// XDP doesn't support rate limiting - always use iptables
	if err := h.iptables.RateLimit(ip, duration); err != nil {
		return err
	}
	if h.OnBlock != nil {
		h.OnBlock(ip, ActionRateLimit, "RATE_LIMIT", duration)
	}
	return nil
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

// BlockCIDR blocks a CIDR range using XDP (if available) or iptables
func (h *HybridRemediator) BlockCIDR(cidr string, duration time.Duration) error {
	// Try XDP first (faster)
	if h.xdpEnabled && h.xdp != nil {
		xdpErr := h.xdp.BlockCIDR(cidr, duration)
		if xdpErr == nil {
			// XDP succeeded - also add to iptables for redundancy
			if err := h.iptables.BlockCIDR(cidr, duration); err != nil {
				logger.Warnf("⚠️  XDP CIDR succeeded but iptables redundancy failed: %v", err)
			}
			return nil
		}
		logger.Warnf("⚠️  XDP CIDR block failed, using iptables: %v", xdpErr)
	}

	// Fallback to iptables
	return h.iptables.BlockCIDR(cidr, duration)
}

// UnblockCIDR removes a CIDR from both XDP and iptables
func (h *HybridRemediator) UnblockCIDR(cidr string) error {
	var errs []error

	// Remove from XDP
	if h.xdpEnabled && h.xdp != nil {
		if err := h.xdp.UnblockCIDR(cidr); err != nil {
			errs = append(errs, fmt.Errorf("XDP unblock CIDR: %w", err))
		}
	}

	// IPSetRemediator doesn't have UnblockCIDR - uses timeout

	if len(errs) > 0 {
		return fmt.Errorf("unblock CIDR errors: %v", errs)
	}
	return nil
}

// Unblock removes an IP from the specified block list
func (h *HybridRemediator) Unblock(ip net.IP, blockType BlockType) error {
	var errs []error

	// Remove from XDP (all block types use same XDP blocklist)
	if h.xdpEnabled && h.xdp != nil {
		if err := h.xdp.Unblock(ip, blockType); err != nil {
			errs = append(errs, fmt.Errorf("XDP unblock: %w", err))
		}
	}

	// Remove from ipset based on block type
	if h.iptables != nil {
		if err := h.iptables.Unblock(ip, blockType); err != nil {
			errs = append(errs, fmt.Errorf("ipset unblock: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("unblock errors: %v", errs)
	}
	return nil
}

// GetIPSetRemediator returns the underlying IPSetRemediator for use with AutoBlocker
func (h *HybridRemediator) GetIPSetRemediator() *IPSetRemediator {
	return h.iptables
}

// GetXDPRemediator returns the underlying XDPRemediator (nil if XDP is disabled or failed setup)
func (h *HybridRemediator) GetXDPRemediator() *XDPRemediator {
	return h.xdp
}

// StartBlockedPacketReader starts reading blocked packet events from XDP ring buffer
// This should be called after Setup() and will call the OnBlockedPacket callback for each event
func (h *HybridRemediator) StartBlockedPacketReader() error {
	if !h.xdpEnabled || h.xdp == nil {
		return fmt.Errorf("XDP not enabled, cannot start blocked packet reader")
	}

	// Wire the callback through to the XDP remediator
	if h.OnBlockedPacket != nil {
		h.xdp.OnBlockedPacket = h.OnBlockedPacket
	}

	return h.xdp.StartBlockedPacketReader()
}
