package remediation

import (
	"fmt"
	"net"
	"time"
)

// XDP block and unblock operations for the XDP firewall.
// Block/BlockCIDR add entries to the XDP blocklist maps
// with optional expiration. Unblock/UnblockCIDR remove them.

func (r *XDPRemediator) Block(ip net.IP, duration time.Duration) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if !r.attached {
		return errNotAttached
	}

	// Enforce map trust classification — refuse writes to frozen maps
	if cls, ok := MapClassificationByName("xdp_blocklist"); ok && cls.Frozen {
		return fmt.Errorf("map xdp_blocklist is frozen (trust level: %s) — writes are not allowed", cls.TrustLevel)
	}
	if cls, ok := MapClassificationByName("xdp_blocklist_v6"); ok && cls.Frozen {
		return fmt.Errorf("map xdp_blocklist_v6 is frozen (trust level: %s) — writes are not allowed", cls.TrustLevel)
	}

	if err := validateIP(ip); err != nil {
		return err
	}
	if !isExternalIP(ip) {
		logger.Warnf("⚠️  XDP: Skipping non-external IP: %s", ip)
		return nil
	}

	// Use monotonic clock (CLOCK_BOOTTIME) which aligns with bpf_ktime_get_ns()
	var expiresNs uint64
	if duration > 0 {
		expiresNs = uint64(monotonicNs() + duration.Nanoseconds())
	}

	if ip4 := ip.To4(); ip4 != nil {
		if err := blockIPv4(r.objs.XdpBlocklist, ip, expiresNs); err != nil {
			return fmt.Errorf("block IPv4: %w", err)
		}
		auditMapWrite("xdp_blocklist", "insert", ip.String(), "block_command", true)
	} else {
		if err := blockIPv6(r.objs.XdpBlocklistV6, ip, expiresNs); err != nil {
			return fmt.Errorf("block IPv6: %w", err)
		}
		auditMapWrite("xdp_blocklist_v6", "insert", ip.String(), "block_command", true)
	}

	// Notify callback if set
	if r.OnBlock != nil {
		r.OnBlock(ip, ActionBlock, "manual", duration)
	}

	return nil
}

// BlockCIDR adds an IPv4 CIDR range to the XDP blocklist.
// IPv6 CIDRs are not currently supported (parseCIDRv4 only handles IPv4).
// TODO: add parseCIDRv6 for IPv6 CIDR support.
func (r *XDPRemediator) BlockCIDR(cidr string, duration time.Duration) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if !r.attached {
		return errNotAttached
	}
	if r.objs.XdpCidrBlocklist == nil {
		return errCIDRDisabled
	}

	key, err := parseCIDRv4(cidr)
	if err != nil {
		return err
	}

	var expiresNs uint64
	if duration > 0 {
		expiresNs = uint64(monotonicNs() + duration.Nanoseconds())
	}

	if err := r.objs.XdpCidrBlocklist.Put(key, blockEntry{ExpiresNs: expiresNs}); err != nil {
		return fmt.Errorf("block CIDR: %w", err)
	}
	logger.Infof("🚫 XDP blocked CIDR %s for %v", cidr, duration)
	return nil
}

// rateLimitState mirrors the BPF struct for xdp_rate_limit map
type rateLimitState struct {
	WindowStart uint64 // Start of current window (ns since boot)
	PacketCount uint64 // Packets in current window
	ByteCount   uint64 // Bytes in current window
}

// SetRateLimit configures global rate limiting.
// The xdp_rate_config map is frozen after the first write, making subsequent
func (r *XDPRemediator) Unblock(ip net.IP, blockType BlockType) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if !r.attached {
		return errNotAttached
	}
	// Add validation that was missing
	if err := validateIP(ip); err != nil {
		return err
	}
	// Note: We don't check isExternalIP for Unblock to allow unblocking
	// IPs that may have been blocked before the external check was added,
	// or IPs that changed classification due to configuration changes.

	if ip4 := ip.To4(); ip4 != nil {
		if err := unblockIPv4(r.objs.XdpBlocklist, ip); err != nil {
			return err
		}
		auditMapWrite("xdp_blocklist", "delete", ip.String(), "block_command", true)
	} else {
		if err := unblockIPv6(r.objs.XdpBlocklistV6, ip); err != nil {
			return err
		}
		auditMapWrite("xdp_blocklist_v6", "delete", ip.String(), "block_command", true)
	}
	logger.Infof("✅ XDP unblocked %s", ip)
	return nil
}

// UnblockCIDR removes CIDR from blocklist
func (r *XDPRemediator) UnblockCIDR(cidr string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if !r.attached {
		return errNotAttached
	}
	if r.objs.XdpCidrBlocklist == nil {
		return errCIDRDisabled
	}
	key, err := parseCIDRv4(cidr)
	if err != nil {
		return err
	}
	if err := r.objs.XdpCidrBlocklist.Delete(key); err != nil && !isNotExist(err) {
		return err
	}
	auditMapWrite("xdp_cidr_blocklist", "delete", cidr, "block_command", true)
	logger.Infof("✅ XDP unblocked CIDR %s", cidr)
	return nil
}
