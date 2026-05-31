package remediation

import (
	"fmt"
	"net"
	"strconv"
	"time"

)

// IPSet block and unblock operations for ipset/iptables remediation.
// Handles dual-stack IPv4/IPv6 block management with automatic timeout.

func (r *IPSetRemediator) Block(ip net.IP, duration time.Duration) error {
	if err := r.validateIP(ip); err != nil {
		return err
	}
	if !isExternalIP(ip) {
		logger.Warnf("⚠️  Skipping block for non-external IP: %s", ip)
		return nil
	}

	set := blockSet
	if ip.To4() == nil {
		set = blockSetV6
	}

	// Add with timeout (0 = permanent)
	timeoutSec := int(duration.Seconds())
	args := []string{"add", set, ip.String()}
	if timeoutSec > 0 {
		args = append(args, "timeout", strconv.Itoa(timeoutSec))
	}
	args = append(args, "-exist")

	if err := r.Runner("ipset", args...); err != nil {
		return fmt.Errorf("ipset add failed: %w", err)
	}

	// Track in memory - use max time for permanent blocks
	r.mu.Lock()
	if duration > 0 {
		r.blockedIPs[ip.String()] = time.Now().Add(duration)
	} else {
		// Permanent block - use max time
		r.blockedIPs[ip.String()] = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
	}
	r.mu.Unlock()

	if r.onBlock != nil {
		r.onBlock(ip, ActionBlock, "IPSET_BLOCK", duration)
	}

	if duration > 0 {
		logger.Infof("🚫 Blocked %s for %v", ip, duration)
	} else {
		logger.Infof("🚫 Blocked %s permanently", ip)
	}
	return nil
}

// Unblock removes an IP from the specified blocklist
func (r *IPSetRemediator) Unblock(ip net.IP, blockType BlockType) error {
	if err := r.validateIP(ip); err != nil {
		return err
	}

	// Determine which ipset to use based on block type
	set := blockSet
	switch blockType {
	case BlockTypeRateLimit:
		set = rateLimitSet
	case BlockTypeCIDR:
		set = "kerneleye_block_cidr"
	default:
		set = blockSet
	}

	// Adjust for IPv6
	if ip.To4() == nil {
		switch blockType {
		case BlockTypeRateLimit:
			set = rateLimitSetV6
		case BlockTypeCIDR:
			set = "kerneleye_block_cidr_v6"
		default:
			set = blockSetV6
		}
	}

	if err := r.Runner("ipset", "del", set, ip.String(), "-exist"); err != nil {
		return fmt.Errorf("ipset del failed: %w", err)
	}

	r.mu.Lock()
	delete(r.blockedIPs, ip.String())
	r.mu.Unlock()

	logger.Infof("✅ Unblocked %s from %s", ip, set)
	return nil
}

// BlockCIDR blocks an IP range (e.g., 192.168.0.0/24)
func (r *IPSetRemediator) BlockCIDR(cidr string, duration time.Duration) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %w", err)
	}

	// Create hash:net set if not exists
	isIPv6 := ipnet.IP.To4() == nil
	setName := "kerneleye_block_cidr"
	if isIPv6 {
		setName = "kerneleye_block_cidr_v6"
	}

	// Ensure set exists
	args := []string{"create", setName, "hash:net", "timeout", "0", "-exist"}
	if isIPv6 {
		args = append(args, "family", "inet6")
	}
	if err := r.Runner("ipset", args...); err != nil {
		return fmt.Errorf("ipset create %s failed: %w", setName, err)
	}

	// Add rule to iptables chain if not exists
	if !r.setRuleExists(chainName, setName) {
		if err := r.Runner("iptables", "-I", chainName, "1",
			"-m", "set", "--match-set", setName, "src",
			"-j", "DROP"); err != nil {
			return fmt.Errorf("iptables insert for %s failed: %w", setName, err)
		}
	}

	// Add rule to ip6tables chain for IPv6 if not exists
	if isIPv6 {
		if !r.setRuleExistsIP6(chainName, setName) {
			if err := r.Runner("ip6tables", "-I", chainName, "1",
				"-m", "set", "--match-set", setName, "src",
				"-j", "DROP"); err != nil {
				return fmt.Errorf("ip6tables insert for %s failed: %w", setName, err)
			}
		}
	}

	// Add CIDR to set
	timeoutSec := int(duration.Seconds())
	addArgs := []string{"add", setName, cidr, "-exist"}
	if timeoutSec > 0 {
		addArgs = append(addArgs, "timeout", strconv.Itoa(timeoutSec))
	}

	if err := r.Runner("ipset", addArgs...); err != nil {
		return err
	}

	logger.Infof("🚫 Blocked CIDR %s for %v", cidr, duration)
	return nil
}

// RateLimit adds an IP to rate limit set
func (r *IPSetRemediator) RateLimit(ip net.IP, duration time.Duration) error {
	if err := r.validateIP(ip); err != nil {
		return err
	}
	if !isExternalIP(ip) {
		return fmt.Errorf("refusing to rate-limit internal IP: %s", ip)
	}

	set := rateLimitSet
	if ip.To4() == nil {
		set = rateLimitSetV6
	}

	timeoutSec := int(duration.Seconds())
	if timeoutSec == 0 {
		timeoutSec = 600 // Default 10 minutes
	}

	if err := r.Runner("ipset", "add", set, ip.String(),
		"timeout", strconv.Itoa(timeoutSec), "-exist"); err != nil {
		return err
	}

	if r.onBlock != nil {
		r.onBlock(ip, ActionRateLimit, "IPSET_RATE_LIMIT", duration)
	}

	logger.Warnf("⚠️  Rate-limited %s for %v", ip, duration)
	return nil
}

