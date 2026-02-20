package remediation

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	BlockSet       = "kernel_eye_block"
	BlockSetV6     = "kernel_eye_block_v6"
	RateLimitSet   = "kernel_eye_ratelimit"
	RateLimitSetV6 = "kernel_eye_ratelimit_v6"
	ChainName      = "KERNEL_EYE"
	DockerChain    = "DOCKER-USER"
)

type CommandRunner func(name string, args ...string) error

type IPSetRemediator struct {
	Runner  CommandRunner
	OnBlock BlockCallback // Called when an IP is blocked or rate-limited
}

func NewIPSetRemediator() *IPSetRemediator {
	return &IPSetRemediator{
		Runner: runCommand,
	}
}

func (r *IPSetRemediator) Setup() error {
	// Check required binaries exist
	if _, err := exec.LookPath("ipset"); err != nil {
		return fmt.Errorf("ipset not found in PATH. Install with: sudo apt-get install ipset (Debian/Ubuntu) or sudo yum install ipset (RHEL/CentOS)")
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("iptables not found in PATH. Install with: sudo apt-get install iptables (Debian/Ubuntu) or sudo yum install iptables (RHEL/CentOS)")
	}
	// ip6tables is optional - we'll log if it's missing but continue
	hasIP6Tables := true
	if _, err := exec.LookPath("ip6tables"); err != nil {
		hasIP6Tables = false
		log.Printf("⚠️  ip6tables not found, IPv6 blocking will be skipped")
	}

	// Create IPv4 ipsets
	if err := r.Runner("ipset", "create", BlockSet, "hash:ip", "timeout", "3600", "-exist"); err != nil {
		return fmt.Errorf("failed to create block ipset: %w", err)
	}
	if err := r.Runner("ipset", "create", RateLimitSet, "hash:ip", "timeout", "600", "-exist"); err != nil {
		return fmt.Errorf("failed to create ratelimit ipset: %w", err)
	}

	// Create IPv6 ipsets
	if err := r.Runner("ipset", "create", BlockSetV6, "hash:ip", "family", "inet6", "timeout", "3600", "-exist"); err != nil {
		return fmt.Errorf("failed to create block ipset v6: %w", err)
	}
	if err := r.Runner("ipset", "create", RateLimitSetV6, "hash:ip", "family", "inet6", "timeout", "600", "-exist"); err != nil {
		return fmt.Errorf("failed to create ratelimit ipset v6: %w", err)
	}

	// Create iptables chain
	// Try to create chain. If it already exists, that's fine - we'll flush it.
	if err := r.Runner("iptables", "-N", ChainName); err != nil {
		// Check if error is because chain already exists
		if !isAlreadyExistsError(err) {
			return fmt.Errorf("failed to create chain %s: %w", ChainName, err)
		}
		log.Printf("🔄 Chain %s already exists", ChainName)
	}

	// Ensure jump rules exist (idempotent - checks before inserting)
	if err := r.ensureJumpRule("INPUT", ChainName); err != nil {
		return fmt.Errorf("failed to ensure INPUT jump rule: %w", err)
	}

	// Ensure jump rule from DOCKER-USER to KERNEL_EYE exists (if DOCKER-USER exists)
	if r.chainExists(DockerChain) {
		if err := r.ensureJumpRule(DockerChain, ChainName); err != nil {
			log.Printf("⚠️  Failed to ensure DOCKER-USER jump rule: %v", err)
			// Proceeding without it, but logging the error
		} else {
			log.Printf("✅ Attached %s to %s", ChainName, DockerChain)
		}
	}

	// Flush chain to ensure clean state (removes any existing rules)
	// This prevents rule accumulation if Setup() is called multiple times
	if err := r.Runner("iptables", "-F", ChainName); err != nil {
		return fmt.Errorf("failed to flush chain %s: %w", ChainName, err)
	}

	// Add rules to clean chain
	// Block rules
	if err := r.Runner("iptables", "-A", ChainName, "-m", "set", "--match-set", BlockSet, "src", "-j", "DROP"); err != nil {
		return fmt.Errorf("failed to add block rule: %w", err)
	}

	// Rate limit rules
	if err := r.Runner("iptables", "-A", ChainName, "-m", "set", "--match-set", RateLimitSet, "src", "-m", "limit", "--limit", "10/second", "--limit-burst", "20", "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("failed to add ratelimit accept rule: %w", err)
	}
	if err := r.Runner("iptables", "-A", ChainName, "-m", "set", "--match-set", RateLimitSet, "src", "-j", "DROP"); err != nil {
		return fmt.Errorf("failed to add ratelimit drop rule: %w", err)
	}

	return nil
}

func (r *IPSetRemediator) Block(ip net.IP, duration time.Duration) error {
	if err := r.validateIP(ip); err != nil {
		return err
	}
	if !r.isExternalIP(ip) {
		log.Printf("⚠️  Skipping block for non-external IP: %s", ip)
		return nil
	}

	log.Printf("🚫 Blocking IP %s for %v", ip, duration)
	set := BlockSet
	if ip.To4() == nil {
		set = BlockSetV6
	}
	if err := r.Runner("ipset", "add", set, ip.String(), "timeout", strconv.Itoa(int(duration.Seconds())), "-exist"); err != nil {
		return err
	}
	if r.OnBlock != nil {
		r.OnBlock(ip, ActionBlock, "IPSET_BLOCK", duration)
	}
	return nil
}

func (r *IPSetRemediator) RateLimit(ip net.IP, duration time.Duration) error {
	if err := r.validateIP(ip); err != nil {
		return err
	}
	if !r.isExternalIP(ip) {
		log.Printf("⚠️  Skipping rate-limit for non-external IP: %s", ip)
		return nil
	}

	log.Printf("⚠️  Rate-limiting IP %s for %v", ip, duration)
	set := RateLimitSet
	if ip.To4() == nil {
		set = RateLimitSetV6
	}
	if err := r.Runner("ipset", "add", set, ip.String(), "timeout", strconv.Itoa(int(duration.Seconds())), "-exist"); err != nil {
		return err
	}
	if r.OnBlock != nil {
		r.OnBlock(ip, ActionRateLimit, "IPSET_RATE_LIMIT", duration)
	}
	return nil
}

func (r *IPSetRemediator) SyncBlocklist(ips []net.IP) error {
	// Atomic swap implementation for both IPv4 and IPv6:
	// 1. Create temporary sets for v4 and v6
	// 2. Populate temporary sets
	// 3. Swap with active sets
	// 4. Destroy old sets (now referenced by temp names)

	tempSetV4 := BlockSet + "_temp"
	tempSetV6 := BlockSetV6 + "_temp"

	// Create temp sets with same parameters as BlockSets
	if err := r.Runner("ipset", "create", tempSetV4, "hash:ip", "timeout", "3600", "-exist"); err != nil {
		return fmt.Errorf("failed to create temp ipset v4: %w", err)
	}
	if err := r.Runner("ipset", "create", tempSetV6, "hash:ip", "family", "inet6", "timeout", "3600", "-exist"); err != nil {
		// Clean up v4 temp set if v6 creation fails
		_ = r.Runner("ipset", "destroy", tempSetV4)
		return fmt.Errorf("failed to create temp ipset v6: %w", err)
	}

	// Helper to cleanup temp sets on error (before swap)
	// After swap, tempSet names point to old data, which we DO want to destroy
	cleanupOnError := func() {
		_ = r.Runner("ipset", "destroy", tempSetV4)
		_ = r.Runner("ipset", "destroy", tempSetV6)
	}
	swapSucceeded := false
	defer func() {
		if !swapSucceeded {
			// Only cleanup if swap didn't happen
			cleanupOnError()
		}
		// If swap succeeded, tempSet names now refer to the OLD sets,
		// so we destroy them to clean up (done below)
	}()

	// Populate temp sets
	v4Count, v6Count := 0, 0
	skippedCount := 0
	for _, ip := range ips {
		if err := r.validateIP(ip); err != nil {
			log.Printf("⚠️  Skipping invalid IP in sync: %v", err)
			skippedCount++
			continue
		}

		if !r.isExternalIP(ip) {
			skippedCount++
			continue // Skip non-external IPs
		}

		if ip.To4() != nil {
			// IPv4
			if err := r.Runner("ipset", "add", tempSetV4, ip.String(), "timeout", "3600", "-exist"); err != nil {
				log.Printf("⚠️  Failed to add IP %s to temp v4 set: %v", ip, err)
			} else {
				v4Count++
			}
		} else {
			// IPv6
			if err := r.Runner("ipset", "add", tempSetV6, ip.String(), "timeout", "3600", "-exist"); err != nil {
				log.Printf("⚠️  Failed to add IP %s to temp v6 set: %v", ip, err)
			} else {
				v6Count++
			}
		}
	}

	log.Printf("📊 SyncBlocklist: %d IPv4, %d IPv6 added (%d skipped)", v4Count, v6Count, skippedCount)

	// Atomic Swap for IPv4
	if err := r.Runner("ipset", "swap", tempSetV4, BlockSet); err != nil {
		return fmt.Errorf("failed to swap v4 ipsets: %w", err)
	}

	// Atomic Swap for IPv6
	if err := r.Runner("ipset", "swap", tempSetV6, BlockSetV6); err != nil {
		// Note: v4 has already been swapped. This is a partial failure state.
		// The old v6 set is still active, but v4 has the new data.
		// For now, we just return the error. A more robust implementation might
		// attempt to swap back v4 or track this state.
		return fmt.Errorf("failed to swap v6 ipsets (v4 swap succeeded): %w", err)
	}

	// Swaps succeeded - tempSet names now point to the OLD sets
	swapSucceeded = true

	// Destroy the old sets (now referenced by temp names)
	// Ignore errors here as these are best-effort cleanup
	if err := r.Runner("ipset", "destroy", tempSetV4); err != nil {
		log.Printf("⚠️  Failed to destroy old v4 set (was %s): %v", tempSetV4, err)
	}
	if err := r.Runner("ipset", "destroy", tempSetV6); err != nil {
		log.Printf("⚠️  Failed to destroy old v6 set (was %s): %v", tempSetV6, err)
	}

	return nil
}

func (r *IPSetRemediator) Teardown() error {
	var errs []error

	// Clean up iptables jump rules (may be multiple if duplicates exist)
	// Keep deleting until no more rules found (max 10 iterations to prevent infinite loops)
	for i := 0; i < 10 && r.jumpRuleExists("INPUT", ChainName); i++ {
		if err := r.Runner("iptables", "-D", "INPUT", "-j", ChainName); err != nil {
			errs = append(errs, fmt.Errorf("failed to delete INPUT jump rule: %w", err))
			break // Stop trying if deletion fails
		}
	}

	if r.chainExists(DockerChain) {
		for i := 0; i < 10 && r.jumpRuleExists(DockerChain, ChainName); i++ {
			if err := r.Runner("iptables", "-D", DockerChain, "-j", ChainName); err != nil {
				errs = append(errs, fmt.Errorf("failed to delete DOCKER-USER jump rule: %w", err))
				break
			}
		}
	}

	// Flush and delete chain
	if err := r.Runner("iptables", "-F", ChainName); err != nil {
		errs = append(errs, fmt.Errorf("failed to flush chain %s: %w", ChainName, err))
	}
	if err := r.Runner("iptables", "-X", ChainName); err != nil {
		errs = append(errs, fmt.Errorf("failed to delete chain %s: %w", ChainName, err))
	}

	// Destroy ipsets (best effort - ignore errors as they may not exist)
	for _, set := range []string{BlockSet, RateLimitSet, BlockSetV6, RateLimitSetV6} {
		if err := r.Runner("ipset", "destroy", set); err != nil {
			// Only log, don't fail - sets may not exist or may still be referenced
			log.Printf("⚠️  Failed to destroy ipset %s: %v", set, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("teardown completed with %d errors: %v", len(errs), errors.Join(errs...))
	}
	return nil
}

func (r *IPSetRemediator) validateIP(ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("invalid nil IP")
	}
	// net.IP is a []byte. Valid IPs are 4 or 16 bytes.
	if len(ip) != 4 && len(ip) != 16 {
		return fmt.Errorf("invalid IP length: %d (expected 4 or 16)", len(ip))
	}
	return nil
}

func (r *IPSetRemediator) isExternalIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	// Also check for unspecified (0.0.0.0) and multicast
	if ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	return true
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("command %s %v failed: %v, output: %s", name, args, err, string(out))
	}
	return nil
}

func (r *IPSetRemediator) ensureJumpRule(fromChain, toChain string) error {
	// Check if jump rule exists
	if err := r.Runner("iptables", "-C", fromChain, "-j", toChain); err != nil {
		// If check failed, try to insert at position 1
		if err := r.Runner("iptables", "-I", fromChain, "1", "-j", toChain); err != nil {
			return fmt.Errorf("failed to insert jump rule from %s to %s: %w", fromChain, toChain, err)
		}
		log.Printf("✅ Added jump rule: %s -> %s", fromChain, toChain)
	}
	return nil
}

func (r *IPSetRemediator) jumpRuleExists(fromChain, toChain string) bool {
	// Check if a specific jump rule exists
	// iptables -C fromChain -j toChain
	err := r.Runner("iptables", "-C", fromChain, "-j", toChain)
	return err == nil
}

func (r *IPSetRemediator) chainExists(chain string) bool {
	// iptables -L <chain> -n
	// If returns nil error, chain exists.
	// We ignore output.
	err := r.Runner("iptables", "-L", chain, "-n")
	return err == nil
}

// isAlreadyExistsError checks if an error indicates the chain already exists
func isAlreadyExistsError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "Chain already exists") ||
		strings.Contains(errStr, "File exists")
}
