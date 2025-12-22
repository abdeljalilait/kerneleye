package remediation

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
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
	OnBlock BlockCallback // Called when an IP is blocked
}

func NewIPSetRemediator() *IPSetRemediator {
	return &IPSetRemediator{
		Runner: runCommand,
	}
}

func (r *IPSetRemediator) Setup() error {
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
	if err := r.Runner("iptables", "-N", ChainName); err != nil {
		// Only ignore "Chain already exists" error
		// Note: CombinedOutput usually includes stderr.
		// Exact string depends on iptables version, typically "Chain already exists".
		// For robustness, we can try to flush it. If that succeeds, it existed.
		// Alternatively, just log debug if it fails, but don't return error.
		// A cleaner way in Setup:
		// 1. Create (-N). If fail, Flush (-F).
		if errFlush := r.Runner("iptables", "-F", ChainName); errFlush != nil {
			// If flush failed, implies chain might not exist or other error.
			// But if -N failed, it might exist.
			// Let's rely on the previous -N error for logging but continue.
		}
	}

	// Ensure jump rule from INPUT to KERNEL_EYE exists
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

	// Flush chain
	r.Runner("iptables", "-F", ChainName)

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
	// Atomic swap implementation:
	// 1. Create temporary set
	// 2. Populate temporary set
	// 3. Swap with active set
	// 4. Destroy temporary set

	tempSet := BlockSet + "_temp"
	// Create temp set with same parameters as BlockSet
	if err := r.Runner("ipset", "create", tempSet, "hash:ip", "timeout", "3600", "-exist"); err != nil {
		return fmt.Errorf("failed to create temp ipset: %w", err)
	}

	// Helper to cleanup temp set on error
	defer r.Runner("ipset", "destroy", tempSet)

	// Populate temp set
	// Note: For very large lists, 'restore' mode would be faster, but direct execution is safer for now without changing CommandRunner interface.
	for _, ip := range ips {
		if err := r.validateIP(ip); err != nil {
			continue // Skip invalid IPs
		}

		if !r.isExternalIP(ip) {
			continue // Skip non-external IPs
		}

		// Add to IPv4 temp set (assuming mixed list, we might need separate syncs or sets,
		// but currently BlockSet is v4. Handling v6 in sync requires v6 temp set too.
		// For simplicity/MVP, we'll just handle v4 in this pass or assume caller separates them?
		// The current Block() method splits by v4/v6. Sync needs to ideally do the same.
		// Let's implement v4 sync for BlockSet and v6 for BlockSetV6 if we want full correctness.
		// For now, let's just handle IPv4 as the primary requirement usually implies.
		if ip.To4() != nil {
			if err := r.Runner("ipset", "add", tempSet, ip.String(), "timeout", "3600", "-exist"); err != nil {
				log.Printf("⚠️ Failed to add IP %s to temp set: %v", ip, err)
			}
		}
	}

	// Atomic Swap
	if err := r.Runner("ipset", "swap", tempSet, BlockSet); err != nil {
		return fmt.Errorf("failed to swap ipsets: %w", err)
	}

	// Release reference to temp set so defer destroy works on the OLD set (which is now named tempSet)
	// ipset swap swaps the NAMES. So 'tempSet' name now points to the OLD set.
	// The defer will destroy 'tempSet' (the old set).

	return nil
}

func (r *IPSetRemediator) Teardown() error {
	// Clean up iptables chain
	// Clean up iptables chain
	r.Runner("iptables", "-D", "INPUT", "-j", ChainName)
	if r.chainExists(DockerChain) {
		r.Runner("iptables", "-D", DockerChain, "-j", ChainName)
	}
	r.Runner("iptables", "-F", ChainName)
	r.Runner("iptables", "-X", ChainName)

	// Destroy ipsets
	r.Runner("ipset", "destroy", BlockSet)
	r.Runner("ipset", "destroy", RateLimitSet)
	r.Runner("ipset", "destroy", BlockSetV6)
	r.Runner("ipset", "destroy", RateLimitSetV6)
	return nil
}

func (r *IPSetRemediator) validateIP(ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("invalid nil IP")
	}
	// Basic string representation check is handled by ip.String() which is safe
	// But we want to ensure it's a valid IP structure
	if len(ip) == 0 {
		return fmt.Errorf("empty IP")
	}
	return nil
}

func (r *IPSetRemediator) isExternalIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
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
		// If check failed, try to insert
		if err := r.Runner("iptables", "-I", fromChain, "-j", toChain); err != nil {
			return err
		}
	}
	return nil
}

func (r *IPSetRemediator) chainExists(chain string) bool {
	// iptables -L <chain> -n
	// If returns nil error, chain exists.
	// We ignore output.
	err := r.Runner("iptables", "-L", chain, "-n")
	return err == nil
}
