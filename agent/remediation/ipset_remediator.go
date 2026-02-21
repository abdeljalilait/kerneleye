// Package remediation provides IP blocking via iptables + ipset
// This is the primary blocking method for maximum compatibility
package remediation

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	blockSet       = "kernel_eye_block"
	blockSetV6     = "kernel_eye_block_v6"
	rateLimitSet   = "kernel_eye_ratelimit"
	rateLimitSetV6 = "kernel_eye_ratelimit_v6"
	chainName      = "KERNEL_EYE"
	dockerChain    = "DOCKER-USER"
	
	// Persistence file for restoring across reboots
	persistDir  = "/var/lib/kerneleye"
	persistFile = "ipset.state"
)

// CommandRunner allows mocking for tests
type CommandRunner func(name string, args ...string) error

// IPSetStats holds statistics about the blocklist
type IPSetStats struct {
	BlockedCountV4    int
	BlockedCountV6    int
	RateLimitedCountV4 int
	RateLimitedCountV6 int
	TotalDropped      uint64 // From iptables counters
	IsHealthy         bool
}

// IPSetRemediator implements blocking using iptables + ipset
type IPSetRemediator struct {
	Runner     CommandRunner // Exported for testing
	onBlock    BlockCallback
	persistPath string
	mu         sync.RWMutex
	
	// Track blocked IPs in memory for fast lookup
	blockedIPs map[string]time.Time
}

// NewIPSetRemediator creates a new remediator
func NewIPSetRemediator() *IPSetRemediator {
	return &IPSetRemediator{
		Runner:      runCommand,
		persistPath: filepath.Join(persistDir, persistFile),
		blockedIPs:  make(map[string]time.Time),
	}
}

// SetCallback sets the block callback
func (r *IPSetRemediator) SetCallback(cb BlockCallback) {
	r.onBlock = cb
}

// Setup initializes ipsets and iptables rules
func (r *IPSetRemediator) Setup() error {
	// Check dependencies
	if err := r.checkDependencies(); err != nil {
		return err
	}
	
	// Create persistence directory
	if err := os.MkdirAll(persistDir, 0755); err != nil {
		log.Printf("⚠️  Cannot create persist dir %s: %v", persistDir, err)
	}

	// Create ipsets with optimized settings
	// hash:ip with timeout support for automatic expiry
	// maxelem increased for high-volume attacks
	if err := r.createIPSets(); err != nil {
		return fmt.Errorf("failed to create ipsets: %w", err)
	}

	// Setup iptables chain and rules
	if err := r.setupIPTables(); err != nil {
		return fmt.Errorf("failed to setup iptables: %w", err)
	}

	// Restore previous state if exists
	if err := r.Restore(); err != nil {
		log.Printf("⚠️  Failed to restore ipset state: %v", err)
	}

	log.Printf("✅ IPSet remediator ready (blocklist: %s)", blockSet)
	return nil
}

func (r *IPSetRemediator) checkDependencies() error {
	deps := []string{"ipset", "iptables"}
	for _, dep := range deps {
		if _, err := exec.LookPath(dep); err != nil {
			return fmt.Errorf("%s not found. Install: sudo apt-get install %s", dep, dep)
		}
	}
	
	// Check for ip6tables (optional)
	if _, err := exec.LookPath("ip6tables"); err != nil {
		log.Printf("⚠️  ip6tables not found, IPv6 blocking disabled")
	}
	
	return nil
}

func (r *IPSetRemediator) createIPSets() error {
	// IPv4 sets
	sets := []struct {
		name   string
		family string
	}{
		{blockSet, "inet"},
		{rateLimitSet, "inet"},
		{blockSetV6, "inet6"},
		{rateLimitSetV6, "inet6"},
	}

	for _, s := range sets {
		args := []string{"create", s.name, "hash:ip", "timeout", "0", "maxelem", "1000000", "-exist"}
		if s.family == "inet6" {
			args = append(args, "family", "inet6")
		}
		if err := r.Runner("ipset", args...); err != nil {
			return fmt.Errorf("create %s: %w", s.name, err)
		}
	}

	return nil
}

func (r *IPSetRemediator) setupIPTables() error {
	// Create custom chain
	_ = r.Runner("iptables", "-N", chainName) // Ignore exists error
	
	// Flush to ensure clean state
	if err := r.Runner("iptables", "-F", chainName); err != nil {
		return err
	}

	// Add block rule (DROP matching IPs)
	if err := r.Runner("iptables", "-A", chainName, 
		"-m", "set", "--match-set", blockSet, "src", 
		"-j", "DROP", 
		"-m", "comment", "--comment", "KernelEye blocked IPs"); err != nil {
		return err
	}

	// Add rate limit rules (allow burst, then drop)
	if err := r.Runner("iptables", "-A", chainName,
		"-m", "set", "--match-set", rateLimitSet, "src",
		"-m", "limit", "--limit", "10/minute", "--limit-burst", "20",
		"-j", "ACCEPT"); err != nil {
		return err
	}
	if err := r.Runner("iptables", "-A", chainName,
		"-m", "set", "--match-set", rateLimitSet, "src",
		"-j", "DROP", 
		"-m", "comment", "--comment", "KernelEye rate limited"); err != nil {
		return err
	}

	// Insert jump rule at top of INPUT chain (position 1 for priority)
	if !r.ruleExists("INPUT", "-j", chainName) {
		if err := r.Runner("iptables", "-I", "INPUT", "1", "-j", chainName); err != nil {
			return err
		}
	}

	// Also hook into FORWARD chain for container/bridge traffic
	if !r.ruleExists("FORWARD", "-j", chainName) {
		if err := r.Runner("iptables", "-I", "FORWARD", "1", "-j", chainName); err != nil {
			log.Printf("⚠️  Cannot add FORWARD rule: %v", err)
		}
	}

	// Docker support: hook into DOCKER-USER if exists
	if r.chainExists(dockerChain) && !r.ruleExists(dockerChain, "-j", chainName) {
		if err := r.Runner("iptables", "-I", dockerChain, "1", "-j", chainName); err != nil {
			log.Printf("⚠️  Cannot add DOCKER-USER rule: %v", err)
		} else {
			log.Printf("✅ Docker integration enabled")
		}
	}

	// Setup IPv6 similarly
	return r.setupIP6Tables()
}

func (r *IPSetRemediator) setupIP6Tables() error {
	if _, err := exec.LookPath("ip6tables"); err != nil {
		return nil // IPv6 not available, that's ok
	}

	_ = r.Runner("ip6tables", "-N", chainName)
	_ = r.Runner("ip6tables", "-F", chainName)

	r.Runner("ip6tables", "-A", chainName,
		"-m", "set", "--match-set", blockSetV6, "src",
		"-j", "DROP")
	r.Runner("ip6tables", "-A", chainName,
		"-m", "set", "--match-set", rateLimitSetV6, "src",
		"-m", "limit", "--limit", "10/minute", "--limit-burst", "20",
		"-j", "ACCEPT")
	r.Runner("ip6tables", "-A", chainName,
		"-m", "set", "--match-set", rateLimitSetV6, "src",
		"-j", "DROP")

	if !r.ruleExistsIP6("INPUT", "-j", chainName) {
		r.Runner("ip6tables", "-I", "INPUT", "1", "-j", chainName)
	}

	return nil
}

// Block adds an IP to the blocklist
func (r *IPSetRemediator) Block(ip net.IP, duration time.Duration) error {
	if err := r.validateIP(ip); err != nil {
		return err
	}
	if !r.isExternalIP(ip) {
		log.Printf("⚠️  Skipping block for non-external IP: %s", ip)
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

	// Track in memory
	r.mu.Lock()
	r.blockedIPs[ip.String()] = time.Now().Add(duration)
	r.mu.Unlock()

	if r.onBlock != nil {
		r.onBlock(ip, ActionBlock, "IPSET_BLOCK", duration)
	}

	log.Printf("🚫 Blocked %s for %v", ip, duration)
	return nil
}

// Unblock removes an IP from the blocklist
func (r *IPSetRemediator) Unblock(ip net.IP) error {
	if err := r.validateIP(ip); err != nil {
		return err
	}

	set := blockSet
	if ip.To4() == nil {
		set = blockSetV6
	}

	if err := r.Runner("ipset", "del", set, ip.String(), "-exist"); err != nil {
		return fmt.Errorf("ipset del failed: %w", err)
	}

	r.mu.Lock()
	delete(r.blockedIPs, ip.String())
	r.mu.Unlock()

	log.Printf("✅ Unblocked %s", ip)
	return nil
}

// BlockCIDR blocks an IP range (e.g., 192.168.0.0/24)
func (r *IPSetRemediator) BlockCIDR(cidr string, duration time.Duration) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %w", err)
	}

	// Create hash:net set if not exists
	setName := "kerneleye_block_cidr"
	if ipnet.IP.To4() == nil {
		setName = "kerneleye_block_cidr_v6"
	}

	// Ensure set exists
	args := []string{"create", setName, "hash:net", "timeout", "0", "-exist"}
	if ipnet.IP.To4() == nil {
		args = append(args, "family", "inet6")
	}
	r.Runner("ipset", args...)

	// Add rule to chain if not exists (one-time setup)
	if !r.setRuleExists(chainName, setName) {
		r.Runner("iptables", "-I", chainName, "1",
			"-m", "set", "--match-set", setName, "src",
			"-j", "DROP")
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

	log.Printf("🚫 Blocked CIDR %s for %v", cidr, duration)
	return nil
}

// RateLimit adds an IP to rate limit set
func (r *IPSetRemediator) RateLimit(ip net.IP, duration time.Duration) error {
	if err := r.validateIP(ip); err != nil {
		return err
	}
	if !r.isExternalIP(ip) {
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

	log.Printf("⚠️  Rate-limited %s for %v", ip, duration)
	return nil
}

// IsBlocked checks if an IP is currently blocked (fast memory check)
func (r *IPSetRemediator) IsBlocked(ip net.IP) bool {
	r.mu.RLock()
	expires, exists := r.blockedIPs[ip.String()]
	r.mu.RUnlock()

	if !exists {
		return false
	}
	
	// Check if expired
	if time.Now().After(expires) {
		r.mu.Lock()
		delete(r.blockedIPs, ip.String())
		r.mu.Unlock()
		return false
	}
	return true
}

// GetStats returns current block statistics
func (r *IPSetRemediator) GetStats() (*IPSetStats, error) {
	stats := &IPSetStats{}

	// Parse ipset list output
	out, err := exec.Command("ipset", "list", blockSet).Output()
	if err == nil {
		stats.BlockedCountV4 = r.parseMemberCount(string(out))
	}

	out, err = exec.Command("ipset", "list", blockSetV6).Output()
	if err == nil {
		stats.BlockedCountV6 = r.parseMemberCount(string(out))
	}

	out, err = exec.Command("ipset", "list", rateLimitSet).Output()
	if err == nil {
		stats.RateLimitedCountV4 = r.parseMemberCount(string(out))
	}

	out, err = exec.Command("ipset", "list", rateLimitSetV6).Output()
	if err == nil {
		stats.RateLimitedCountV6 = r.parseMemberCount(string(out))
	}

	// Get packet counters from iptables
	stats.TotalDropped = r.getDropCount()
	stats.IsHealthy = r.HealthCheck() == nil

	return stats, nil
}

// HealthCheck verifies iptables rules are in place
func (r *IPSetRemediator) HealthCheck() error {
	if !r.chainExists(chainName) {
		return errors.New("iptables chain missing")
	}
	if !r.ruleExists("INPUT", "-j", chainName) {
		return errors.New("INPUT jump rule missing")
	}
	return nil
}

// Save persists current blocklist to disk
func (r *IPSetRemediator) Save() error {
	// Use ipset save for atomic dump
	out, err := exec.Command("ipset", "save").Output()
	if err != nil {
		return fmt.Errorf("ipset save failed: %w", err)
	}

	// Filter to only our sets
	var filtered strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	inOurSet := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "create kerneleye_") {
			inOurSet = true
			filtered.WriteString(line + "\n")
		} else if strings.HasPrefix(line, "create ") {
			inOurSet = false
		} else if inOurSet {
			filtered.WriteString(line + "\n")
		}
	}

	tmpFile := r.persistPath + ".tmp"
	if err := os.WriteFile(tmpFile, []byte(filtered.String()), 0600); err != nil {
		return err
	}
	
	return os.Rename(tmpFile, r.persistPath)
}

// Restore loads blocklist from disk
func (r *IPSetRemediator) Restore() error {
	data, err := os.ReadFile(r.persistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No state to restore
		}
		return err
	}

	// Restore via ipset restore
	cmd := exec.Command("ipset", "restore")
	cmd.Stdin = strings.NewReader(string(data))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ipset restore failed: %v, output: %s", err, out)
	}

	log.Printf("✅ Restored blocklist from %s", r.persistPath)
	return nil
}

// Teardown removes all rules and ipsets
func (r *IPSetRemediator) Teardown() error {
	var errs []error

	// Remove jump rules
	for r.ruleExists("INPUT", "-j", chainName) {
		if err := r.Runner("iptables", "-D", "INPUT", "-j", chainName); err != nil {
			errs = append(errs, err)
			break
		}
	}

	for r.ruleExists("FORWARD", "-j", chainName) {
		r.Runner("iptables", "-D", "FORWARD", "-j", chainName)
	}

	if r.chainExists(dockerChain) {
		for r.ruleExists(dockerChain, "-j", chainName) {
			r.Runner("iptables", "-D", dockerChain, "-j", chainName)
		}
	}

	// Flush and delete chain
	r.Runner("iptables", "-F", chainName)
	r.Runner("iptables", "-X", chainName)

	// Destroy ipsets
	sets := []string{blockSet, blockSetV6, rateLimitSet, rateLimitSetV6, 
		"kerneleye_block_cidr", "kerneleye_block_cidr_v6"}
	for _, set := range sets {
		if err := r.Runner("ipset", "destroy", set); err != nil {
			log.Printf("⚠️  Failed to destroy ipset %s: %v", set, err)
		}
	}

	// Remove state file
	os.Remove(r.persistPath)

	if len(errs) > 0 {
		return fmt.Errorf("teardown had errors: %v", errs)
	}
	return nil
}

// SyncBlocklist atomically replaces the entire blocklist
func (r *IPSetRemediator) SyncBlocklist(ips []net.IP) error {
	// Create temp sets
	tempBlock := blockSet + "_temp"
	tempBlockV6 := blockSetV6 + "_temp"

	r.Runner("ipset", "create", tempBlock, "hash:ip", "timeout", "0", "-exist")
	r.Runner("ipset", "create", tempBlockV6, "hash:ip", "family", "inet6", "timeout", "0", "-exist")

	// Populate
	for _, ip := range ips {
		if !r.isExternalIP(ip) {
			continue
		}
		set := tempBlock
		if ip.To4() == nil {
			set = tempBlockV6
		}
		r.Runner("ipset", "add", set, ip.String(), "-exist")
	}

	// Atomic swap
	if err := r.Runner("ipset", "swap", tempBlock, blockSet); err != nil {
		return err
	}
	if err := r.Runner("ipset", "swap", tempBlockV6, blockSetV6); err != nil {
		return err
	}

	// Cleanup old sets
	r.Runner("ipset", "destroy", tempBlock)
	r.Runner("ipset", "destroy", tempBlockV6)

	return nil
}

// Helper methods

func (r *IPSetRemediator) validateIP(ip net.IP) error {
	if ip == nil || len(ip) != 4 && len(ip) != 16 {
		return errors.New("invalid IP")
	}
	return nil
}

func (r *IPSetRemediator) isExternalIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || 
	   ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	return true
}

func (r *IPSetRemediator) chainExists(chain string) bool {
	err := r.Runner("iptables", "-L", chain, "-n")
	return err == nil
}

func (r *IPSetRemediator) ruleExists(chain string, args ...string) bool {
	fullArgs := append([]string{"-C", chain}, args...)
	err := r.Runner("iptables", fullArgs...)
	return err == nil
}

func (r *IPSetRemediator) ruleExistsIP6(chain string, args ...string) bool {
	fullArgs := append([]string{"-C", chain}, args...)
	err := r.Runner("ip6tables", fullArgs...)
	return err == nil
}

func (r *IPSetRemediator) setRuleExists(chain, setName string) bool {
	cmd := exec.Command("iptables", "-L", chain, "-n")
	out, _ := cmd.Output()
	return strings.Contains(string(out), setName)
}

func (r *IPSetRemediator) parseMemberCount(output string) int {
	// Parse "Number of entries: X" from ipset list output
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "Number of entries:") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				if n, err := strconv.Atoi(fields[3]); err == nil {
					return n
				}
			}
		}
	}
	return 0
}

func (r *IPSetRemediator) getDropCount() uint64 {
	// Parse iptables -L -v -n output for drop count
	cmd := exec.Command("iptables", "-L", chainName, "-v", "-n", "-x")
	out, _ := cmd.Output()
	
	var total uint64
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "DROP") && strings.Contains(line, blockSet) {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if n, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
					total += n
				}
			}
		}
	}
	return total
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %v, output: %s", name, args, err, string(out))
	}
	return nil
}
