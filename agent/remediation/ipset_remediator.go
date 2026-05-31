// Package remediation provides IP blocking via iptables + ipset
// This is the primary blocking method for maximum compatibility
package remediation

import (
	"errors"
	"fmt"
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
	BlockedCountV4     int
	BlockedCountV6     int
	RateLimitedCountV4 int
	RateLimitedCountV6 int
	TotalDropped       uint64 // From iptables counters
	IsHealthy          bool
}

// IPSetRemediator implements blocking using iptables + ipset
type IPSetRemediator struct {
	Runner      CommandRunner // Exported for testing
	onBlock     BlockCallback
	persistPath string
	mu          sync.RWMutex

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
		logger.Warnf("⚠️  Cannot create persist dir %s: %v", persistDir, err)
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
		logger.Warnf("⚠️  Failed to restore ipset state: %v", err)
	}

	logger.Infof("✅ IPSet remediator ready (blocklist: %s)", blockSet)
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
		logger.Info("⚠️  ip6tables not found, IPv6 blocking disabled")
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
			logger.Warnf("⚠️  Cannot add FORWARD rule: %v", err)
		}
	}

	// Docker support: hook into DOCKER-USER if exists
	if r.chainExists(dockerChain) && !r.ruleExists(dockerChain, "-j", chainName) {
		if err := r.Runner("iptables", "-I", dockerChain, "1", "-j", chainName); err != nil {
			logger.Info("⚠️  Cannot add DOCKER-USER rule: %v", err)
		} else {
			logger.Info("✅ Docker integration enabled")
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
// IsBlocked checks if an IP is currently blocked (fast memory check)

func (r *IPSetRemediator) validateIP(ip net.IP) error {
	if ip == nil || len(ip) != 4 && len(ip) != 16 {
		return errors.New("invalid IP")
	}
	return nil
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

func (r *IPSetRemediator) setRuleExistsIP6(chain, setName string) bool {
	cmd := exec.Command("ip6tables", "-L", chain, "-n")
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
