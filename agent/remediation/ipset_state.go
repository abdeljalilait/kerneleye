package remediation

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// IPSet state inspection — query current membership, get statistics,
// health-check the kernel ipset subsystem, and sync block lists.

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

	logger.Infof("✅ Restored blocklist from %s", r.persistPath)

	// Rebuild the in-memory blockedIPs map so IsBlocked() reflects restored state.
	// Without this, IsBlocked() always returns false after a restart even though
	// the IPs are present in the kernel ipset.
	entries, err := r.ListCurrentlyBlocked()
	if err != nil {
		logger.Warnf("⚠️  Could not read back restored ipset state: %v", err)
		return nil
	}
	r.mu.Lock()
	for _, e := range entries {
		if e.BlockType == BlockTypeBlocklist {
			// Permanent block (timeout 0) — use sentinel far-future time
			r.blockedIPs[e.IP.String()] = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
		}
	}
	r.mu.Unlock()
	logger.Infof("🔄 Rebuilt in-memory block map with %d restored entries", len(entries))
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

	// Destroy ipsets - check existence first and handle gracefully
	sets := []string{blockSet, blockSetV6, rateLimitSet, rateLimitSetV6,
		"kerneleye_block_cidr", "kerneleye_block_cidr_v6"}
	for _, set := range sets {
		// Check if ipset exists
		if out, err := exec.Command("ipset", "list", set).Output(); err != nil || len(out) == 0 {
			continue // Skip non-existent ipsets
		}
		// Flush the ipset first (removes all entries)
		r.Runner("ipset", "flush", set)
		// Then destroy
		if err := r.Runner("ipset", "destroy", set); err != nil {
			logger.Warnf("⚠️  Failed to destroy ipset %s: %v", set, err)
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
		if !isExternalIP(ip) {
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

// ListCurrentlyBlocked reads every IP currently present in all kernel_eye ipsets by
// running `ipset list` and parsing the Members section. Unlike the in-memory
// blockedIPs map this reflects the true kernel-level state — including entries
// that survived an agent restart via Restore().
func (r *IPSetRemediator) ListCurrentlyBlocked() ([]BlockedEntry, error) {
	type setSpec struct {
		name      string
		blockType BlockType
		version   int
	}
	sets := []setSpec{
		{blockSet, BlockTypeBlocklist, 4},
		{blockSetV6, BlockTypeBlocklist, 6},
		{rateLimitSet, BlockTypeRateLimit, 4},
		{rateLimitSetV6, BlockTypeRateLimit, 6},
	}

	var entries []BlockedEntry
	for _, s := range sets {
		out, err := exec.Command("ipset", "list", s.name).Output()
		if err != nil {
			// Set doesn't exist yet — skip silently
			continue
		}
		for _, ipStr := range r.parseMembersSection(string(out)) {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue
			}
			if s.version == 4 {
				ip = ip.To4()
			}
			if ip == nil {
				continue
			}
			entries = append(entries, BlockedEntry{
				IP:        ip,
				BlockType: s.blockType,
				Version:   s.version,
			})
		}
	}
	return entries, nil
}

// parseMembersSection extracts IP strings from `ipset list` output.
// Returns every entry after the "Members:" header (first field only).
func (r *IPSetRemediator) parseMembersSection(output string) []string {
	var ips []string
	inMembers := false
	for _, line := range strings.Split(output, "\n") {
		if line == "Members:" {
			inMembers = true
			continue
		}
		if !inMembers {
			continue
		}
		// Each member line is: "<ip> [timeout <n>]" — take first field
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		ips = append(ips, fields[0])
	}
	return ips
}
