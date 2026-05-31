package remediation

import (
	"time"

	"github.com/cilium/ebpf"
)

// XDP map cleanup — periodic eviction of expired blocklist entries.
// Runs in a background goroutine to prevent map memory leaks.

func (r *XDPRemediator) StartCleanup(interval time.Duration) {
	if interval <= 0 {
		logger.Errorf("StartCleanup: interval must be positive (got %v)", interval)
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.cleanupEnabled {
		return // Already running
	}

	r.cleanupEnabled = true
	r.cleanupInterval = interval
	r.cleanupCancel = make(chan struct{})

	r.cleanupWg.Add(1)
	go r.cleanupLoop()

	logger.Infof("🧹 XDP cleanup started (interval: %v)", interval)
}

// StopCleanup stops the cleanup goroutine
func (r *XDPRemediator) StopCleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.cleanupEnabled {
		return
	}

	close(r.cleanupCancel)
	r.cleanupWg.Wait()
	r.cleanupEnabled = false

	logger.Info("🧹 XDP cleanup stopped")
}

// cleanupLoop runs the periodic cleanup
func (r *XDPRemediator) cleanupLoop() {
	defer r.cleanupWg.Done()

	ticker := time.NewTicker(r.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.cleanupCancel:
			return
		case <-ticker.C:
			r.cleanupExpiredEntries()
		}
	}
}

// cleanupExpiredEntries removes expired entries from XDP blocklist maps
func (r *XDPRemediator) cleanupExpiredEntries() {
	if !r.attached || r.objs == nil {
		return
	}

	now := uint64(monotonicNs())
	cleaned := 0

	// Cleanup IPv4 blocklist
	if r.objs.XdpBlocklist != nil {
		cleaned += r.cleanupMap(r.objs.XdpBlocklist, now)
	}

	// Cleanup IPv6 blocklist
	if r.objs.XdpBlocklistV6 != nil {
		cleaned += r.cleanupMapV6(r.objs.XdpBlocklistV6, now)
	}

	// Cleanup CIDR blocklist
	if r.objs.XdpCidrBlocklist != nil {
		cleaned += r.cleanupLPMMap(r.objs.XdpCidrBlocklist, now)
	}

	if cleaned > 0 {
		logger.Debugf("🧹 XDP cleanup: removed %d expired entries", cleaned)
	}
}

// cleanupMap removes expired entries from an IPv4 blocklist map
func (r *XDPRemediator) cleanupMap(m *ebpf.Map, now uint64) int {
	var key uint32
	var val blockEntry
	cleaned := 0

	iter := m.Iterate()
	for iter.Next(&key, &val) {
		// expires_ns = 0 means permanent (never expires)
		if val.ExpiresNs > 0 && now > val.ExpiresNs {
			if err := m.Delete(key); err == nil {
				cleaned++
			}
		}
	}

	return cleaned
}

// ListCurrentlyBlocked returns all non-expired IPs in the XDP blocklist BPF maps.
// It can be called on a running remediator (uses live maps) or without Setup()
// (opens pinned maps from /sys/fs/bpf/kerneleye) for the -list-blocked CLI flag.
func (r *XDPRemediator) cleanupMapV6(m *ebpf.Map, now uint64) int {
	var key [16]byte
	var val blockEntry
	cleaned := 0

	iter := m.Iterate()
	for iter.Next(&key, &val) {
		if val.ExpiresNs > 0 && now > val.ExpiresNs {
			if err := m.Delete(key); err == nil {
				cleaned++
			}
		}
	}

	return cleaned
}

// cleanupLPMMap removes expired entries from a CIDR blocklist map
func (r *XDPRemediator) cleanupLPMMap(m *ebpf.Map, now uint64) int {
	var key lpmKeyV4
	var val blockEntry
	cleaned := 0

	iter := m.Iterate()
	for iter.Next(&key, &val) {
		if val.ExpiresNs > 0 && now > val.ExpiresNs {
			if err := m.Delete(key); err == nil {
				cleaned++
			}
		}
	}

	return cleaned
}
