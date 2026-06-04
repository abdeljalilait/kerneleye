package remediation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"time"

	"github.com/cilium/ebpf"
)

// Map identity and integrity verification for the XDP firewall.
// Captures map ID, content hash, and frozen status at load time,
// then periodically verifies maps haven't been tampered with.
// All writes to high-trust maps are audited.

func (r *XDPRemediator) captureMapSnapshots() {
	maps := []struct {
		m    *ebpf.Map
		name string
	}{
		{r.objs.XdpBlocklist, "xdp_blocklist"},
		{r.objs.XdpBlocklistV6, "xdp_blocklist_v6"},
		{r.objs.XdpStats, "xdp_stats"},
		{r.objs.XdpCidrBlocklist, "xdp_cidr_blocklist"},
		{r.objs.XdpRateLimit, "xdp_rate_limit"},
		{r.objs.XdpRateConfig, "xdp_rate_config"},
		{r.objs.XdpBlockEvents, "xdp_block_events"},
	}

	r.mapSnapshots = make(map[string]*MapStateSnapshot)

	for _, entry := range maps {
		if entry.m == nil {
			continue
		}
		info, err := entry.m.Info()
		if err != nil {
			logger.Warnf("Failed to get map info for %s: %v", entry.name, err)
			continue
		}

		cls, _ := MapClassificationByName(entry.name)
		mapID, hasID := info.ID()
		if !hasID {
			mapID = 0
		}
		snap := &MapStateSnapshot{
			Name:       entry.name,
			MapID:      mapID,
			PinnedPath: filepath.Join(r.pinPath, entry.name),
			Frozen:     info.Frozen(),
			TrustLevel: cls.TrustLevel,
			CapturedAt: time.Now(),
		}

		// Compute content hash for High/VeryHigh maps
		if cls.TrustLevel >= TrustLevelHigh {
			snap.ContentHash, snap.EntryCount = hashMapContents(entry.m)
		}

	r.mapSnapshots[entry.name] = snap
	// Only slice ContentHash when long enough (can be empty for low-trust maps)
	hashPreview := "<no-hash>"
	if len(snap.ContentHash) >= 12 {
		hashPreview = snap.ContentHash[:12] + "..."
	}
	logger.Debugf("Map snapshot: %s id=%d frozen=%v trust=%s entries=%d hash=%s",
		snap.Name, snap.MapID, snap.Frozen, snap.TrustLevel, snap.EntryCount,
		hashPreview)
	}
}

// hashMapContents computes a deterministic SHA-256 hash of all entries in a map.
func hashMapContents(m *ebpf.Map) (hash string, count int) {
	h := sha256.New()
	iter := m.Iterate()
	var key, val []byte

	// Collect and sort keys for deterministic hashing
	type entry struct {
		key []byte
		val []byte
	}
	var entries []entry
	for iter.Next(&key, &val) {
		k := make([]byte, len(key))
		v := make([]byte, len(val))
		copy(k, key)
		copy(v, val)
		entries = append(entries, entry{k, v})
	}
	if err := iter.Err(); err != nil {
		logger.Warnf("Map iteration error for %s: %v", m.String(), err)
		return "", 0
	}

	// Sort by key for deterministic output
	sort.Slice(entries, func(i, j int) bool {
		return bytes.Compare(entries[i].key, entries[j].key) < 0
	})

	for _, e := range entries {
		h.Write(e.key)
		h.Write(e.val)
	}

	return hex.EncodeToString(h.Sum(nil)), len(entries)
}

// GetMapSnapshots returns the load-time map identity snapshots for integrity verification.
func (r *XDPRemediator) GetMapSnapshots() map[string]*MapStateSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.mapSnapshots
}

// VerifyMapSnapshot compares the current state of a pinned map against its load-time snapshot.
// Returns warnings if the map ID, frozen status, or content hash has changed unexpectedly.
func VerifyMapSnapshot(name string, snap *MapStateSnapshot) (warnings []string) {
	pinnedPath := snap.PinnedPath

	// Open pinned map read-only for verification
	m, err := ebpf.LoadPinnedMap(pinnedPath, &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		if snap.TrustLevel >= TrustLevelHigh {
			warnings = append(warnings,
				fmt.Sprintf("map %s: pinned file %s not accessible — possible tampering: %v", name, pinnedPath, err))
		}
		return
	}
	defer m.Close()

	info, err := m.Info()
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("map %s: cannot get info: %v", name, err))
		return
	}

	// Check map ID unchanged (detect replacement)
	currentID, hasID := info.ID()
	if hasID && snap.MapID != 0 && currentID != snap.MapID {
		warnings = append(warnings,
			fmt.Sprintf("map %s: ID changed %d → %d — map was replaced", name, snap.MapID, currentID))
	}

	// Check frozen status matches expectation.
	// Skip the warning if the map is empty (unconfigured) — an empty map that
	// has never been written to is not a security violation.
	cls, _ := MapClassificationByName(name)
	if cls.Frozen && !info.Frozen() && snap.EntryCount > 0 {
		warnings = append(warnings,
			fmt.Sprintf("map %s: classified as frozen but BPF_MAP_FREEZE not applied", name))
	}

	// For frozen maps, verify content hash (immutable maps should never change).
	// Skip for non-frozen dynamic maps (e.g., blocklists) — legitimate Block/Unblock
	// operations naturally change their contents, so hash comparison is meaningless.
	if snap.Frozen && snap.ContentHash != "" {
		currentHash, _ := hashMapContents(m)
		if currentHash != snap.ContentHash {
			warnings = append(warnings,
				fmt.Sprintf("map %s: content hash changed — integrity violation suspected: unexpected writer detected", name))
		}
	}

	return warnings
}

// auditMapWrite logs a write operation to a high-trust map.
func auditMapWrite(mapName, action, key, source string, signatureValid bool) {
	entry := WriteAuditEntry{
		MapName:        mapName,
		Action:         action,
		Key:            key,
		Source:         source,
		SignatureValid: signatureValid,
		Timestamp:      time.Now(),
	}
	data, _ := json.Marshal(entry)
	logger.Infof("[AUDIT] map_write %s", string(data))
}

// loadXDPFirewallSpec loads the XDP program spec.
// It checks the following in order:
// 1. Configured objectPath if set
// 2. KERNELEYE_XDP_PATH environment variable
// 3. DefaultXDPObjectPath
// 4. Relative to executable directory
