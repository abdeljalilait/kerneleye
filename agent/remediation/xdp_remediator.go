package remediation

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/kerneleye/agent/assets"
)

// DefaultXDPObjectPath is the default path to the XDP eBPF object file.
// This can be overridden via XDPConfig or by setting KERNELEYE_XDP_PATH env var.
const DefaultXDPObjectPath = "/usr/local/lib/kerneleye/xdp_firewall_bpfel.o"

var (
	errNotAttached  = errors.New("XDP not attached")
	errInvalidIP    = errors.New("invalid IP")
	errMapNotLoaded = errors.New("map not loaded")
	errIPv4Only     = errors.New("only IPv4 CIDR supported")
	errCIDRDisabled = errors.New("CIDR blocking not enabled")
	errRLDisabled   = errors.New("rate limiting not enabled")
)

// XDPRemediator implements Remediator using XDP for fast-path blocking
type XDPRemediator struct {
	interfaceName     string
	mode              XDPMode
	objs              *xdpObjects
	xdpLink           link.Link
	attached, pinMaps bool
	pinPath           string
	objectPath        string                // Path to the eBPF object file
	OnBlock           BlockCallback         // Called when an IP is blocked
	OnBlockedPacket   BlockedPacketCallback // Called when XDP logs a blocked packet

	mapSnapshots map[string]*MapStateSnapshot // Load-time map identity snapshots

	ringbufReader *ringbuf.Reader
	ringbufCancel chan struct{}
	ringbufWg     sync.WaitGroup

	cleanupEnabled  bool
	cleanupInterval time.Duration
	cleanupCancel   chan struct{}
	cleanupWg       sync.WaitGroup

	mu sync.RWMutex // Protects all mutable fields
}

// NewXDPRemediator creates a new XDP-based remediator
func NewXDPRemediator(interfaceName string) *XDPRemediator {
	return &XDPRemediator{
		interfaceName: interfaceName,
		pinMaps:       true,
		pinPath:       DefaultXDPMapPinPath,
		objectPath:    "", // Will be auto-detected
	}
}

// NewXDPRemediatorWithConfig creates a remediator with custom config
func NewXDPRemediatorWithConfig(cfg XDPConfig) *XDPRemediator {
	pinPath := cfg.PinPath
	if pinPath == "" {
		pinPath = DefaultXDPMapPinPath
	}
	return &XDPRemediator{
		interfaceName: cfg.InterfaceName,
		pinMaps:       cfg.PinMaps,
		pinPath:       pinPath,
		objectPath:    cfg.ObjectPath,
	}
}

// Setup loads and attaches the XDP program
func (r *XDPRemediator) Setup() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	iface, err := net.InterfaceByName(r.interfaceName)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", r.interfaceName, err)
	}

	// Use embedded binary instead of relative path
	spec, err := r.loadXDPFirewallSpec()
	if err != nil {
		return fmt.Errorf("failed to load XDP spec: %w", err)
	}

	r.objs = &xdpObjects{}
	opts := &ebpf.CollectionOptions{}
	if r.pinMaps {
		if err := os.MkdirAll(r.pinPath, 0755); err != nil {
			return fmt.Errorf("failed to create BPF pin path %s: %w", r.pinPath, err)
		}
		opts.Maps.PinPath = r.pinPath
	}

	if err := spec.LoadAndAssign(r.objs, opts); err != nil {
		return fmt.Errorf("failed to load XDP objects: %w", err)
	}

	// Capture map identity snapshots for later integrity verification
	r.captureMapSnapshots()

	// Try DRV mode first, fallback to SKB
	r.xdpLink, err = link.AttachXDP(link.XDPOptions{
		Program: r.objs.XdpFirewall, Interface: iface.Index, Flags: link.XDPDriverMode,
	})
	if err != nil {
		logger.Warnf("⚠️  XDP DRV failed: %v, trying SKB", err)
		r.mode = XDPModeSKB
		r.xdpLink, err = link.AttachXDP(link.XDPOptions{
			Program: r.objs.XdpFirewall, Interface: iface.Index, Flags: link.XDPGenericMode,
		})
		if err != nil {
			r.cleanup()
			return fmt.Errorf("XDP attach failed: %w", err)
		}
	} else {
		r.mode = XDPModeDRV
	}

	r.attached = true
	logger.Infof("✅ XDP attached to %s (%s)", r.interfaceName, r.mode)
	return nil
}

// captureMapSnapshots records the identity of all loaded maps for later
// integrity verification. Takes snapshots of map IDs, content hashes, and
// metadata right after LoadAndAssign succeeds.
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
			snap.ContentHash, snap.EntryCount = r.hashMapContents(entry.m)
		}

		r.mapSnapshots[entry.name] = snap
		logger.Debugf("Map snapshot: %s id=%d frozen=%v trust=%s entries=%d hash=%s",
			snap.Name, snap.MapID, snap.Frozen, snap.TrustLevel, snap.EntryCount,
			snap.ContentHash[:12]+"...")
	}
}

// hashMapContents computes a deterministic SHA-256 hash of all entries in a map.
func (r *XDPRemediator) hashMapContents(m *ebpf.Map) (hash string, count int) {
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

// verifyMapSnapshot compares the current state of a pinned map against its load-time snapshot.
// Returns warnings if the map ID, frozen status, or content hash has changed unexpectedly.
func (r *XDPRemediator) verifyMapSnapshot(name string, snap *MapStateSnapshot) (warnings []string) {
	pinnedPath := filepath.Join(r.pinPath, name)

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

	// Check frozen status matches expectation
	cls, _ := MapClassificationByName(name)
	if cls.Frozen && !info.Frozen() {
		warnings = append(warnings,
			fmt.Sprintf("map %s: classified as frozen but BPF_MAP_FREEZE not applied", name))
	}

	// For High/VeryHigh maps, verify content hash
	if snap.TrustLevel >= TrustLevelHigh && snap.ContentHash != "" {
		currentHash, _ := r.hashMapContents(m)
		if currentHash != snap.ContentHash {
			warnings = append(warnings,
				fmt.Sprintf("map %s: content hash changed — integrity violation suspected: unexpected writer detected", name))
		}
	}

	return warnings
}

// auditMapWrite logs a write operation to a high-trust map.
func auditMapWrite(r *XDPRemediator, mapName, action, key, source string, signatureValid bool) {
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
// 5. Embedded binary (fallback - always available)
func (r *XDPRemediator) loadXDPFirewallSpec() (*ebpf.CollectionSpec, error) {
	// Try to load from file system first (allows custom/user-provided objects)
	path := r.objectPath
	if path == "" {
		path = os.Getenv("KERNELEYE_XDP_PATH")
	}
	if path == "" {
		// Try default system path
		if _, err := os.Stat(DefaultXDPObjectPath); err == nil {
			path = DefaultXDPObjectPath
		}
	}
	if path == "" {
		// Try relative to executable directory
		if ex, err := os.Executable(); err == nil {
			execDir := filepath.Dir(ex)
			relPath := filepath.Join(execDir, "ebpf", "xdp_firewall_bpfel.o")
			if _, err := os.Stat(relPath); err == nil {
				path = relPath
			}
		}
	}

	// If we found a file path, try to load from it
	if path != "" {
		if spec, err := ebpf.LoadCollectionSpec(path); err == nil {
			return spec, nil
		} else if r.objectPath != "" || os.Getenv("KERNELEYE_XDP_PATH") != "" {
			// Only error if user explicitly specified a path that failed
			return nil, fmt.Errorf("failed to load XDP spec from %s: %w", path, err)
		}
		// Otherwise, fall through to embedded
	}

	// Load from embedded bytes (always available)
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(assets.XDPFirewallBpfelO))
	if err != nil {
		return nil, fmt.Errorf("failed to load XDP spec from embedded data: %w", err)
	}
	return spec, nil
}

// Block adds an IP to the XDP blocklist
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
		auditMapWrite(r, "xdp_blocklist", "insert", ip.String(), "block_command", false)
	} else {
		if err := blockIPv6(r.objs.XdpBlocklistV6, ip, expiresNs); err != nil {
			return fmt.Errorf("block IPv6: %w", err)
		}
		auditMapWrite(r, "xdp_blocklist_v6", "insert", ip.String(), "block_command", false)
	}

	// Notify callback if set
	if r.OnBlock != nil {
		r.OnBlock(ip, ActionBlock, "manual", duration)
	}

	return nil
}

// BlockCIDR adds a CIDR range to the blocklist
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
// calls to SetRateLimit no-ops (rate limit config is immutable after init).
func (r *XDPRemediator) SetRateLimit(maxPPS, maxBPS uint64, blockDuration time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.attached {
		return errNotAttached
	}
	if r.objs.XdpRateConfig == nil {
		return errRLDisabled
	}

	// Check if map is already frozen (irreversible)
	if info, err := r.objs.XdpRateConfig.Info(); err == nil && info != nil {
		if info.Frozen() {
			logger.Warn("xdp_rate_config is frozen — rate limit cannot be changed without restart")
			return nil
		}
	}

	cfg := rateLimitConfig{maxPPS, maxBPS, uint64(blockDuration.Nanoseconds())}
	if err := r.objs.XdpRateConfig.Put(uint32(0), cfg); err != nil {
		return fmt.Errorf("set rate limit: %w", err)
	}

	// Freeze the map — irreversible, prevents future userspace writes
	if err := r.objs.XdpRateConfig.Freeze(); err != nil {
		logger.Warnf("Failed to freeze xdp_rate_config (kernel may not support BPF_MAP_FREEZE): %v", err)
	} else {
		logger.Infof("🔒 Frozen xdp_rate_config — rate limit config is now immutable")
	}
	auditMapWrite(r, "xdp_rate_config", "update", "rate_config", "local_setup", true)

	// Clear existing state (holding mutex prevents races with Block/Unblock)
	if r.objs.XdpRateLimit != nil {
		r.clearRateLimitState()
	}
	logger.Infof("⚡ XDP rate limit: %d PPS, %d BPS", maxPPS, maxBPS)
	return nil
}

func (r *XDPRemediator) clearRateLimitState() {
	if r.objs.XdpRateLimit == nil {
		return
	}
	var key uint32
	var val rateLimitState // Use correct value type instead of empty struct
	iter := r.objs.XdpRateLimit.Iterate()
	keys := make([]uint32, 0, 1000)
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		r.objs.XdpRateLimit.Delete(k)
	}
}

// RateLimit per-IP - not supported, use iptables
func (r *XDPRemediator) RateLimit(ip net.IP, duration time.Duration) error {
	logger.Warnf("⚠️  XDP: Per-IP rate limiting not supported for %s", ip)
	// Return error instead of silently succeeding
	return fmt.Errorf("%w: XDP does not support per-IP rate limiting, use IPSetRemediator", errRLDisabled)
}

// Teardown detaches XDP
func (r *XDPRemediator) Teardown() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	wasAttached := r.attached
	var errs []error

	// Stop cleanup goroutine
	if r.cleanupEnabled {
		close(r.cleanupCancel)
		r.cleanupWg.Wait()
		r.cleanupEnabled = false
	}

	// Cleanup XDP resources
	if err := r.cleanupWithErrors(); err != nil {
		errs = append(errs, err)
	}

	if wasAttached {
		logger.Infof("✅ XDP detached from %s", r.interfaceName)
	} else {
		logger.Info("ℹ️  XDP was not attached to %s", r.interfaceName)
	}

	if len(errs) > 0 {
		return fmt.Errorf("XDP teardown completed with errors: %v", errors.Join(errs...))
	}
	return nil
}

// GetStats returns packet statistics
func (r *XDPRemediator) GetStats() (XDPStats, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if !r.attached || r.objs == nil {
		return XDPStats{}, errNotAttached
	}
	return aggregateStats(r.objs.XdpStats), nil
}

// IsAttached returns attachment status
func (r *XDPRemediator) IsAttached() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.attached
}

// Mode returns current XDP mode
func (r *XDPRemediator) Mode() XDPMode {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.mode
}

// StartBlockedPacketReader starts reading blocked packet events from the ring buffer
// This should be called after Setup() and will call the OnBlockedPacket callback for each event
func (r *XDPRemediator) StartBlockedPacketReader() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.attached || r.objs == nil || r.objs.XdpBlockEvents == nil {
		return errNotAttached
	}

	if r.ringbufReader != nil {
		return nil // Already started
	}

	reader, err := ringbuf.NewReader(r.objs.XdpBlockEvents)
	if err != nil {
		return fmt.Errorf("failed to create ring buffer reader: %w", err)
	}

	r.ringbufReader = reader
	r.ringbufCancel = make(chan struct{})
	r.ringbufWg.Add(1)

	go r.readBlockedPackets()

	logger.Infof("✅ XDP blocked packet reader started")
	return nil
}

// StopBlockedPacketReader stops the ring buffer reader
func (r *XDPRemediator) StopBlockedPacketReader() error {
	r.mu.Lock()
	if r.ringbufReader == nil {
		r.mu.Unlock()
		return nil
	}

	close(r.ringbufCancel)
	reader := r.ringbufReader
	r.ringbufReader = nil
	r.mu.Unlock()

	// Close the reader to unblock any pending Read() call
	if err := reader.Close(); err != nil {
		logger.Warnf("Failed to close ring buffer reader: %v", err)
	}

	// Wait for the goroutine to finish
	r.ringbufWg.Wait()

	logger.Infof("✅ XDP blocked packet reader stopped")
	return nil
}

// readBlockedPackets is the goroutine that reads from the ring buffer
func (r *XDPRemediator) readBlockedPackets() {
	defer r.ringbufWg.Done()

	for {
		select {
		case <-r.ringbufCancel:
			return
		default:
		}

		record, err := r.ringbufReader.Read()
		if err != nil {
			select {
			case <-r.ringbufCancel:
				return
			default:
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				logger.Warnf("Ring buffer read error: %v", err)
				continue
			}
		}

		// Parse the blocked packet event
		if len(record.RawSample) < 32 {
			continue // Invalid sample size
		}

		var event BlockedPacketEvent
		// Parse the event from the ring buffer
		// C struct layout: src_ip (4), src_ip6 (16), ip_version (1), dest_port (2), protocol (1), reason (1), timestamp (8)
		event.SrcIP = binary.LittleEndian.Uint32(record.RawSample[0:4])
		copy(event.SrcIP6[:], record.RawSample[4:20])
		event.IPVersion = record.RawSample[20]
		event.DestPort = binary.LittleEndian.Uint16(record.RawSample[21:23])
		event.Protocol = record.RawSample[23]
		event.Reason = record.RawSample[24]
		event.Timestamp = binary.LittleEndian.Uint64(record.RawSample[25:33])

		// Convert IP to string
		var ipStr string
		if event.IPVersion == 6 {
			ip := net.IP(event.SrcIP6[:])
			ipStr = ip.String()
		} else {
			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, event.SrcIP)
			ipStr = ip.String()
		}

		// Call the callback if set
		if r.OnBlockedPacket != nil {
			r.OnBlockedPacket(ipStr, event.DestPort, event.Protocol, event.Reason)
		}
	}
}

// Unblock removes IP from blocklist
// Note: blockType is ignored since XDP uses a single blocklist for all types
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
		auditMapWrite(r, "xdp_blocklist", "delete", ip.String(), "block_command", false)
	} else {
		if err := unblockIPv6(r.objs.XdpBlocklistV6, ip); err != nil {
			return err
		}
		auditMapWrite(r, "xdp_blocklist_v6", "delete", ip.String(), "block_command", false)
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
	auditMapWrite(r, "xdp_cidr_blocklist", "delete", cidr, "block_command", false)
	logger.Infof("✅ XDP unblocked CIDR %s", cidr)
	return nil
}

func (r *XDPRemediator) cleanup() {
	_ = r.cleanupWithErrors()
}

func (r *XDPRemediator) cleanupWithErrors() error {
	var errs []error

	// Stop the ring buffer reader first
	if r.ringbufReader != nil {
		if err := r.StopBlockedPacketReader(); err != nil {
			errs = append(errs, fmt.Errorf("failed to stop ring buffer reader: %w", err))
		}
	}

	if r.xdpLink != nil {
		if err := r.xdpLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close XDP link: %w", err))
		}
		r.xdpLink = nil
	}
	if r.objs != nil {
		if err := r.unpinAndClose(); err != nil {
			errs = append(errs, err)
		}
		r.objs = nil
	}
	r.attached = false

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (r *XDPRemediator) unpinAndClose() error {
	var errs []error

	maps := []*ebpf.Map{
		r.objs.XdpBlocklist, r.objs.XdpBlocklistV6, r.objs.XdpStats,
		r.objs.XdpCidrBlocklist, r.objs.XdpRateLimit, r.objs.XdpRateConfig,
	}
	for _, m := range maps {
		if m != nil {
			if r.pinMaps {
				if err := m.Unpin(); err != nil {
					errs = append(errs, fmt.Errorf("failed to unpin map: %w", err))
				}
			}
			if err := m.Close(); err != nil {
				errs = append(errs, fmt.Errorf("failed to close map: %w", err))
			}
		}
	}
	if r.objs.XdpBlockEvents != nil {
		if err := r.objs.XdpBlockEvents.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close block events map: %w", err))
		}
	}
	if r.objs.XdpFirewall != nil {
		if err := r.objs.XdpFirewall.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close XDP program: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %w", errors.Join(errs...))
	}
	return nil
}

// StartCleanup starts a goroutine that periodically removes expired entries from XDP maps
// This is optional - call after Setup() if you want automatic cleanup of expired blocks
func (r *XDPRemediator) StartCleanup(interval time.Duration) {
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
func (r *XDPRemediator) ListCurrentlyBlocked() ([]BlockedEntry, error) {
	v4Map, v6Map, cleanup, err := r.openBlocklistMaps()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	now := uint64(monotonicNs())
	var entries []BlockedEntry

	// IPv4 — key is BigEndian uint32, value is blockEntry
	var k4 uint32
	var v4val blockEntry
	iter4 := v4Map.Iterate()
	for iter4.Next(&k4, &v4val) {
		if v4val.ExpiresNs != 0 && v4val.ExpiresNs < now {
			continue // expired
		}
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, k4)
		entries = append(entries, BlockedEntry{
			IP:        net.IP(b),
			BlockType: BlockTypeBlocklist,
			Version:   4,
		})
	}
	if err := iter4.Err(); err != nil {
		return nil, fmt.Errorf("iterating xdp_blocklist: %w", err)
	}

	// IPv6 — key is [16]byte, value is blockEntry
	var k6 [16]byte
	var v6val blockEntry
	iter6 := v6Map.Iterate()
	for iter6.Next(&k6, &v6val) {
		if v6val.ExpiresNs != 0 && v6val.ExpiresNs < now {
			continue // expired
		}
		ip := make(net.IP, 16)
		copy(ip, k6[:])
		entries = append(entries, BlockedEntry{
			IP:        ip,
			BlockType: BlockTypeBlocklist,
			Version:   6,
		})
	}
	if err := iter6.Err(); err != nil {
		return nil, fmt.Errorf("iterating xdp_blocklist_v6: %w", err)
	}

	return entries, nil
}

// FlushBlocklistMaps removes all entries from the XDP blocklist BPF maps.
// Works both on a live (attached) remediator and standalone (opens pinned maps
// from /sys/fs/bpf/kerneleye). This is what --flush-blocklists uses.
func (r *XDPRemediator) FlushBlocklistMaps() error {
	v4Map, v6Map, cleanup, err := r.openBlocklistMaps()
	if err != nil {
		return fmt.Errorf("open XDP blocklist maps: %w", err)
	}
	defer cleanup()

	// Collect then delete — cannot delete while iterating.
	var v4Keys []uint32
	var k4 uint32
	var v4val blockEntry
	iter4 := v4Map.Iterate()
	for iter4.Next(&k4, &v4val) {
		v4Keys = append(v4Keys, k4)
	}
	if err := iter4.Err(); err != nil {
		return fmt.Errorf("iterating xdp_blocklist: %w", err)
	}
	for _, k := range v4Keys {
		_ = v4Map.Delete(k)
	}

	var v6Keys [][16]byte
	var k6 [16]byte
	var v6val blockEntry
	iter6 := v6Map.Iterate()
	for iter6.Next(&k6, &v6val) {
		v6Keys = append(v6Keys, k6)
	}
	if err := iter6.Err(); err != nil {
		return fmt.Errorf("iterating xdp_blocklist_v6: %w", err)
	}
	for _, k := range v6Keys {
		_ = v6Map.Delete(k)
	}

	logger.Infof("🧹 XDP blocklist flushed (%d IPv4, %d IPv6 entries removed)",
		len(v4Keys), len(v6Keys))
	return nil
}

// openBlocklistMaps returns references to xdp_blocklist and xdp_blocklist_v6.
// If the remediator is attached and live, the existing map handles are returned
// directly (no-op cleanup). Otherwise, the pinned maps are opened from the BPF
// filesystem and the caller must call cleanup() to close them.
func (r *XDPRemediator) openBlocklistMaps() (v4Map, v6Map *ebpf.Map, cleanup func(), err error) {
	r.mu.RLock()
	if r.attached && r.objs != nil {
		v4 := r.objs.XdpBlocklist
		v6 := r.objs.XdpBlocklistV6
		r.mu.RUnlock()
		return v4, v6, func() {}, nil
	}
	pinPath := r.pinPath
	r.mu.RUnlock()

	readOnly := &ebpf.LoadPinOptions{ReadOnly: true}
	v4, err2 := ebpf.LoadPinnedMap(filepath.Join(pinPath, "xdp_blocklist"), readOnly)
	if err2 != nil {
		return nil, nil, func() {}, fmt.Errorf("open pinned xdp_blocklist: %w", err2)
	}
	v6, err2 := ebpf.LoadPinnedMap(filepath.Join(pinPath, "xdp_blocklist_v6"), readOnly)
	if err2 != nil {
		v4.Close()
		return nil, nil, func() {}, fmt.Errorf("open pinned xdp_blocklist_v6: %w", err2)
	}
	return v4, v6, func() { v4.Close(); v6.Close() }, nil
}

// cleanupMapV6 removes expired entries from an IPv6 blocklist map
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
