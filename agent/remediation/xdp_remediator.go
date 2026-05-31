package remediation

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
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
// calls to SetRateLimit no-ops (rate limit config is immutable after init).
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
// Note: blockType is ignored since XDP uses a single blocklist for all types

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
