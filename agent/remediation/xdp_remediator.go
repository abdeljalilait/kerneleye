package remediation

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
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
	objectPath        string // Path to the eBPF object file
	OnBlock           BlockCallback // Called when an IP is blocked

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
		opts.Maps.PinPath = r.pinPath
	}

	if err := spec.LoadAndAssign(r.objs, opts); err != nil {
		return fmt.Errorf("failed to load XDP objects: %w", err)
	}

	// Try DRV mode first, fallback to SKB
	r.xdpLink, err = link.AttachXDP(link.XDPOptions{
		Program: r.objs.XdpFirewall, Interface: iface.Index, Flags: link.XDPDriverMode,
	})
	if err != nil {
		log.Printf("⚠️  XDP DRV failed: %v, trying SKB", err)
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
	log.Printf("✅ XDP attached to %s (%s)", r.interfaceName, r.mode)
	return nil
}

// loadXDPFirewallSpec loads the XDP program spec from the configured path.
// It checks the following in order:
// 1. Configured objectPath if set
// 2. KERNELEYE_XDP_PATH environment variable
// 3. DefaultXDPObjectPath
// 4. Relative path "ebpf/xdp_firewall_bpfel.o" (for development)
func (r *XDPRemediator) loadXDPFirewallSpec() (*ebpf.CollectionSpec, error) {
	// Determine path to use
	path := r.objectPath
	if path == "" {
		path = os.Getenv("KERNELEYE_XDP_PATH")
	}
	if path == "" {
		// Try default system path first
		if _, err := os.Stat(DefaultXDPObjectPath); err == nil {
			path = DefaultXDPObjectPath
		} else {
			// Fall back to relative path for development
			// Get the directory of the executable to make this more reliable
			if ex, err := os.Executable(); err == nil {
				// Try relative to executable directory
				execDir := filepath.Dir(ex)
				relPath := filepath.Join(execDir, "ebpf", "xdp_firewall_bpfel.o")
				if _, err := os.Stat(relPath); err == nil {
					path = relPath
				}
			}
		}
	}
	if path == "" {
		// Last resort: try current working directory relative path
		path = "ebpf/xdp_firewall_bpfel.o"
	}

	// Load from file
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load XDP spec from %s: %w", path, err)
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
	if err := validateIP(ip); err != nil {
		return err
	}
	if !isExternalIP(ip) {
		log.Printf("⚠️  XDP: Skipping non-external IP: %s", ip)
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
	} else {
		if err := blockIPv6(r.objs.XdpBlocklistV6, ip, expiresNs); err != nil {
			return fmt.Errorf("block IPv6: %w", err)
		}
	}
	log.Printf("🚫 XDP blocked %s for %v", ip, duration)
	if r.OnBlock != nil {
		r.OnBlock(ip, ActionBlock, "XDP_BLOCK", duration)
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
	log.Printf("🚫 XDP blocked CIDR %s for %v", cidr, duration)
	return nil
}

// rateLimitState mirrors the BPF struct for xdp_rate_limit map
type rateLimitState struct {
	WindowStart uint64 // Start of current window (ns since boot)
	PacketCount uint64 // Packets in current window
	ByteCount   uint64 // Bytes in current window
}

// SetRateLimit configures global rate limiting
func (r *XDPRemediator) SetRateLimit(maxPPS, maxBPS uint64, blockDuration time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.attached {
		return errNotAttached
	}
	if r.objs.XdpRateConfig == nil {
		return errRLDisabled
	}

	cfg := rateLimitConfig{maxPPS, maxBPS, uint64(blockDuration.Nanoseconds())}
	if err := r.objs.XdpRateConfig.Put(uint32(0), cfg); err != nil {
		return fmt.Errorf("set rate limit: %w", err)
	}

	// Clear existing state (holding mutex prevents races with Block/Unblock)
	if r.objs.XdpRateLimit != nil {
		r.clearRateLimitState()
	}
	log.Printf("⚡ XDP rate limit: %d PPS, %d BPS", maxPPS, maxBPS)
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
	log.Printf("⚠️  XDP: Per-IP rate limiting not supported for %s", ip)
	// Return error instead of silently succeeding
	return fmt.Errorf("%w: XDP does not support per-IP rate limiting, use IPSetRemediator", errRLDisabled)
}

// Teardown detaches XDP
func (r *XDPRemediator) Teardown() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	wasAttached := r.attached
	var errs []error

	// Capture any errors from cleanup
	if err := r.cleanupWithErrors(); err != nil {
		errs = append(errs, err)
	}

	if wasAttached {
		log.Printf("✅ XDP detached from %s", r.interfaceName)
	} else {
		log.Printf("ℹ️  XDP was not attached to %s", r.interfaceName)
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

// Unblock removes IP from blocklist
func (r *XDPRemediator) Unblock(ip net.IP) error {
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
	} else {
		if err := unblockIPv6(r.objs.XdpBlocklistV6, ip); err != nil {
			return err
		}
	}
	log.Printf("✅ XDP unblocked %s", ip)
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
	log.Printf("✅ XDP unblocked CIDR %s", cidr)
	return nil
}

func (r *XDPRemediator) cleanup() {
	_ = r.cleanupWithErrors()
}

func (r *XDPRemediator) cleanupWithErrors() error {
	var errs []error

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
