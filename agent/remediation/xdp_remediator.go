package remediation

import (
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

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
	OnBlock           BlockCallback // Called when an IP is blocked
}

// NewXDPRemediator creates a new XDP-based remediator
func NewXDPRemediator(interfaceName string) *XDPRemediator {
	return &XDPRemediator{
		interfaceName: interfaceName,
		mode:          XDPModeDRV,
		pinMaps:       true,
		pinPath:       DefaultXDPMapPinPath,
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
		mode:          XDPModeDRV,
		pinMaps:       cfg.PinMaps,
		pinPath:       pinPath,
	}
}

// Setup loads and attaches the XDP program
func (r *XDPRemediator) Setup() error {
	iface, err := net.InterfaceByName(r.interfaceName)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", r.interfaceName, err)
	}

	spec, err := ebpf.LoadCollectionSpec("ebpf/xdp_firewall_bpfel.o")
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
	}

	r.attached = true
	log.Printf("✅ XDP attached to %s (%s)", r.interfaceName, r.mode)
	return nil
}

// Block adds an IP to the XDP blocklist
func (r *XDPRemediator) Block(ip net.IP, duration time.Duration) error {
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

// SetRateLimit configures global rate limiting
func (r *XDPRemediator) SetRateLimit(maxPPS, maxBPS uint64, blockDuration time.Duration) error {
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

	// Clear existing state
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
	var val struct{}
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
	return nil
}

// Teardown detaches XDP
func (r *XDPRemediator) Teardown() error {
	r.cleanup()
	log.Printf("✅ XDP detached from %s", r.interfaceName)
	return nil
}

// GetStats returns packet statistics
func (r *XDPRemediator) GetStats() (XDPStats, error) {
	if !r.attached || r.objs == nil {
		return XDPStats{}, errNotAttached
	}
	return aggregateStats(r.objs.XdpStats), nil
}

// IsAttached returns attachment status
func (r *XDPRemediator) IsAttached() bool { return r.attached }

// Mode returns current XDP mode
func (r *XDPRemediator) Mode() XDPMode { return r.mode }

// Unblock removes IP from blocklist
func (r *XDPRemediator) Unblock(ip net.IP) error {
	if !r.attached {
		return errNotAttached
	}
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
	if r.xdpLink != nil {
		r.xdpLink.Close()
		r.xdpLink = nil
	}
	if r.objs != nil {
		r.unpinAndClose()
		r.objs = nil
	}
	r.attached = false
}

func (r *XDPRemediator) unpinAndClose() {
	maps := []*ebpf.Map{
		r.objs.XdpBlocklist, r.objs.XdpBlocklistV6, r.objs.XdpStats,
		r.objs.XdpCidrBlocklist, r.objs.XdpRateLimit, r.objs.XdpRateConfig,
	}
	for _, m := range maps {
		if m != nil {
			if r.pinMaps {
				m.Unpin()
			}
			m.Close()
		}
	}
	if r.objs.XdpFirewall != nil {
		r.objs.XdpFirewall.Close()
	}
}
