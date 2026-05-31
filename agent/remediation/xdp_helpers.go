package remediation

//go:generate clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c ../ebpf/xdp_firewall.c -o ../ebpf/xdp_firewall_bpfel.o -I/usr/include/bpf

import (
	"encoding/binary"
	"errors"
	"net"
	"runtime"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// XDPMode represents XDP attach modes
type XDPMode int

const (
	XDPModeDRV     XDPMode = iota // Native driver mode (fastest)
	XDPModeSKB                    // Generic/SKB mode (slower)
	XDPModeOffload                // Hardware offload
)

// DefaultXDPMapPinPath is the default pin path for BPF maps
const DefaultXDPMapPinPath = "/sys/fs/bpf/kerneleye"

func (m XDPMode) String() string {
	switch m {
	case XDPModeDRV:
		return "DRV (native)"
	case XDPModeSKB:
		return "SKB (generic)"
	case XDPModeOffload:
		return "Offload (hardware)"
	default:
		return "Unknown"
	}
}

// XDPStats holds packet statistics
type XDPStats struct {
	PassedPackets, PassedBytes       uint64
	DroppedPackets, DroppedBytes     uint64
	ErrorPackets, ErrorBytes         uint64
	RateLimitPackets, RateLimitBytes uint64
}

// blockEntry mirrors the BPF struct
type blockEntry struct{ ExpiresNs uint64 }

// xdpStatsEntry mirrors the BPF struct
type xdpStatsEntry struct{ Packets, Bytes uint64 }

// rateLimitConfig mirrors the BPF struct
type rateLimitConfig struct{ MaxPPS, MaxBPS, BlockTimeNs uint64 }

// lpmKeyV4 for CIDR keys
type lpmKeyV4 struct {
	PrefixLen uint32
	Addr      uint32
}

// xdpObjects holds loaded BPF objects
type xdpObjects struct {
	XdpFirewall      *ebpf.Program `ebpf:"xdp_firewall"`
	XdpBlocklist     *ebpf.Map     `ebpf:"xdp_blocklist"`
	XdpBlocklistV6   *ebpf.Map     `ebpf:"xdp_blocklist_v6"`
	XdpStats         *ebpf.Map     `ebpf:"xdp_stats"`
	XdpCidrBlocklist *ebpf.Map     `ebpf:"xdp_cidr_blocklist"`
	XdpRateLimit     *ebpf.Map     `ebpf:"xdp_rate_limit"`
	XdpRateConfig    *ebpf.Map     `ebpf:"xdp_rate_config"`
	XdpBlockEvents   *ebpf.Map     `ebpf:"xdp_block_events"`
}

// MapStateSnapshot captures the identity and integrity state of a loaded eBPF map.
type MapStateSnapshot struct {
	Name        string          // Map name (e.g., "xdp_blocklist")
	MapID       ebpf.MapID      // Kernel BPF map ID (from MapInfo.ID())
	PinnedPath  string          // Expected pinned path
	Frozen      bool            // True if Map.Freeze() was called
	TrustLevel  MapTrustLevel   // Sensitivity classification
	ContentHash string          // SHA-256 of all entries (blank for Low trust maps)
	EntryCount  int             // Number of entries at snapshot time
	CapturedAt  time.Time       // When the snapshot was taken
}

// WriteAuditEntry records a single write operation to a high-trust map.
type WriteAuditEntry struct {
	MapName        string
	Action         string // "insert", "delete", "update"
	Key            string
	Source         string // "backend_command", "local_auto_block", "manual"
	SignatureValid bool
	Timestamp      time.Time
}

// XDPConfig options for XDP remediator
type XDPConfig struct {
	InterfaceName string
	PinMaps       bool
	PinPath       string
	ObjectPath    string // Path to xdp_firewall_bpfel.o (optional, auto-detected if empty)
}

// aggregateStats reads per-CPU stats and aggregates them
func aggregateStats(statsMap *ebpf.Map) XDPStats {
	var stats XDPStats
	if statsMap == nil {
		return stats
	}
	numCPUs := runtime.NumCPU()
	for idx := uint32(0); idx < 4; idx++ {
		values := make([]xdpStatsEntry, numCPUs)
		if err := statsMap.Lookup(idx, &values); err != nil {
			continue
		}
		for _, v := range values {
			switch idx {
			case 0:
				stats.PassedPackets += v.Packets
				stats.PassedBytes += v.Bytes
			case 1:
				stats.DroppedPackets += v.Packets
				stats.DroppedBytes += v.Bytes
			case 2:
				stats.ErrorPackets += v.Packets
				stats.ErrorBytes += v.Bytes
			case 3:
				stats.RateLimitPackets += v.Packets
				stats.RateLimitBytes += v.Bytes
			}
		}
	}
	return stats
}

// monotonicNs returns nanoseconds since boot (aligns with bpf_ktime_get_ns)
func monotonicNs() int64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		logger.Warnf("⚠️  Failed to get boot time: %v", err)
		return time.Now().UnixNano()
	}
	return ts.Nano()
}

// isNotExist checks if error indicates key doesn't exist
func isNotExist(err error) bool {
	if err == nil {
		return false
	}
	// Check for the wrapped error first
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return true
	}
	// Also check for common error string patterns (for compatibility)
	errStr := err.Error()
	return strings.Contains(errStr, "key does not exist") || strings.Contains(errStr, "no such file")
}

// isExternalIP checks if IP is external (not private/loopback/link-local)
func isExternalIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		return !ip4.IsPrivate()
	}
	ip6 := ip.To16()
	if ip6 == nil {
		return false
	}
	// ULA (fc00::/7) or multicast (ff00::/8)
	if ip6[0]&0xfe == 0xfc || ip6[0] == 0xff {
		return false
	}
	return true
}

// validateIP checks if IP is valid
func validateIP(ip net.IP) error {
	if len(ip) == 0 {
		return errInvalidIP
	}
	return nil
}

// blockIPv4 adds IPv4 to blocklist
func blockIPv4(m *ebpf.Map, ip net.IP, expiresNs uint64) error {
	if m == nil {
		return errMapNotLoaded
	}
	// Use BigEndian to create the integer value that matches the
	// network-byte-order integer (ip->saddr) used by the BPF program.
	key := binary.BigEndian.Uint32(ip.To4())
	return m.Put(key, blockEntry{ExpiresNs: expiresNs})
}

// blockIPv6 adds IPv6 to blocklist
func blockIPv6(m *ebpf.Map, ip net.IP, expiresNs uint64) error {
	if m == nil {
		return errMapNotLoaded
	}
	var key [16]byte
	copy(key[:], ip.To16())
	return m.Put(key, blockEntry{ExpiresNs: expiresNs})
}

// unblockIPv4 removes IPv4 from blocklist
func unblockIPv4(m *ebpf.Map, ip net.IP) error {
	if m == nil {
		return errMapNotLoaded
	}
	key := binary.BigEndian.Uint32(ip.To4())
	if err := m.Delete(key); err != nil && !isNotExist(err) {
		return err
	}
	return nil
}

// unblockIPv6 removes IPv6 from blocklist
func unblockIPv6(m *ebpf.Map, ip net.IP) error {
	if m == nil {
		return errMapNotLoaded
	}
	var key [16]byte
	copy(key[:], ip.To16())
	if err := m.Delete(key); err != nil && !isNotExist(err) {
		return err
	}
	return nil
}

// parseCIDRv4 parses CIDR and returns masked LPM key
func parseCIDRv4(cidr string) (lpmKeyV4, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return lpmKeyV4{}, err
	}
	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return lpmKeyV4{}, errIPv4Only
	}
	prefixLen, _ := ipNet.Mask.Size()
	maskedIP := ipNet.IP.Mask(ipNet.Mask).To4()

	// Convert to native endian (BigEndian used to match proper integer value)
	addr := binary.BigEndian.Uint32(maskedIP)

	return lpmKeyV4{
		PrefixLen: uint32(prefixLen),
		Addr:      addr,
	}, nil
}
