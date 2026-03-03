package main

import (
	"sync"
	"time"
)

// Event matches the C struct event_t in traffic_probe.c (84 bytes)
// C struct layout:
//   - saddr: 16 bytes (union of uint32 and in6_addr)
//   - daddr: 16 bytes (union of uint32 and in6_addr)
//   - lport: 2 bytes
//   - rport: 2 bytes
//   - family: 2 bytes
//   - protocol: 1 byte
//   - flags: 1 byte
//   - direction: 1 byte
//   - _pad: 1 byte + 6 bytes padding (to align timestamp to 8 bytes)
//   - timestamp: 8 bytes
//   - pid: 4 bytes
//   - tgid: 4 bytes
//   - uid: 4 bytes
//   - comm: 16 bytes
type Event struct {
	Saddr     [16]byte // 16-byte union (IPv4 uses first 4 bytes, IPv6 uses all 16)
	Daddr     [16]byte // 16-byte union (IPv4 uses first 4 bytes, IPv6 uses all 16)
	Lport     uint16
	Rport     uint16
	Family    uint16
	Protocol  uint8
	Flags     uint8
	Direction uint8
	_         [7]byte // Padding: 1 byte explicit + 6 bytes to align timestamp to offset 48
	Timestamp uint64
	Pid       uint32
	Tgid      uint32
	Uid       uint32
	Comm      [16]byte // TASK_COMM_LEN
}

// Direction constants matching eBPF defines
const (
	DirInbound  uint8 = 0 // Someone connecting to us
	DirOutbound uint8 = 1 // We connecting to someone
)

// IpBytes matches the C struct ip_bytes in traffic_probe.c
type IpBytes struct {
	BytesIn  uint64
	BytesOut uint64
}

// IpICMP matches the C struct icmp_pkt_count in traffic_probe.c.
// Layout: two consecutive uint64 values — no padding needed.
type IpICMP struct {
	PacketsIn  uint64
	PacketsOut uint64
}

// IpPortKey matches the C struct ip_port_key in traffic_probe.c.
// Size: 4 (ip) + 2 (port) + 2 (pad) = 8 bytes, naturally aligned.
// Must be used as the BPF map key for ip_port_bytes lookups.
type IpPortKey struct {
	IP   uint32
	Port uint16
	_    [2]byte // explicit padding mirrors C struct _pad[2]
}

// PortBytes matches the C struct port_bytes in traffic_probe.c.
type PortBytes struct {
	BytesIn  uint64
	BytesOut uint64
}

// IPStats holds per-IP statistics for aggregation
type IPStats struct {
	mu               sync.Mutex // Protects all mutable fields below
	Protocol         uint8
	SYNCount         int
	ACKCount         int
	FailedHandshakes int
	UniquePorts      map[uint16]bool
	PortCounts       map[uint16]int // Track count per port for primary port detection
	PortHits         map[uint16]int // port -> hit count (for service abuse detection)
	BytesIn          uint64
	BytesOut         uint64
	// ICMP packet counters (populated from icmp_counters BPF map at flush)
	ICMPPacketsIn  uint64
	ICMPPacketsOut uint64
	// Per-port byte breakdown (populated from ip_port_bytes BPF map at flush)
	PortBytesIn  map[uint16]uint64
	PortBytesOut map[uint16]uint64
	Direction    uint8  // Predominant direction (set on first event)
	LocalIP      string // Our server's IP (for proper source/destination)
	FirstSeen    time.Time
	LastSeen     time.Time
	ProcessName  string // Most recently seen process name (from eBPF comm field)
}

// Global BPF map references — set in SetupBandwidthTracking after eBPF objects are loaded.
// All three maps use IPv4 host-byte-order uint32 as keys (or IpPortKey for ip_port_bytes).
var byteCounterMap interface{ Lookup(any, any) error }
var icmpCounterMap interface{ Lookup(any, any) error }
var ipPortBytesMap interface{ Lookup(any, any) error }
