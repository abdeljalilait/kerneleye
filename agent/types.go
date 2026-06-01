package main

import (
	"sync"
	"time"
)

// Event matches the C struct event_t in traffic_probe.c (80 bytes — no padding).
// C struct layout (zero-padding, offset→field):
//   [0:8]   timestamp (uint64)
//   [8:12]  pid (uint32)
//   [12:16] tgid (uint32)
//   [16:20] uid (uint32)
//   [20:22] lport (uint16)
//   [22:24] rport (uint16)
//   [24:26] family (uint16)
//   [26]    protocol (uint8)
//   [27]    flags (uint8)
//   [28]    direction (uint8)
//   [29:32] _pad[3] (3 byte alignment padding)
//   [32:48] saddr (16-byte union: IPv4 uses first 4 bytes, IPv6 all 16)
//   [48:64] daddr (16-byte union)
//   [64:80] comm[16] (TASK_COMM_LEN)
type Event struct {
	Timestamp uint64
	Pid       uint32
	Tgid      uint32
	Uid       uint32
	Lport     uint16
	Rport     uint16
	Family    uint16
	Protocol  uint8
	Flags     uint8
	Direction uint8
	_         [3]byte // alignment padding, mirrors C _pad[3]
	Saddr     [16]byte
	Daddr     [16]byte
	Comm      [16]byte
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
