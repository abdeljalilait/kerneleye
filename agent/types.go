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

// IPStats holds per-IP statistics for aggregation
type IPStats struct {
	mu               sync.Mutex // Protects all mutable fields below
	Protocol         uint8
	SYNCount         int
	ACKCount         int
	FailedHandshakes int
	UniquePorts      map[uint16]bool
	PortCounts       map[uint16]int // Track count per port for primary port detection
	PortHits         map[uint16]int // NEW: port -> hit count (for service abuse detection)
	BytesIn          uint64
	BytesOut         uint64
	Direction        uint8  // Predominant direction (set on first event)
	LocalIP          string // Our server's IP (for proper source/destination)
	FirstSeen        time.Time
	LastSeen         time.Time
}

// Global byte counter map reference (set after loading eBPF)
var byteCounterMap interface{ Lookup(any, any) error }
