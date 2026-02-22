package main

import (
	"sync"
	"time"
)

// Event matches the C struct in traffic_probe.c
type Event struct {
	Saddr     uint32
	Daddr     uint32
	Lport     uint16
	Rport     uint16
	Family    uint16
	Protocol  uint8
	Flags     uint8
	Direction uint8
	_         [3]byte // Alignment padding
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
	BytesIn          uint64
	BytesOut         uint64
	Direction        uint8  // Predominant direction (set on first event)
	LocalIP          string // Our server's IP (for proper source/destination)
	FirstSeen        time.Time
	LastSeen         time.Time
}

// Global byte counter map reference (set after loading eBPF)
var byteCounterMap interface{ Lookup(any, any) error }
