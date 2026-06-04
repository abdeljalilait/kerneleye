package remediation

import (
	"net"
	"time"
)

// Action defines the type of remediation action
type Action string

const (
	ActionBlock     Action = "BLOCK"
	ActionRateLimit Action = "RATE_LIMIT"
	ActionNone      Action = "NONE"
)

// TrafficEvent represents a simplified networking event for analysis
type TrafficEvent struct {
	SourceIP net.IP
	DestPort uint16
	Protocol uint8
	Flags    uint8
	Time     time.Time
}

// Decision represents a remediation decision
type Decision struct {
	IP       net.IP
	Action   Action
	Reason   string
	Duration time.Duration
	DestPort uint16
	Protocol uint8
}

// BlockCallback is called when an IP is blocked or rate-limited
type BlockCallback func(ip net.IP, action Action, reason string, duration time.Duration)

// Remediator defines the interface for applying remediation actions
type Remediator interface {
	// Setup initializes the remediation system (e.g. creating ipsets and iptables chains)
	Setup() error
	// Block adds an IP to the blocklist for the specified duration
	Block(ip net.IP, duration time.Duration) error
	// RateLimit adds an IP to the rate-limit list for the specified duration
	RateLimit(ip net.IP, duration time.Duration) error
	// Unblock removes an IP from the specified block list
	Unblock(ip net.IP, blockType BlockType) error
	// Teardown cleans up resources (optional)
	Teardown() error
}

// TrafficAnalyzer defines the interface for analyzing traffic and triggering remediation
type TrafficAnalyzer interface {
	// Evaluate analyzes an event and returns a decision if remediation is needed
	Evaluate(event TrafficEvent) *Decision
}

// BlockedPacketEvent represents a blocked packet event from the XDP ring buffer
// This mirrors the C struct block_event in xdp_firewall.c
type BlockedPacketEvent struct {
	SrcIP     uint32
	SrcIP6    [16]byte
	IPVersion uint8
	DestPort  uint16
	Protocol  uint8
	Reason    uint8
	Timestamp uint64
}

// BlockedPacketCallback is called when a blocked packet event is received from XDP
type BlockedPacketCallback func(ip string, port uint16, protocol uint8, reason uint8)

// BlockReason represents the reason why a packet was blocked
type BlockReason uint8

const (
	BlockReasonBlocklist BlockReason = 1 // IP in blocklist
	BlockReasonCIDR      BlockReason = 2 // IP in CIDR blocklist
	BlockReasonRateLimit BlockReason = 3 // Rate limit exceeded
)

func (r BlockReason) String() string {
	switch r {
	case BlockReasonBlocklist:
		return "blocklist"
	case BlockReasonCIDR:
		return "cidr"
	case BlockReasonRateLimit:
		return "rate_limit"
	default:
		return "unknown"
	}
}

// BlockedEntry represents an IP currently present in an ipset
type BlockedEntry struct {
	IP        net.IP
	BlockType BlockType // BlockTypeBlocklist or BlockTypeRateLimit
	Version   int       // 4 or 6
}

// BlockType represents the type of block list
type BlockType uint8

const (
	BlockTypeUnspecified BlockType = 0
	BlockTypeBlocklist   BlockType = 1 // kernel_eye_block / xdp_blocklist
	BlockTypeRateLimit   BlockType = 2 // kernel_eye_ratelimit
	BlockTypeCIDR        BlockType = 3 // kerneleye_block_cidr
)

func (bt BlockType) String() string {
	switch bt {
	case BlockTypeBlocklist:
		return "blocklist"
	case BlockTypeRateLimit:
		return "ratelimit"
	case BlockTypeCIDR:
		return "cidr"
	default:
		return "unspecified"
	}
}

// MapTrustLevel classifies eBPF maps by their security sensitivity.
// Higher levels require stricter access controls and integrity checking.
type MapTrustLevel uint8

const (
	// TrustLevelLow — telemetry/debug maps. No security impact if tampered.
	TrustLevelLow MapTrustLevel = 0

	// TrustLevelMedium — event/stat maps. Tampering degrades observability but
	// does not directly alter security posture.
	TrustLevelMedium MapTrustLevel = 1

	// TrustLevelHigh — blocking/policy maps. Tampering could allow/deny traffic
	// incorrectly. All writes must be audited.
	TrustLevelHigh MapTrustLevel = 2

	// TrustLevelVeryHigh — configuration maps. Must be frozen after initial
	// configuration. Any mutation is a security event.
	TrustLevelVeryHigh MapTrustLevel = 3
)

func (tl MapTrustLevel) String() string {
	switch tl {
	case TrustLevelLow:
		return "low"
	case TrustLevelMedium:
		return "medium"
	case TrustLevelHigh:
		return "high"
	case TrustLevelVeryHigh:
		return "very_high"
	default:
		return "unknown"
	}
}

// MapClassification describes the security posture of a single eBPF map.
type MapClassification struct {
	Name       string
	TrustLevel MapTrustLevel
	Frozen     bool // If true, the map should be read-only after initialization
	AuditWrites bool // If true, all writes to this map should be logged
}

// ClassifyMaps returns the security classification for all known KernelEye maps.
func ClassifyMaps() []MapClassification {
	return []MapClassification{
		// Traffic probe maps
		{Name: "events", TrustLevel: TrustLevelMedium, Frozen: false, AuditWrites: false},
		{Name: "rate_limiter", TrustLevel: TrustLevelLow, Frozen: false, AuditWrites: false},
		{Name: "global_rate_limiter", TrustLevel: TrustLevelLow, Frozen: false, AuditWrites: false},
		{Name: "tcp_syn_tracker", TrustLevel: TrustLevelMedium, Frozen: false, AuditWrites: false},
		{Name: "tcp_syn_tracker_v6", TrustLevel: TrustLevelMedium, Frozen: false, AuditWrites: false},
		{Name: "debug_counters", TrustLevel: TrustLevelLow, Frozen: false, AuditWrites: false},
		{Name: "ip_byte_counters", TrustLevel: TrustLevelLow, Frozen: false, AuditWrites: false},
		{Name: "ip_byte_counters_v6", TrustLevel: TrustLevelLow, Frozen: false, AuditWrites: false},
		{Name: "icmp_counters", TrustLevel: TrustLevelLow, Frozen: false, AuditWrites: false},
		{Name: "ip_port_bytes", TrustLevel: TrustLevelLow, Frozen: false, AuditWrites: false},

		// XDP firewall maps
		{Name: "xdp_blocklist", TrustLevel: TrustLevelHigh, Frozen: false, AuditWrites: true},
		{Name: "xdp_blocklist_v6", TrustLevel: TrustLevelHigh, Frozen: false, AuditWrites: true},
		{Name: "xdp_cidr_blocklist", TrustLevel: TrustLevelHigh, Frozen: false, AuditWrites: true},
		{Name: "xdp_rate_limit", TrustLevel: TrustLevelHigh, Frozen: false, AuditWrites: true},
		{Name: "xdp_stats", TrustLevel: TrustLevelMedium, Frozen: false, AuditWrites: false},
		{Name: "xdp_block_events", TrustLevel: TrustLevelMedium, Frozen: false, AuditWrites: false},
		{Name: "xdp_rate_config", TrustLevel: TrustLevelVeryHigh, Frozen: true, AuditWrites: true},
	}
}

// MapClassificationByName returns the classification for a given map name.
func MapClassificationByName(name string) (MapClassification, bool) {
	for _, c := range ClassifyMaps() {
		if c.Name == name {
			return c, true
		}
	}
	return MapClassification{}, false
}
