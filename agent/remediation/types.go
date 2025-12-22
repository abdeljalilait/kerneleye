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
	// Teardown cleans up resources (optional)
	Teardown() error
}

// TrafficAnalyzer defines the interface for analyzing traffic and triggering remediation
type TrafficAnalyzer interface {
	// Evaluate analyzes an event and returns a decision if remediation is needed
	Evaluate(event TrafficEvent) *Decision
}
