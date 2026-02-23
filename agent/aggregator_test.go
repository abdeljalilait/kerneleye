package main

import (
	"net"
	"testing"
	"time"

	"github.com/kerneleye/agent/remediation"
)

type recordingRemediator struct {
	blockCalls     int
	rateLimitCalls int
}

func (r *recordingRemediator) Setup() error { return nil }

func (r *recordingRemediator) Block(_ net.IP, _ time.Duration) error {
	r.blockCalls++
	return nil
}

func (r *recordingRemediator) RateLimit(_ net.IP, _ time.Duration) error {
	r.rateLimitCalls++
	return nil
}

func (r *recordingRemediator) Teardown() error { return nil }

func TestTrackedPortForEvent(t *testing.T) {
	outbound := Event{Direction: DirOutbound, Lport: 40616, Rport: 443}
	if got := trackedPortForEvent(outbound); got != 443 {
		t.Fatalf("outbound tracked port = %d, want 443", got)
	}

	inbound := Event{Direction: DirInbound, Lport: 22, Rport: 58086}
	if got := trackedPortForEvent(inbound); got != 22 {
		t.Fatalf("inbound tracked port = %d, want 22", got)
	}
}

func TestProcessEventOutboundTracksRemoteServicePort(t *testing.T) {
	agg := &Aggregator{
		stats:          NewSafeStats(),
		cachedPublicIP: "203.0.113.10",
		bootTime:       time.Now().Add(-time.Hour),
	}

	agg.ProcessEvent(Event{
		Saddr:     ipToNetworkOrder("46.224.59.11"),
		Lport:     40616,
		Rport:     443,
		Protocol:  6,
		Direction: DirOutbound,
		Flags:     0x01,
		Timestamp: uint64((10 * time.Second).Nanoseconds()),
	})

	stats, ok := agg.stats.Get("46.224.59.11")
	if !ok {
		t.Fatal("expected stats for remote IP")
	}

	stats.mu.Lock()
	_, hasServicePort := stats.UniquePorts[443]
	_, hasEphemeralPort := stats.UniquePorts[40616]
	portCount := len(stats.UniquePorts)
	stats.mu.Unlock()

	if !hasServicePort {
		t.Fatal("expected remote service port 443 to be tracked")
	}
	if hasEphemeralPort {
		t.Fatal("did not expect local ephemeral port 40616 to be tracked")
	}
	if portCount != 1 {
		t.Fatalf("tracked unique ports = %d, want 1", portCount)
	}

	events := agg.buildProtoEvents()
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if got := events[0].GetDestinationPort(); got != 443 {
		t.Fatalf("destination_port = %d, want 443", got)
	}
}

func TestProcessEventOutboundEphemeralPortsDoNotTriggerPortScan(t *testing.T) {
	cfg := remediation.DefaultAnalyzerConfig()
	cfg.PortScanThreshold = 2
	cfg.PortScanWindow = 30 * time.Second

	rem := &recordingRemediator{}
	agg := &Aggregator{
		stats:          NewSafeStats(),
		cachedPublicIP: "203.0.113.10",
		bootTime:       time.Now().Add(-time.Hour),
		analyzer:       remediation.NewAnalyzer(cfg),
		remediator:     rem,
	}

	for i := 0; i < 3; i++ {
		agg.ProcessEvent(Event{
			Saddr:     ipToNetworkOrder("46.224.59.11"),
			Lport:     uint16(40000 + i),
			Rport:     443,
			Protocol:  6,
			Direction: DirOutbound,
			Flags:     0,
			Timestamp: uint64((time.Duration(11+i) * time.Second).Nanoseconds()),
		})
	}

	if rem.rateLimitCalls != 0 {
		t.Fatalf("rate-limit decisions = %d, want 0", rem.rateLimitCalls)
	}
}
