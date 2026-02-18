package remediation

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestSynFloodDetection(t *testing.T) {
	// Config: 20 SYNs in 60s
	cfg := DefaultAnalyzerConfig()
	cfg.SynFloodThreshold = 20
	cfg.SynFloodWindow = 60 * time.Second
	analyzer := NewAnalyzer(cfg)

	ip := net.ParseIP("192.168.1.100")
	start := time.Now()

	// Send 21 SYNs quickly - should trigger block at packet 21
	// Logic: count > threshold, so 21 > 20 triggers block
	for i := 0; i < 25; i++ {
		evt := TrafficEvent{
			SourceIP: ip,
			DestPort: 80,
			Protocol: 6,    // TCP
			Flags:    0x02, // SYN
			Time:     start.Add(time.Duration(i) * time.Millisecond), // 1ms gaps
		}
		decision := analyzer.Evaluate(evt)

		if i < 20 {
			// Should not trigger before threshold
			if decision != nil {
				t.Fatalf("Unexpected decision at event %d: %v", i, decision)
			}
		} else if decision != nil {
			// Should trigger at or after threshold
			if decision.Action != ActionBlock {
				t.Errorf("Expected Block, got %v", decision.Action)
			}
			return // Success
		}
	}
	t.Fatal("Failed to detect SYN flood after 25 packets")
}

func TestRingBufferWraparound(t *testing.T) {
	cfg := DefaultAnalyzerConfig()
	cfg.SynFloodThreshold = 5
	cfg.SynFloodWindow = 1 * time.Second
	analyzer := NewAnalyzer(cfg)
	ip := net.ParseIP("10.0.0.1")

	// Fill buffer past capacity (size = 6)
	// Send 10 packets, 1 per second.
	// Window 1s.
	// Only last 1 or 2 should be counted.

	base := time.Now()
	for i := 0; i < 10; i++ {
		evt := TrafficEvent{
			SourceIP: ip,
			DestPort: 80,
			Protocol: 6,
			Flags:    0x02,
			Time:     base.Add(time.Duration(i) * 2 * time.Second), // 2s gap
		}
		decision := analyzer.Evaluate(evt)
		if decision != nil {
			t.Fatalf("Should not block (rate 0.5/s < threshold 5/1s). Event %d triggered block", i)
		}
	}
}

func TestConcurrentEvaluation(t *testing.T) {
	cfg := DefaultAnalyzerConfig()
	cfg.MaxStates = 100 // Small cap to force evictions
	analyzer := NewAnalyzer(cfg)

	// 20 concurrent routines, 50 events each = 1000 events total
	concurrency := 20
	events := 50
	done := make(chan bool)

	for i := 0; i < concurrency; i++ {
		go func(id int) {
			ip := net.ParseIP(fmt.Sprintf("192.168.1.%d", id%10)) // 10 distinct IPs
			baseTime := time.Now()
			for j := 0; j < events; j++ {
				evt := TrafficEvent{
					SourceIP: ip,
					DestPort: 80,
					Protocol: 6,
					Flags:    0x02,
					Time:     baseTime.Add(time.Duration(j) * time.Microsecond),
				}
				analyzer.Evaluate(evt)
			}
			done <- true
		}(i)
	}

	for i := 0; i < concurrency; i++ {
		<-done
	}
}
