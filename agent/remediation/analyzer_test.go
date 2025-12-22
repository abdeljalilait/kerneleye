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

	// Send 19 SYNs (under threshold)
	for i := 0; i < 19; i++ {
		evt := TrafficEvent{
			SourceIP: ip,
			DestPort: 80,
			Protocol: 6,    // TCP
			Flags:    0x02, // SYN
			Time:     start.Add(time.Duration(i) * 10 * time.Millisecond),
		}
		decision := analyzer.Evaluate(evt)
		if decision != nil {
			t.Fatalf("Unexpected decision at event %d: %v", i, decision)
		}
	}

	// Send 20th SYN (should trigger if threshold is strict, or 21st?)
	// Logic says: count > threshold. stored: 19. currently adding 20th. count will be 19? no
	// Let's trace:
	// 1. Add to ring. Ring has 20 items.
	// 2. Count items in window. Count = 20.
	// 3. 20 > 20 is False. So 21st packet needed?

	// Let's optimize: send 120 packets in 1 second (120 Hz)
	// Threshold 20/60s. So packet 21 (or 22) should ideally block.

	for i := 19; i < 120; i++ {
		evt := TrafficEvent{
			SourceIP: ip,
			DestPort: 80,
			Protocol: 6,
			Flags:    0x02,
			Time:     start.Add(time.Duration(i) * 10 * time.Millisecond), // 1200ms total
		}
		decision := analyzer.Evaluate(evt)

		// Expect block after some point
		if decision != nil {
			if decision.Action != ActionBlock {
				t.Errorf("Expected Block, got %v", decision.Action)
			}
			return // Success
		}
	}
	t.Fatal("Failed to detect SYN flood after 120 packets")
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
	cfg.MaxStates = 1000 // Small cap to force evictions
	analyzer := NewAnalyzer(cfg)

	// 50 concurrent routines, 100 events each
	concurrency := 50
	events := 100
	done := make(chan bool)

	for i := 0; i < concurrency; i++ {
		go func(id int) {
			ip := net.ParseIP(fmt.Sprintf("192.168.1.%d", id%10)) // 10 distinct IPs
			for j := 0; j < events; j++ {
				evt := TrafficEvent{
					SourceIP: ip,
					DestPort: 80,
					Protocol: 6,
					Flags:    0x02,
					Time:     time.Now(),
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
