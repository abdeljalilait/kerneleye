package scoring

import (
	"testing"
	"time"
)

func TestCalculateScore_LowVolumeOutbound(t *testing.T) {
	ts := NewThreatScorer()
	now := time.Now()

	// Test case: Single outbound connection (1 SYN, 0 ACK)
	// This was scoring 90 before the fix
	metrics := IPMetrics{
		SYNCount:         1,
		ACKCount:         0,
		FailedHandshakes: 0,
		UniquePorts:      1,
		TotalConnections: 1,
		WindowStart:      now.Add(-100 * time.Millisecond), // Very short window
		WindowEnd:        now,
		Direction:        DirectionOutbound,
	}

	score := ts.CalculateScore(metrics)

	// After fix: Should be capped at 30 for low-volume outbound
	if score.Score > 30 {
		t.Errorf("Low-volume outbound connection scored too high: got %d, want <= 30", score.Score)
	}

	// Should be "normal" level, not malicious
	if score.Level != ThreatLevelNormal {
		t.Errorf("Low-volume outbound should be normal: got %s, want normal", score.Level)
	}

	t.Logf("Score: %d, Level: %s, Reasons: %v", score.Score, score.Level, score.Reasons)
}

func TestCalculateScore_LowVolumeInbound(t *testing.T) {
	ts := NewThreatScorer()
	now := time.Now()

	// Test case: Single inbound connection attempt
	metrics := IPMetrics{
		SYNCount:         1,
		ACKCount:         0,
		FailedHandshakes: 0,
		UniquePorts:      1,
		TotalConnections: 1,
		WindowStart:      now.Add(-100 * time.Millisecond),
		WindowEnd:        now,
		Direction:        DirectionInbound,
	}

	score := ts.CalculateScore(metrics)

	// After fix: Should be capped at 40 for low-confidence, low-volume
	if score.Score > 40 {
		t.Errorf("Low-volume inbound scored too high: got %d, want <= 40", score.Score)
	}

	t.Logf("Score: %d, Level: %s, Reasons: %v", score.Score, score.Level, score.Reasons)
}

func TestCalculateScore_HighVolumeAttack(t *testing.T) {
	ts := NewThreatScorer()
	now := time.Now()

	// Test case: Actual attack pattern (high volume, short window)
	metrics := IPMetrics{
		SYNCount:               100,
		ACKCount:               5,
		FailedHandshakes:       95,
		UniquePorts:            10,
		TotalConnections:       105,
		EstablishedConnections: 5,
		WindowStart:            now.Add(-10 * time.Second),
		WindowEnd:              now,
		Direction:              DirectionInbound,
	}

	score := ts.CalculateScore(metrics)

	// High volume attacks should still score high
	if score.Score < 60 {
		t.Errorf("High-volume attack should score high: got %d, want >= 60", score.Score)
	}

	if score.Level != ThreatLevelMalicious {
		t.Errorf("High-volume attack should be malicious: got %s, want malicious", score.Level)
	}

	t.Logf("Score: %d, Level: %s, Type: %s, Reasons: %v", score.Score, score.Level, score.Type, score.Reasons)
}

func TestCalculateScore_FailedHandshakes(t *testing.T) {
	ts := NewThreatScorer()
	now := time.Now()

	tests := []struct {
		name        string
		failed      int
		direction   Direction
		maxScore    int
		description string
	}{
		{
			name:        "Single failed outbound",
			failed:      1,
			direction:   DirectionOutbound,
			maxScore:    30,
			description: "Single failed handshake should not score high",
		},
		{
			name:        "Two failed outbound",
			failed:      2,
			direction:   DirectionOutbound,
			maxScore:    30,
			description: "Two failed handshakes should not score high",
		},
		{
			name:        "Five failed inbound",
			failed:      5,
			direction:   DirectionInbound,
			maxScore:    100, // Can be high
			description: "Five failed handshakes could be suspicious",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := IPMetrics{
				SYNCount:         tt.failed,
				ACKCount:         0,
				FailedHandshakes: tt.failed,
				UniquePorts:      1,
				TotalConnections: tt.failed,
				WindowStart:      now.Add(-5 * time.Second),
				WindowEnd:        now,
				Direction:        tt.direction,
			}

			score := ts.CalculateScore(metrics)
			t.Logf("%s: Score=%d, Level=%s", tt.description, score.Score, score.Level)

			if score.Score > tt.maxScore {
				t.Errorf("%s: got score %d, want <= %d", tt.name, score.Score, tt.maxScore)
			}
		})
	}
}
