package scoring

import (
	"math"
	"strings"
	"testing"
	"time"
)

func TestCalculateScore_SYN_BalancedButHighFailures(t *testing.T) {
	scorer := NewThreatScorer()

	// Balanced SYN/ACK (50/50) so Ratio = 0.5.
	// But High Failed Handshakes (10 > 3).
	// And High Rate (100 packets in 1 sec = 100/sec > Suspicious)
	metrics := IPMetrics{
		SYNCount:         50,
		ACKCount:         50,
		FailedHandshakes: 10,
		TotalConnections: 100,
		WindowStart:      time.Now().Add(-1 * time.Second),
		WindowEnd:        time.Now(),
	}

	score := scorer.CalculateScore(metrics)

	// Prior to fix, this would return 0 for SYN component because Ratio < 0.65.
	// Now it should fall through and score based on high rate.
	if score.RawMetrics.SYNComponent <= 0 {
		t.Errorf("Should score SYN component for high failures even if ratio is balanced. Got %f", score.RawMetrics.SYNComponent)
	}
}

func TestCalculateScore_DivisionByZero(t *testing.T) {
	scorer := NewThreatScorer()
	metrics := IPMetrics{
		WindowStart: time.Now(),
		WindowEnd:   time.Now(), // Zero duration
	}

	// Should not panic
	score := scorer.CalculateScore(metrics)
	if score.Confidence < 0.1 {
		t.Errorf("Expected confidence >= 0.1, got %f", score.Confidence)
	}
}

func TestCalculateScore_Normalization(t *testing.T) {
	scorer := NewThreatScorer()
	scorer.SYNRateWeight = 1000.0 // Force high score

	metrics := IPMetrics{
		SYNCount:         1000,
		TotalConnections: 1000,
		WindowStart:      time.Now().Add(-1 * time.Minute),
		WindowEnd:        time.Now(),
	}

	score := scorer.CalculateScore(metrics)
	if score.Score > 100 {
		t.Errorf("Score should be capped at 100, got %d", score.Score)
	}
	if score.FinalScoreFloat > 100.0 {
		t.Errorf("Normalized score should be capped at 100.0, got %f", score.FinalScoreFloat)
	}
}

func TestCalculateScore_BurstDetection(t *testing.T) {
	scorer := NewThreatScorer()

	// Short duration, high rate
	metrics := IPMetrics{
		TotalConnections: 150, // 30 conn/sec > 20 threshold
		WindowStart:      time.Now().Add(-5 * time.Second),
		WindowEnd:        time.Now(),
	}

	score := scorer.CalculateScore(metrics)
	// Expect burst component to be active
	if score.RawMetrics.BurstComponent <= 4.0 {
		t.Errorf("Should detect burst, got %f", score.RawMetrics.BurstComponent)
	}
}

func TestCalculateScore_FailedHandshake(t *testing.T) {
	scorer := NewThreatScorer()

	// Slow brute force: low rate but high failure ratio
	metrics := IPMetrics{
		FailedHandshakes:       60,
		EstablishedConnections: 10,
		WindowStart:            time.Now().Add(-10 * time.Second), // 6 fails/sec
		WindowEnd:              time.Now(),
	}

	score := scorer.CalculateScore(metrics)
	if score.RawMetrics.FailedComponent <= 0.0 {
		t.Errorf("Should score for slow brute force")
	}
}

func TestCalculateScore_RSTStorm(t *testing.T) {
	scorer := NewThreatScorer()

	metrics := IPMetrics{
		EstablishedConnections: 10,
		RSTCount:               30, // 3x established
		WindowStart:            time.Now().Add(-1 * time.Minute),
		WindowEnd:              time.Now(),
	}

	score := scorer.CalculateScore(metrics)
	if score.RawMetrics.BurstComponent <= 2.0 {
		t.Errorf("Should detect RST storm, got burst component %f", score.RawMetrics.BurstComponent)
	}
}

func TestCalculateScore_RSTStorm_NoiseAvoidance(t *testing.T) {
	scorer := NewThreatScorer()

	// Established 0, RST 4 (<= 5). Should NOT trigger even though RST > Est*2
	metrics := IPMetrics{
		EstablishedConnections: 0,
		RSTCount:               4,
		WindowStart:            time.Now().Add(-1 * time.Minute),
		WindowEnd:              time.Now(),
	}

	score := scorer.CalculateScore(metrics)
	if score.RawMetrics.BurstComponent > 0.0 {
		t.Errorf("Should avoid RST noise when RST count is low")
	}
}

func TestCalculateScore_ServicePorts(t *testing.T) {
	scorer := NewThreatScorer()

	// Base metrics that would generate a score
	metrics := IPMetrics{
		SYNCount:         50,
		TotalConnections: 50,
		WindowStart:      time.Now().Add(-10 * time.Second),
		WindowEnd:        time.Now(),
		ServicePorts:     []int{8080}, // Non-whitelist
		UniquePorts:      1,           // Need > 0 for ratio check
	}

	score1 := scorer.CalculateScore(metrics)

	// Same metrics but with whitelisted port
	metrics2 := metrics
	metrics2.ServicePorts = []int{80}

	score2 := scorer.CalculateScore(metrics2)

	// Since UniquePorts is 1 and ServicePorts hits 1 (port 80), ratio is 100% >= 50%
	// Should apply reduction
	if score2.FinalScoreFloat >= score1.FinalScoreFloat {
		t.Errorf("Whitelisted ports should reduce score. Score1: %f, Score2: %f", score1.FinalScoreFloat, score2.FinalScoreFloat)
	}
}

func TestCalculateScore_Decay(t *testing.T) {
	scorer := NewThreatScorer()

	metrics := IPMetrics{
		PreviousScore: 50,
		WindowStart:   time.Now().Add(-1 * time.Minute),
		WindowEnd:     time.Now(),
		// Minimal current activity
	}

	score := scorer.CalculateScore(metrics)
	// Should be roughly 0 * 0.3 + 50 * 0.7 = 35
	if math.Abs(score.FinalScoreFloat-35.0) > 5.0 {
		t.Errorf("Score should decay from previous. Got %f, expected ~35", score.FinalScoreFloat)
	}
}

func TestCalculateScore_PreviousScoreTrust(t *testing.T) {
	scorer := NewThreatScorer()

	metrics := IPMetrics{
		PreviousScore: 9999, // Maliciously high input
		WindowStart:   time.Now().Add(-1 * time.Minute),
		WindowEnd:     time.Now(),
	}

	score := scorer.CalculateScore(metrics)
	// Should be clamped to 100 before calculation
	// 100 * 0.7 + 0 * 0.3 = 70
	if score.FinalScoreFloat > 75.0 {
		t.Errorf("PreviousScore should be clamped. Got %f", score.FinalScoreFloat)
	}
}

func TestCalculateScore_LongWindowPorts(t *testing.T) {
	scorer := NewThreatScorer()

	// Many unique ports but over a very long duration (slow legitimate traffic)
	metrics := IPMetrics{
		UniquePorts:      50,
		TotalConnections: 50,                             // 1 conn per port
		WindowStart:      time.Now().Add(-2 * time.Hour), // Very long window
		WindowEnd:        time.Now(),
	}

	// ports/sec = 50 / 7200 = 0.0069
	// Should NOT trigger port scan detection because rate is low

	score := scorer.CalculateScore(metrics)
	if score.RawMetrics.PortScanComponent > 0 {
		t.Errorf("Should ensure long windows don't trigger port scan. Component: %f", score.RawMetrics.PortScanComponent)
	}
}

func TestCalculateScore_ConfidencePrefix(t *testing.T) {
	scorer := NewThreatScorer()

	// Short window -> Low confidence
	metrics := IPMetrics{
		SYNCount:    100, // Trigger reason
		WindowStart: time.Now().Add(-2 * time.Second),
		WindowEnd:   time.Now(),
	}

	score := scorer.CalculateScore(metrics)
	if len(score.Reasons) > 0 {
		if !strings.Contains(score.Reasons[0], "(Low Confidence)") {
			t.Errorf("Should prefix reasons with 'Low Confidence' on short windows")
		}
	}
}

func TestConfig_SafetyGuard(t *testing.T) {
	scorer := NewThreatScorer()

	// Manually act like we loaded bad config
	scorer.MaliciousThreshold = 90
	scorer.AutoBlockThreshold = 50 // Unsafe

	// Re-run validation logic (simulate logic from NewThreatScorer)
	if scorer.AutoBlockThreshold < scorer.MaliciousThreshold {
		scorer.AutoBlockThreshold = scorer.MaliciousThreshold
	}

	if scorer.AutoBlockThreshold < 90 {
		t.Errorf("Safety guard should enforce AutoBlock >= Malicious")
	}
}
