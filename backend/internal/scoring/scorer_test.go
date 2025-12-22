package scoring

import (
	"math"
	"testing"
	"time"
)

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
	if score.NormalizedScore > 100.0 {
		t.Errorf("Normalized score should be capped at 100.0, got %f", score.NormalizedScore)
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

func TestCalculateScore_ServicePorts(t *testing.T) {
	scorer := NewThreatScorer()

	// Base metrics that would generate a score
	metrics := IPMetrics{
		SYNCount:         50,
		TotalConnections: 50,
		WindowStart:      time.Now().Add(-10 * time.Second),
		WindowEnd:        time.Now(),
		ServicePorts:     []int{8080}, // Non-whitelist
	}

	score1 := scorer.CalculateScore(metrics)

	// Same metrics but with whitelisted port
	metrics2 := metrics
	metrics2.ServicePorts = []int{80}

	score2 := scorer.CalculateScore(metrics2)

	if score2.NormalizedScore >= score1.NormalizedScore {
		t.Errorf("Whitelisted ports should reduce score. Score1: %f, Score2: %f", score1.NormalizedScore, score2.NormalizedScore)
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
	if math.Abs(score.NormalizedScore-35.0) > 5.0 {
		t.Errorf("Score should decay from previous. Got %f, expected ~35", score.NormalizedScore)
	}
}
