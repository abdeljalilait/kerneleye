package analysis

import (
	"testing"
	"time"

	"github.com/kerneleye/backend/internal/database"
	"github.com/kerneleye/shared/scoring"
)

func TestBuildMetrics_ServiceAbuseApproximation(t *testing.T) {
	w := &Worker{}
	now := time.Now()

	row := database.GetTrafficAggregationByIPRow{
		SynCount:         73,
		AckCount:         73,
		FailedHandshakes: 0,
		PortCount:        1,
		WindowStart:      now.Add(-5 * time.Minute),
		WindowEnd:        now,
	}

	metrics := w.buildMetrics(row)
	if metrics.MaxPortHits != 73 {
		t.Fatalf("expected max_port_hits=73, got %d", metrics.MaxPortHits)
	}
	if metrics.Direction != scoring.DirectionInbound {
		t.Fatalf("expected inbound direction, got %q", metrics.Direction)
	}

	score := scoring.NewThreatScorer().CalculateScore(metrics)
	if score.Score <= 0 {
		t.Fatalf("expected positive score for sustained single-port traffic, got %d", score.Score)
	}
}

func TestBuildMetrics_MultiPortTrafficLowersServiceConcentration(t *testing.T) {
	w := &Worker{}
	now := time.Now()

	row := database.GetTrafficAggregationByIPRow{
		SynCount:         73,
		AckCount:         73,
		FailedHandshakes: 0,
		PortCount:        17,
		WindowStart:      now.Add(-5 * time.Minute),
		WindowEnd:        now,
	}

	metrics := w.buildMetrics(row)
	if metrics.MaxPortHits > 10 {
		t.Fatalf("expected reduced max_port_hits for multi-port traffic, got %d", metrics.MaxPortHits)
	}
}
