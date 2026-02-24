package api

import (
	"testing"
	"time"

	pb "github.com/kerneleye/proto/kerneleye/v1"
	"github.com/kerneleye/shared/scoring"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestBuildMetricsFromEvent_ServiceAbuseScoresAboveZero(t *testing.T) {
	now := time.Now()
	event := &pb.ConnectionEvent{
		SourceIp:         "193.32.162.188",
		DestinationPort:  22,
		SynCount:         29,
		AckCount:         29,
		FailedHandshakes: 0,
		UniquePortsCount: 1,
		PortsAccessed:    []uint32{22},
		Direction:        pb.Direction_DIRECTION_INBOUND,
		FirstSeen:        timestamppb.New(now.Add(-10 * time.Second)),
		LastSeen:         timestamppb.New(now),
	}

	metrics := buildMetricsFromEvent(event)
	score := scoring.NewThreatScorer().CalculateScore(metrics)
	if score.Score <= 0 {
		t.Fatalf("expected positive score for repeated inbound service hits, got %d", score.Score)
	}
}

func TestScoreFromAgentEvent_UsesProvidedFields(t *testing.T) {
	event := &pb.ConnectionEvent{
		ThreatScore: 55,
		ThreatLevel: pb.ThreatLevel_THREAT_LEVEL_SUSPICIOUS,
		ThreatType:  pb.ThreatType_THREAT_TYPE_SERVICE_ABUSE,
		Direction:   pb.Direction_DIRECTION_INBOUND,
		Reasons:     []string{"Service abuse"},
	}

	score, ok := scoreFromAgentEvent(event)
	if !ok {
		t.Fatal("expected agent score to be considered present")
	}
	if score.Score != 55 {
		t.Fatalf("expected score 55, got %d", score.Score)
	}
	if score.Level != scoring.ThreatLevelSuspicious {
		t.Fatalf("expected suspicious level, got %s", score.Level)
	}
	if score.Type != scoring.ThreatTypeServiceAbuse {
		t.Fatalf("expected service_abuse type, got %s", score.Type)
	}
}
