package scoring

import (
	"time"
)

type ThreatLevel string

const (
	ThreatLevelNormal     ThreatLevel = "normal"
	ThreatLevelSuspicious ThreatLevel = "suspicious"
	ThreatLevelMalicious  ThreatLevel = "malicious"
)

type IPMetrics struct {
	SYNCount         int
	ACKCount         int
	RSTCount         int
	FailedHandshakes int
	UniquePorts      int
	TotalConnections int
	BytesIn          uint64
	BytesOut         uint64
	WindowStart      time.Time
	WindowEnd        time.Time

	EstablishedConnections int
	ServicePorts           []int
	PreviousScore          int
}

type ThreatScore struct {
	Score           int
	FinalScoreFloat float64
	Level           ThreatLevel
	Reasons         []string
	Timestamp       time.Time
	Confidence      float64
	RawMetrics      ScoreComponents
}

type ScoreComponents struct {
	SYNComponent      float64
	PortScanComponent float64
	FailedComponent   float64
	BurstComponent    float64
	WindowDuration    float64
}
