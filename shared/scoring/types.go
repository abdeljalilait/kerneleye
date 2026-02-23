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

type ThreatType string

const (
	ThreatTypeNone            ThreatType = "none"
	ThreatTypePortScan        ThreatType = "port_scan"
	ThreatTypeServiceAbuse    ThreatType = "service_abuse"
	ThreatTypeSynFlood        ThreatType = "syn_flood"
	ThreatTypeFailedHandshake ThreatType = "failed_handshake"
	ThreatTypeConnectionBurst ThreatType = "connection_burst"
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
	PreviousScore          int
	ServicePorts           []int

	PortHits    map[int]int // port -> hit count
	MaxPortHits int         // max hits to single port
	PrimaryPort int         // most hit port
}

type ThreatScore struct {
	Score           int
	FinalScoreFloat float64
	Level           ThreatLevel
	Type            ThreatType
	Reasons         []string
	Timestamp       time.Time
	Confidence      float64
	RawMetrics      ScoreComponents
}

type ScoreComponents struct {
	SYNComponent          float64
	PortScanComponent     float64
	FailedComponent       float64
	BurstComponent        float64
	ServiceAbuseComponent float64
	WindowDuration        float64
}
