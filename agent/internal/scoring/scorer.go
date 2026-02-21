// Package scoring provides threat scoring for the agent
// Simplified version for local use without backend dependencies
package scoring

import (
	"fmt"
	"math"
	"time"
)

// ThreatLevel represents the severity of a threat
type ThreatLevel string

const (
	ThreatLevelNormal     ThreatLevel = "normal"
	ThreatLevelSuspicious ThreatLevel = "suspicious"
	ThreatLevelMalicious  ThreatLevel = "malicious"
)

// IPMetrics represents aggregated data for an IP address
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

// ThreatScore represents the calculated score and classification
type ThreatScore struct {
	Score           int
	FinalScoreFloat float64
	Level           ThreatLevel
	Reasons         []string
	Timestamp       time.Time
	Confidence      float64
	IsBlockWorthy   bool
}

// ScoreComponents breaks down the score calculation
type ScoreComponents struct {
	SYNComponent      float64
	PortScanComponent float64
	FailedComponent   float64
	BurstComponent    float64
	WindowDuration    float64
}

// ThreatScorer implements threat scoring
type ThreatScorer struct {
	SYNRateWeight         float64
	UniquePortsWeight     float64
	FailedHandshakeWeight float64
	NormalSYNRate         float64
	SuspiciousSYNRate     float64
	PortScanThreshold     int
	FailedHandshakeRate   float64
	SuspiciousThreshold   int
	MaliciousThreshold    int
	AutoBlockThreshold    int
	MinWindowDuration     time.Duration
}

// NewThreatScorer creates a scorer with production-tuned defaults
func NewThreatScorer() *ThreatScorer {
	ts := &ThreatScorer{
		SYNRateWeight:         10.0,
		UniquePortsWeight:     2.0,
		FailedHandshakeWeight: 15.0,
		NormalSYNRate:         1.0,
		SuspiciousSYNRate:     5.0,
		PortScanThreshold:     20,
		FailedHandshakeRate:   2.0,
		SuspiciousThreshold:   30,
		MaliciousThreshold:    60,
		AutoBlockThreshold:    80,
		MinWindowDuration:     10 * time.Second,
	}
	
	// Safety guard
	if ts.AutoBlockThreshold < ts.MaliciousThreshold {
		ts.AutoBlockThreshold = ts.MaliciousThreshold
	}
	
	return ts
}

// CalculateScore applies rate-normalized scoring
func (ts *ThreatScorer) CalculateScore(metrics IPMetrics) ThreatScore {
	windowDuration := metrics.WindowEnd.Sub(metrics.WindowStart).Seconds()
	confidence := ts.calculateConfidence(windowDuration)
	
	if windowDuration < 1.0 {
		windowDuration = 1.0
	}
	
	// Clamp PreviousScore
	if metrics.PreviousScore > 100 {
		metrics.PreviousScore = 100
	} else if metrics.PreviousScore < 0 {
		metrics.PreviousScore = 0
	}
	
	// Calculate rates
	synRate := float64(metrics.SYNCount) / windowDuration
	failedRate := float64(metrics.FailedHandshakes) / windowDuration
	connectionRate := float64(metrics.TotalConnections) / windowDuration
	
	// Calculate components
	synComponent := ts.calculateSYNScore(synRate, metrics)
	portComponent := ts.calculatePortScore(metrics.UniquePorts, connectionRate, windowDuration)
	failedComponent := ts.calculateFailedScore(failedRate, metrics)
	burstComponent := ts.calculateBurstScore(connectionRate, windowDuration)
	
	// RST storm detection
	if metrics.RSTCount > 5 {
		if metrics.EstablishedConnections == 0 ||
			metrics.RSTCount > metrics.EstablishedConnections*2 {
			burstComponent += 3.0
		}
	}
	
	// Combine components
	rawScore := (synComponent * ts.SYNRateWeight) +
		(portComponent * ts.UniquePortsWeight) +
		(failedComponent * ts.FailedHandshakeWeight) +
		burstComponent
	
	// Service Port Whitelisting
	serviceHits := 0
	for _, port := range metrics.ServicePorts {
		if port == 80 || port == 443 || port == 22 || port == 53 {
			serviceHits++
		}
	}
	
	if serviceHits > 0 && metrics.UniquePorts > 0 {
		if serviceHits >= metrics.UniquePorts/2 {
			rawScore *= 0.8
		}
	}
	
	// Apply confidence penalty
	adjustedScore := rawScore * confidence
	
	// Apply decay if previous score exists
	if metrics.PreviousScore > 0 {
		adjustedScore = (float64(metrics.PreviousScore) * 0.7) + (adjustedScore * 0.3)
	}
	
	// Cap score
	if adjustedScore > 100 {
		adjustedScore = 100
	}
	finalScore := int(adjustedScore)
	
	// Classify
	level := ts.classifyThreat(finalScore, confidence)
	
	// Generate reasons
	reasons := ts.generateReasons(metrics, synRate, failedRate, connectionRate, windowDuration, confidence)
	
	// Determine if block worthy
	isBlockWorthy := level == ThreatLevelMalicious &&
		finalScore >= ts.AutoBlockThreshold &&
		confidence >= 0.8
	
	return ThreatScore{
		Score:         finalScore,
		FinalScoreFloat: adjustedScore,
		Level:         level,
		Reasons:       reasons,
		Timestamp:     time.Now(),
		Confidence:    confidence,
		IsBlockWorthy: isBlockWorthy,
	}
}

func (ts *ThreatScorer) calculateConfidence(duration float64) float64 {
	minDuration := ts.MinWindowDuration.Seconds()
	if duration >= minDuration {
		return 1.0
	}
	conf := duration / minDuration
	if conf < 0.1 {
		return 0.1
	}
	return conf
}

func (ts *ThreatScorer) calculateSYNScore(synRate float64, metrics IPMetrics) float64 {
	totalPackets := metrics.SYNCount + metrics.ACKCount
	if totalPackets > 10 {
		synRatio := float64(metrics.SYNCount) / float64(totalPackets)
		if synRatio < 0.65 && metrics.FailedHandshakes < 3 {
			return 0
		}
	}
	
	if synRate <= ts.NormalSYNRate {
		return 0
	}
	
	if synRate > ts.SuspiciousSYNRate {
		excess := synRate - ts.SuspiciousSYNRate
		return 5.0 + math.Log10(excess+1)*3.0
	}
	
	return (synRate - ts.NormalSYNRate) / ts.NormalSYNRate
}

func (ts *ThreatScorer) calculatePortScore(uniquePorts int, connectionRate float64, duration float64) float64 {
	if uniquePorts < 5 {
		return 0
	}
	
	portsPerSec := float64(uniquePorts) / duration
	portsPerConnection := float64(uniquePorts) / (connectionRate + 1)
	
	if portsPerConnection > 0.8 && uniquePorts > 10 {
		dynamicThreshold := math.Max(0.5, 5.0/duration)
		
		if portsPerSec > dynamicThreshold {
			excess := float64(uniquePorts - ts.PortScanThreshold)
			if excess > 0 {
				return 5.0 + math.Sqrt(excess)
			}
			return float64(uniquePorts) / 5.0
		}
	}
	
	return 0
}

func (ts *ThreatScorer) calculateFailedScore(failedRate float64, metrics IPMetrics) float64 {
	if failedRate <= 0.5 {
		return 0
	}
	
	totalAttempts := metrics.FailedHandshakes + metrics.EstablishedConnections
	if totalAttempts > 0 {
		failureRatio := float64(metrics.FailedHandshakes) / float64(totalAttempts)
		
		if failureRatio < 0.5 && metrics.EstablishedConnections > 5 {
			return 0
		}
		
		if failedRate > 5.0 && failureRatio > 0.6 {
			return 5.0 + (failedRate - ts.FailedHandshakeRate)
		}
		
		if failureRatio > 0.9 {
			return 5.0 + (failedRate - ts.FailedHandshakeRate)
		}
	}
	
	return (failedRate - ts.FailedHandshakeRate) * 2.0
}

func (ts *ThreatScorer) calculateBurstScore(rate float64, duration float64) float64 {
	if duration < 10.0 && rate > 20.0 {
		return 5.0
	}
	
	adaptiveThreshold := 10.0 * math.Max(1.0, duration/60.0)
	
	if rate > adaptiveThreshold {
		return math.Log10(rate/adaptiveThreshold) * 5.0
	}
	
	return 0
}

func (ts *ThreatScorer) classifyThreat(score int, confidence float64) ThreatLevel {
	if confidence < 0.1 {
		return ThreatLevelNormal
	}
	
	maliciousThreshold := int(float64(ts.MaliciousThreshold) / confidence)
	suspiciousThreshold := int(float64(ts.SuspiciousThreshold) / confidence)
	
	if score >= maliciousThreshold {
		return ThreatLevelMalicious
	} else if score >= suspiciousThreshold {
		return ThreatLevelSuspicious
	}
	return ThreatLevelNormal
}

func (ts *ThreatScorer) generateReasons(metrics IPMetrics, synRate, failedRate, connRate, duration, confidence float64) []string {
	reasons := []string{}
	prefix := ""
	if confidence < 0.5 {
		prefix = "(Low Confidence) "
	}
	
	if metrics.UniquePorts > ts.PortScanThreshold {
		portsPerSec := float64(metrics.UniquePorts) / duration
		reasons = append(reasons,
			fmt.Sprintf("%sPort scanning detected: %d unique ports (%.1f ports/sec)",
				prefix, metrics.UniquePorts, portsPerSec))
	}
	
	totalPackets := metrics.SYNCount + metrics.ACKCount
	if totalPackets > 10 {
		synRatio := float64(metrics.SYNCount) / float64(totalPackets)
		if synRatio > 0.75 && synRate > ts.SuspiciousSYNRate {
			reasons = append(reasons,
				fmt.Sprintf("%sPossible SYN flood: %.1f SYN/sec with %.0f%% SYN ratio",
					prefix, synRate, synRatio*100))
		}
	}
	
	if failedRate > ts.FailedHandshakeRate {
		failureRatio := 0.0
		totalAttempts := metrics.FailedHandshakes + metrics.EstablishedConnections
		if totalAttempts > 0 {
			failureRatio = float64(metrics.FailedHandshakes) / float64(totalAttempts) * 100
		}
		reasons = append(reasons,
			fmt.Sprintf("High failure rate: %.1f failed/sec (%.0f%% failure ratio)",
				failedRate, failureRatio))
	}
	
	if connRate > 15.0 {
		reasons = append(reasons,
			fmt.Sprintf("Connection burst: %.1f connections/sec", connRate))
	}
	
	if duration < ts.MinWindowDuration.Seconds() {
		reasons = append(reasons,
			fmt.Sprintf("Limited observation time (%.1fs) - confidence: %.0f%%",
				duration, ts.calculateConfidence(duration)*100))
	}
	
	if len(reasons) == 0 {
		reasons = append(reasons, "Normal traffic pattern")
	}
	
	return reasons
}
