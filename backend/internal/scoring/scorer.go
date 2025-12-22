package scoring

import (
	"fmt"
	"math"
	"time"
)

// ThreatScorer implements an improved scoring model with rate normalization
type ThreatScorer struct {
	// Base weights for scoring components
	SYNRateWeight         float64
	UniquePortsWeight     float64
	FailedHandshakeWeight float64

	// Thresholds (rates per second)
	NormalSYNRate       float64 // Expected normal SYN rate
	SuspiciousSYNRate   float64 // Rate that indicates scanning
	PortScanThreshold   int     // Number of unique ports before suspicious
	FailedHandshakeRate float64 // Failed handshakes per second threshold

	// Score thresholds
	SuspiciousThreshold int
	MaliciousThreshold  int

	// Auto-block configuration
	AutoBlockThreshold int
	MinWindowDuration  time.Duration // Minimum observation time before scoring
}

// IPMetrics represents aggregated data for an IP address
type IPMetrics struct {
	SYNCount         int
	ACKCount         int
	RSTCount         int // Track RST packets separately
	FailedHandshakes int
	UniquePorts      int
	TotalConnections int
	BytesIn          uint64
	BytesOut         uint64
	WindowStart      time.Time
	WindowEnd        time.Time

	// Additional context
	EstablishedConnections int   // Successfully completed connections
	ServicePorts           []int // Ports the IP is legitimately connecting to
	PreviousScore          int   // Score from previous window for decay
}

// ThreatScore represents the calculated score and classification
type ThreatScore struct {
	Score           int
	NormalizedScore float64 // 0-100 normalized score
	Level           ThreatLevel
	Reasons         []string
	Timestamp       time.Time
	Confidence      float64 // 0-1, based on observation window
	RawMetrics      ScoreComponents
}

// ScoreComponents breaks down the score calculation
type ScoreComponents struct {
	SYNComponent      float64
	PortScanComponent float64
	FailedComponent   float64
	BurstComponent    float64
	WindowDuration    float64
}

type ThreatLevel string

const (
	ThreatLevelNormal     ThreatLevel = "normal"
	ThreatLevelSuspicious ThreatLevel = "suspicious"
	ThreatLevelMalicious  ThreatLevel = "malicious"
)

// NewThreatScorer creates a scorer with production-tuned defaults
func NewThreatScorer() *ThreatScorer {
	return &ThreatScorer{
		// Weights
		SYNRateWeight:         10.0,
		UniquePortsWeight:     2.0,
		FailedHandshakeWeight: 15.0,

		// Rate thresholds (per second)
		NormalSYNRate:       1.0, // 1 SYN/sec is normal
		SuspiciousSYNRate:   5.0, // 5+ SYN/sec starts to look like scanning
		PortScanThreshold:   20,  // 20+ unique ports is suspicious
		FailedHandshakeRate: 2.0, // 2+ failed/sec is suspicious

		// Score thresholds
		SuspiciousThreshold: 30,
		MaliciousThreshold:  60,
		AutoBlockThreshold:  80,

		// Minimum 10 seconds of observation before scoring
		MinWindowDuration: 10 * time.Second,
	}
}

// CalculateScore applies rate-normalized scoring with false positive reduction
func (ts *ThreatScorer) CalculateScore(metrics IPMetrics) ThreatScore {
	windowDuration := metrics.WindowEnd.Sub(metrics.WindowStart).Seconds()

	// Confidence increases with observation time (0-1 scale)
	confidence := ts.calculateConfidence(windowDuration)

	// Ensure minimum duration to avoid false positives on short windows
	if windowDuration < 1.0 {
		windowDuration = 1.0
	}

	// Calculate rate-normalized components
	synRate := float64(metrics.SYNCount) / windowDuration
	failedRate := float64(metrics.FailedHandshakes) / windowDuration
	connectionRate := float64(metrics.TotalConnections) / windowDuration

	// SYN flood detection (with exponential scaling above threshold)
	synComponent := ts.calculateSYNScore(synRate, metrics)

	// Port scanning detection (non-linear scaling)
	portComponent := ts.calculatePortScore(metrics.UniquePorts, connectionRate)

	// Failed connection detection (rate-based)
	failedComponent := ts.calculateFailedScore(failedRate, metrics)

	// Connection burst detection (adaptive threshold)
	burstComponent := ts.calculateBurstScore(connectionRate, windowDuration)

	// RST storm detection
	if metrics.RSTCount > metrics.EstablishedConnections*2 && metrics.RSTCount > 5 {
		burstComponent += 3.0
	}

	// Combine components with weights
	rawScore := (synComponent * ts.SYNRateWeight) +
		(portComponent * ts.UniquePortsWeight) +
		(failedComponent * ts.FailedHandshakeWeight) +
		burstComponent

	// Service Port Whitelisting (Reduction)
	for _, port := range metrics.ServicePorts {
		// Common service ports (HTTP, HTTPS, SSH, DNS, etc.)
		if port == 80 || port == 443 || port == 22 || port == 53 {
			rawScore *= 0.8 // 20% reduction for known service ports
			break           // Only apply once
		}
	}

	// Apply confidence penalty for short observation windows
	adjustedScore := rawScore * confidence

	// Apply decay if previous score exists
	if metrics.PreviousScore > 0 {
		// CrowdSec-style decay: blend previous and current
		// This provides memory between windows
		adjustedScore = (float64(metrics.PreviousScore) * 0.7) + (adjustedScore * 0.3)
	}

	// Cap the score and normalize explicit
	if adjustedScore > 100 {
		adjustedScore = 100
	}
	finalScore := int(adjustedScore)

	// Determine threat level with hysteresis
	level := ts.classifyThreat(finalScore, confidence)

	// Generate detailed reasons
	reasons := ts.generateReasons(metrics, synRate, failedRate, connectionRate, windowDuration)

	return ThreatScore{
		Score:           finalScore,
		NormalizedScore: adjustedScore,
		Level:           level,
		Reasons:         reasons,
		Timestamp:       time.Now(),
		Confidence:      confidence,
		RawMetrics: ScoreComponents{
			SYNComponent:      synComponent,
			PortScanComponent: portComponent,
			FailedComponent:   failedComponent,
			BurstComponent:    burstComponent,
			WindowDuration:    windowDuration,
		},
	}
}

// calculateConfidence returns confidence based on observation window
func (ts *ThreatScorer) calculateConfidence(duration float64) float64 {
	minDuration := ts.MinWindowDuration.Seconds()
	if duration >= minDuration {
		return 1.0
	}
	// Linear ramp-up to minimum duration, clamped to min 0.1 to avoid div-by-zero
	conf := duration / minDuration
	if conf < 0.1 {
		return 0.1
	}
	return conf
}

// calculateSYNScore with non-linear scaling for attack detection
func (ts *ThreatScorer) calculateSYNScore(synRate float64, metrics IPMetrics) float64 {
	// Check SYN/ACK ratio - legitimate traffic should have balanced SYN/ACK
	totalPackets := metrics.SYNCount + metrics.ACKCount
	if totalPackets > 10 { // Need minimum sample size
		synRatio := float64(metrics.SYNCount) / float64(totalPackets)
		// Normal traffic: ~50% SYN, ~50% ACK
		// SYN flood: >80% SYN
		if synRatio < 0.65 {
			// Balanced SYN/ACK ratio = likely legitimate
			return 0
		}
	}

	if synRate <= ts.NormalSYNRate {
		return 0
	}

	// Exponential scaling above suspicious threshold
	if synRate > ts.SuspiciousSYNRate {
		excess := synRate - ts.SuspiciousSYNRate
		return 5.0 + math.Log10(excess+1)*3.0
	}

	// Linear scaling in suspicious range
	return (synRate - ts.NormalSYNRate) / ts.NormalSYNRate
}

// calculatePortScore with context awareness
func (ts *ThreatScorer) calculatePortScore(uniquePorts int, connectionRate float64) float64 {
	if uniquePorts < 5 {
		return 0 // Very few ports = likely legitimate
	}

	// Port scanning typically has high port diversity with low connection rate per port
	portsPerConnection := float64(uniquePorts) / (connectionRate + 1)

	if portsPerConnection > 0.8 && uniquePorts > 10 {
		// High port diversity = scanning
		excess := float64(uniquePorts - ts.PortScanThreshold)
		if excess > 0 {
			return 5.0 + math.Sqrt(excess)
		}
		return float64(uniquePorts) / 5.0
	}

	// Concentrated traffic to few ports = likely legitimate
	return 0
}

// calculateFailedScore distinguishes between different failure types
func (ts *ThreatScorer) calculateFailedScore(failedRate float64, metrics IPMetrics) float64 {
	if failedRate <= 0.5 {
		return 0 // Low failure rate = normal
	}

	// Check if there are successful connections too
	totalAttempts := metrics.FailedHandshakes + metrics.EstablishedConnections
	if totalAttempts > 0 {
		failureRatio := float64(metrics.FailedHandshakes) / float64(totalAttempts)

		// Some successful connections = might be legitimate service with occasional failures
		if failureRatio < 0.5 && metrics.EstablishedConnections > 5 {
			return 0
		}

		// Absolute failure check for slow brute force
		if failedRate > 5.0 && failureRatio > 0.6 {
			return 5.0 + (failedRate - ts.FailedHandshakeRate)
		}

		// High failure rate with no successes = scanning
		if failureRatio > 0.9 {
			return 5.0 + (failedRate - ts.FailedHandshakeRate)
		}
	}

	return (failedRate - ts.FailedHandshakeRate) * 2.0
}

// calculateBurstScore detects abnormal connection bursts
func (ts *ThreatScorer) calculateBurstScore(rate float64, duration float64) float64 {
	// Strict check for short-term bursts
	if duration < 10.0 && rate > 20.0 {
		return 5.0
	}

	// Allow higher rates for longer observation windows (sustained traffic = likely legitimate)
	adaptiveThreshold := 10.0 * math.Max(1.0, duration/60.0)

	if rate > adaptiveThreshold {
		return math.Log10(rate/adaptiveThreshold) * 5.0
	}

	return 0
}

// classifyThreat with confidence-aware thresholds
func (ts *ThreatScorer) classifyThreat(score int, confidence float64) ThreatLevel {
	// Guard against division by zero (though calculateConfidence now clamps to 0.1)
	if confidence < 0.1 {
		return ThreatLevelNormal
	}

	// Require higher scores for low-confidence classifications
	maliciousThreshold := int(float64(ts.MaliciousThreshold) / confidence)
	suspiciousThreshold := int(float64(ts.SuspiciousThreshold) / confidence)

	if score >= maliciousThreshold {
		return ThreatLevelMalicious
	} else if score >= suspiciousThreshold {
		return ThreatLevelSuspicious
	}
	return ThreatLevelNormal
}

// generateReasons creates detailed, actionable explanations
func (ts *ThreatScorer) generateReasons(metrics IPMetrics, synRate, failedRate, connRate, duration float64) []string {
	reasons := []string{}

	// Port scanning with specifics
	if metrics.UniquePorts > ts.PortScanThreshold {
		portsPerSec := float64(metrics.UniquePorts) / duration
		reasons = append(reasons,
			fmt.Sprintf("Port scanning detected: %d unique ports (%.1f ports/sec)",
				metrics.UniquePorts, portsPerSec))
	}

	// SYN flood with ratio
	totalPackets := metrics.SYNCount + metrics.ACKCount
	if totalPackets > 10 {
		synRatio := float64(metrics.SYNCount) / float64(totalPackets)
		if synRatio > 0.75 && synRate > ts.SuspiciousSYNRate {
			reasons = append(reasons,
				fmt.Sprintf("Possible SYN flood: %.1f SYN/sec with %.0f%% SYN ratio",
					synRate, synRatio*100))
		}
	}

	// Failed connections with context
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

	// Connection burst
	if connRate > 15.0 {
		reasons = append(reasons,
			fmt.Sprintf("Connection burst: %.1f connections/sec", connRate))
	}

	// Low confidence warning
	if duration < ts.MinWindowDuration.Seconds() {
		reasons = append(reasons,
			fmt.Sprintf("Limited observation time (%.1fs) - confidence: %.0f%%",
				duration, ts.calculateConfidence(duration)*100))
	}

	// Default reason
	if len(reasons) == 0 {
		reasons = append(reasons, "Normal traffic pattern")
	}

	return reasons
}

// IsBlockWorthy determines if IP should be auto-blocked
func (ts *ThreatScorer) IsBlockWorthy(score ThreatScore) bool {
	// Conservative blocking: require high score, high confidence, and malicious classification
	return score.Level == ThreatLevelMalicious &&
		score.Score >= ts.AutoBlockThreshold &&
		score.Confidence >= 0.8
}

// CalculateBatchScores processes multiple IPs efficiently
func (ts *ThreatScorer) CalculateBatchScores(metricsMap map[string]IPMetrics) map[string]ThreatScore {
	scores := make(map[string]ThreatScore, len(metricsMap))
	for ip, metrics := range metricsMap {
		scores[ip] = ts.CalculateScore(metrics)
	}
	return scores
}

// AdjustThresholdsForEnvironment allows runtime tuning based on observed traffic
func (ts *ThreatScorer) AdjustThresholdsForEnvironment(avgSYNRate, avgConnectionRate float64) {
	// Auto-tune thresholds based on baseline traffic (to be called after baseline period)
	ts.NormalSYNRate = avgSYNRate * 1.5
	ts.SuspiciousSYNRate = avgSYNRate * 5.0
}
