// SPDX-License-Identifier: AGPL-3.0-only

package scoring

import (
	"fmt"
	"math"
	"time"
)

type ThreatScorer struct {
	SYNRateWeight         float64
	UniquePortsWeight     float64
	FailedHandshakeWeight float64
	ServiceAbuseWeight    float64

	NormalSYNRate         float64
	SuspiciousSYNRate     float64
	PortScanThreshold     int
	FailedHandshakeRate   float64
	ServiceAbuseThreshold int

	SuspiciousThreshold int
	MaliciousThreshold  int

	AutoBlockThreshold int
	MinWindowDuration  time.Duration

	// Score decay settings - how fast old scores fade
	// DecayRate: score multiplier per hour (e.g., 0.9 = 10% decay per hour)
	// After 6 hours at 0.9: score = original * 0.9^6 ≈ 0.53 (half decay)
	// After 24 hours at 0.9: score = original * 0.9^24 ≈ 0.08 (near zero)
	ScoreDecayRate float64
}

func NewThreatScorer() *ThreatScorer {
	ts := &ThreatScorer{
		SYNRateWeight:         10.0,
		UniquePortsWeight:     2.0,
		FailedHandshakeWeight: 15.0,
		ServiceAbuseWeight:    8.0,

		NormalSYNRate:         0.05,
		SuspiciousSYNRate:     1.0,
		PortScanThreshold:     3,
		FailedHandshakeRate:   0.5,
		ServiceAbuseThreshold: 5,

		SuspiciousThreshold: 20,
		MaliciousThreshold:  40,
		AutoBlockThreshold:  40,

		MinWindowDuration: 10 * time.Second,

		// Score decays ~5% per hour (0.95^6 ≈ 0.74 after 6 hours)
		// This allows blocked IPs to "cool down" over time without losing all history
		ScoreDecayRate: 0.95,
	}

	if ts.AutoBlockThreshold < ts.MaliciousThreshold {
		ts.AutoBlockThreshold = ts.MaliciousThreshold
	}

	return ts
}

func (ts *ThreatScorer) CalculateScore(metrics IPMetrics) ThreatScore {
	windowDuration := metrics.WindowEnd.Sub(metrics.WindowStart).Seconds()

	confidence := ts.calculateConfidence(windowDuration)

	// Use effective window for rate calculations to prevent inflated scores
	// from short observation windows (e.g., single event in <1 second)
	effectiveWindow := windowDuration
	if effectiveWindow < ts.MinWindowDuration.Seconds() {
		effectiveWindow = ts.MinWindowDuration.Seconds()
	}
	if effectiveWindow < 1.0 {
		effectiveWindow = 1.0
	}

	if metrics.PreviousScore > 100 {
		metrics.PreviousScore = 100
	} else if metrics.PreviousScore < 0 {
		metrics.PreviousScore = 0
	}

	synRate := float64(metrics.SYNCount) / effectiveWindow
	failedRate := float64(metrics.FailedHandshakes) / effectiveWindow
	connectionRate := float64(metrics.TotalConnections) / effectiveWindow

	synComponent := ts.calculateSYNScore(synRate, metrics)
	portComponent := ts.calculatePortScore(metrics, connectionRate, windowDuration)
	failedComponent := ts.calculateFailedScore(failedRate, metrics)
	burstComponent := ts.calculateBurstScore(connectionRate, windowDuration, metrics.TotalConnections)
	serviceComponent := ts.calculateServiceAbuseScore(metrics, effectiveWindow)

	if metrics.RSTCount > 5 {
		if metrics.EstablishedConnections == 0 ||
			metrics.RSTCount > metrics.EstablishedConnections*2 {
			burstComponent += 3.0
		}
	}

	rawScore := (synComponent * ts.SYNRateWeight) +
		(portComponent * ts.UniquePortsWeight) +
		(failedComponent * ts.FailedHandshakeWeight) +
		(serviceComponent * ts.ServiceAbuseWeight) +
		burstComponent

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

	adjustedScore := rawScore

	if metrics.PreviousScore > 0 && !metrics.LastSeen.IsZero() {
		// Apply time-decay to previous score based on time since last observation
		// This allows scores to naturally decrease over time if no new traffic
		decayedPreviousScore := ts.applyTimeDecay(float64(metrics.PreviousScore), metrics.LastSeen)

		// Asymmetric scoring: increase fast, decay slow
		// Attack detection must rise fast and decay slowly
		if adjustedScore > decayedPreviousScore {
			// Rising threat - aggressive increase (70% new, 30% history)
			adjustedScore = (adjustedScore * 0.7) + (decayedPreviousScore * 0.3)
		} else {
			// Decreasing threat - slow decay (30% new, 70% history)
			adjustedScore = (adjustedScore * 0.3) + (decayedPreviousScore * 0.7)
		}
	}

	// Cap score for low-confidence, low-volume events
	// Single events or very short windows shouldn't trigger high scores
	totalEvents := metrics.SYNCount + metrics.ACKCount + metrics.FailedHandshakes
	if confidence < 0.5 && totalEvents < 5 {
		// Maximum score of 40 for low-confidence, low-volume events
		maxScore := 40.0
		if adjustedScore > maxScore {
			adjustedScore = maxScore
		}
	}

	// Outbound connections with low volume should never be considered malicious
	if metrics.Direction == DirectionOutbound && totalEvents <= 3 {
		maxScore := 30.0
		if adjustedScore > maxScore {
			adjustedScore = maxScore
		}
	}

	if adjustedScore > 100 {
		adjustedScore = 100
	}
	finalScore := int(adjustedScore)

	level := ts.classifyThreat(finalScore)
	threatType := ts.classifyThreatType(metrics, synComponent, portComponent, failedComponent, serviceComponent, burstComponent)
	reasons := ts.generateReasons(metrics, synRate, failedRate, connectionRate, windowDuration)

	return ThreatScore{
		Score:           finalScore,
		FinalScoreFloat: adjustedScore,
		Level:           level,
		Type:            threatType,
		Reasons:         reasons,
		Timestamp:       time.Now(),
		Confidence:      confidence,
		Direction:       metrics.Direction,
		RawMetrics: ScoreComponents{
			SYNComponent:          synComponent,
			PortScanComponent:     portComponent,
			FailedComponent:       failedComponent,
			BurstComponent:        burstComponent,
			ServiceAbuseComponent: serviceComponent,
			WindowDuration:        windowDuration,
		},
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

func (ts *ThreatScorer) calculatePortScore(metrics IPMetrics, connectionRate float64, duration float64) float64 {
	// Use both window-based and cumulative unique ports for slow scan detection
	uniquePorts := metrics.UniquePorts
	cumulativePorts := metrics.CumulativeUniquePorts

	if uniquePorts < ts.PortScanThreshold && cumulativePorts < ts.PortScanThreshold*2 {
		return 0
	}

	if duration <= 0 {
		duration = ts.MinWindowDuration.Seconds()
		if duration <= 0 {
			duration = 1
		}
	}

	portsPerSec := float64(uniquePorts) / duration
	portsPerConnection := float64(uniquePorts) / (connectionRate + 1)
	dynamicThreshold := math.Max(0.5, 5.0/duration)
	excess := float64(uniquePorts - ts.PortScanThreshold)
	if excess < 0 {
		excess = 0
	}

	score := 0.0

	// Fast scan detection (high rate)
	if portsPerConnection <= 0.8 {
		// Lower-confidence signal: broad but less concentrated access pattern.
		if uniquePorts >= ts.PortScanThreshold+3 && portsPerSec > dynamicThreshold*1.5 {
			score = 1.0 + excess*0.25
		}
	} else if uniquePorts <= 10 {
		// Mid-range scans (5-10 ports) should still contribute a small signal.
		if portsPerSec >= dynamicThreshold*0.6 {
			score = 1.0 + excess*0.4
		}
	} else if portsPerSec > dynamicThreshold {
		score = 5.0 + math.Sqrt(excess)
	}

	// Slow scan detection using cumulative ports over extended time
	// Catches: 1 port every 10 seconds = 60 ports over 10 minutes
	if cumulativePorts >= ts.PortScanThreshold*3 && metrics.CumulativeWindowHours > 0.5 {
		// Calculate cumulative rate: ports per hour
		cumulativeRate := float64(cumulativePorts) / metrics.CumulativeWindowHours
		// Even slow accumulation is suspicious if sustained
		if cumulativeRate > 10.0 { // 10+ ports per hour sustained
			slowScanScore := math.Log10(cumulativeRate) * 2.0
			if slowScanScore > score {
				score = slowScanScore
			}
		}
	}

	return score
}

func (ts *ThreatScorer) calculateFailedScore(failedRate float64, metrics IPMetrics) float64 {
	// Require minimum failed handshakes before scoring (prevents single-event high scores)
	if metrics.FailedHandshakes < 3 {
		return 0
	}

	// Outbound connections are typically legitimate client connections
	// Be less aggressive with failed handshake scoring for outbound traffic
	isOutbound := metrics.Direction == DirectionOutbound
	thresholdMultiplier := 1.0
	if isOutbound {
		thresholdMultiplier = 2.0 // Higher threshold for outbound
	}

	if failedRate <= ts.FailedHandshakeRate*thresholdMultiplier {
		return 0
	}

	totalAttempts := metrics.FailedHandshakes + metrics.EstablishedConnections
	if totalAttempts > 0 {
		failureRatio := float64(metrics.FailedHandshakes) / float64(totalAttempts)

		// High success rate means likely legitimate traffic
		if failureRatio < 0.5 && metrics.EstablishedConnections > 5 {
			return 0
		}

		// Only flag as malicious with high failure rate AND high rate
		if failedRate > 5.0*thresholdMultiplier && failureRatio > 0.6 {
			base := 3.0
			if isOutbound {
				base = 2.0 // Lower base for outbound
			}
			return base + (failedRate - ts.FailedHandshakeRate*thresholdMultiplier)
		}

		// Extreme failure ratio is suspicious regardless of direction
		if failureRatio > 0.9 && metrics.FailedHandshakes >= 5 {
			return 3.0 + (failedRate - ts.FailedHandshakeRate)
		}
	}

	// Default case: small penalty for moderate failures
	penalty := (failedRate - ts.FailedHandshakeRate*thresholdMultiplier) * 1.5
	if isOutbound {
		penalty *= 0.5 // Halve penalty for outbound
	}
	return penalty
}

func (ts *ThreatScorer) calculateServiceAbuseScore(metrics IPMetrics, windowDuration float64) float64 {
	if metrics.MaxPortHits < ts.ServiceAbuseThreshold {
		return 0
	}

	// Calculate rate (hits per second) instead of raw hits
	// 100 hits in 1 second = very different from 100 hits in 10 minutes
	effectiveWindow := windowDuration
	if effectiveWindow < 1.0 {
		effectiveWindow = 1.0
	}
	hitsPerSec := float64(metrics.MaxPortHits) / effectiveWindow

	// Rate-based severity: high instantaneous rate indicates flood/burst attacks
	var severity float64
	switch {
	case hitsPerSec >= 50.0:
		severity = 10.0
	case hitsPerSec >= 25.0:
		severity = 7.0
	case hitsPerSec >= 10.0:
		severity = 5.0
	default:
		severity = 3.0
	}

	// Volume-based severity: high absolute connection count indicates sustained
	// brute force (e.g. SSH credential stuffing that completes each TCP handshake,
	// keeping the rate low but the total hit count very high).
	var volumeSeverity float64
	switch {
	case metrics.MaxPortHits >= 1000:
		volumeSeverity = 10.0
	case metrics.MaxPortHits >= 500:
		volumeSeverity = 8.0
	case metrics.MaxPortHits >= 200:
		volumeSeverity = 6.0
	case metrics.MaxPortHits >= 100:
		volumeSeverity = 4.0
	}
	if volumeSeverity > severity {
		severity = volumeSeverity
	}

	return severity
}

func (ts *ThreatScorer) calculateBurstScore(rate float64, duration float64, totalConnections int) float64 {
	// Check both rate AND absolute volume
	// High rate with low volume = less concerning
	// Moderate rate with high volume = sustained attack

	// Short burst detection (high rate, short window)
	if duration < 10.0 && rate > 20.0 {
		return 5.0
	}

	// Volume-based detection - sustained high volume is suspicious
	// 500+ connections in any window is notable
	volumeScore := 0.0
	if totalConnections > 1000 {
		volumeScore = 3.0
	} else if totalConnections > 500 {
		volumeScore = 2.0
	} else if totalConnections > 200 {
		volumeScore = 1.0
	}

	adaptiveThreshold := 10.0 * math.Max(1.0, duration/60.0)

	if rate > adaptiveThreshold {
		return math.Log10(rate/adaptiveThreshold)*5.0 + volumeScore
	}

	return volumeScore
}

func (ts *ThreatScorer) classifyThreat(score int) ThreatLevel {
	if score >= ts.MaliciousThreshold {
		return ThreatLevelMalicious
	} else if score >= ts.SuspiciousThreshold {
		return ThreatLevelSuspicious
	}
	return ThreatLevelNormal
}

func (ts *ThreatScorer) classifyThreatType(metrics IPMetrics, syn, port, failed, service, burst float64) ThreatType {
	type candidate struct {
		threatType ThreatType
		value      float64
		priority   int // lower wins on tie
	}

	candidates := []candidate{
		{threatType: ThreatTypeServiceAbuse, value: service, priority: 0},
		{threatType: ThreatTypePortScan, value: port, priority: 1},
		{threatType: ThreatTypeSynFlood, value: syn, priority: 2},
		{threatType: ThreatTypeFailedHandshake, value: failed, priority: 3},
		{threatType: ThreatTypeConnectionBurst, value: burst, priority: 4},
	}

	bestType := ThreatTypeNone
	bestValue := 0.0
	bestPriority := math.MaxInt

	for _, c := range candidates {
		if c.value <= 0 {
			continue
		}

		switch c.threatType {
		case ThreatTypePortScan:
			if metrics.UniquePorts < ts.PortScanThreshold {
				continue
			}
		case ThreatTypeServiceAbuse:
			if metrics.MaxPortHits < ts.ServiceAbuseThreshold {
				continue
			}
		case ThreatTypeConnectionBurst:
			if c.value <= 5.0 {
				continue
			}
		}

		if c.value > bestValue || (c.value == bestValue && c.priority < bestPriority) {
			bestType = c.threatType
			bestValue = c.value
			bestPriority = c.priority
		}
	}

	return bestType
}

func (ts *ThreatScorer) generateReasons(metrics IPMetrics, synRate, failedRate, connRate, duration float64) []string {
	reasons := []string{}

	if metrics.MaxPortHits >= ts.ServiceAbuseThreshold {
		serviceName := ts.getServiceName(metrics.PrimaryPort)
		reasons = append(reasons, fmt.Sprintf("Service abuse: %d hits on port %d (%s)",
			metrics.MaxPortHits, metrics.PrimaryPort, serviceName))
	}

	if metrics.UniquePorts >= ts.PortScanThreshold {
		portsPerSec := float64(metrics.UniquePorts) / duration
		reasons = append(reasons, fmt.Sprintf("Port scanning: %d unique ports (%.1f ports/sec)",
			metrics.UniquePorts, portsPerSec))
	}

	totalPackets := metrics.SYNCount + metrics.ACKCount
	if totalPackets > 10 {
		synRatio := float64(metrics.SYNCount) / float64(totalPackets)
		if synRatio > 0.75 && synRate > ts.SuspiciousSYNRate {
			reasons = append(reasons, fmt.Sprintf("SYN flood: %.1f SYN/sec (%.0f%% SYN ratio)",
				synRate, synRatio*100))
		}
	}

	if failedRate > ts.FailedHandshakeRate {
		failureRatio := 0.0
		totalAttempts := metrics.FailedHandshakes + metrics.EstablishedConnections
		if totalAttempts > 0 {
			failureRatio = float64(metrics.FailedHandshakes) / float64(totalAttempts) * 100
		}
		reasons = append(reasons, fmt.Sprintf("Failed handshakes: %.1f/sec (%.0f%% failure ratio)",
			failedRate, failureRatio))
	}

	if connRate > 15.0 {
		reasons = append(reasons, fmt.Sprintf("Connection burst: %.1f connections/sec", connRate))
	}

	if len(reasons) == 0 {
		reasons = append(reasons, "Normal traffic")
	}

	return reasons
}

func (ts *ThreatScorer) getServiceName(port int) string {
	services := map[int]string{
		22:    "SSH",
		80:    "HTTP",
		443:   "HTTPS",
		25:    "SMTP",
		3306:  "MySQL",
		5432:  "PostgreSQL",
		6379:  "Redis",
		27017: "MongoDB",
		21:    "FTP",
		23:    "Telnet",
		3389:  "RDP",
		587:   "SMTP",
		110:   "POP3",
		143:   "IMAP",
	}
	if name, ok := services[port]; ok {
		return name
	}
	return "Unknown"
}

func (ts *ThreatScorer) IsBlockWorthy(score ThreatScore) bool {
	return score.Level == ThreatLevelMalicious &&
		score.Score >= ts.AutoBlockThreshold &&
		score.Confidence >= 0.5
}

func (ts *ThreatScorer) CalculateBatchScores(metricsMap map[string]IPMetrics) map[string]ThreatScore {
	scores := make(map[string]ThreatScore, len(metricsMap))
	for ip, metrics := range metricsMap {
		scores[ip] = ts.CalculateScore(metrics)
	}
	return scores
}

func (ts *ThreatScorer) AdjustThresholdsForEnvironment(avgSYNRate, avgConnectionRate float64) {
	ts.NormalSYNRate = avgSYNRate * 1.5
	ts.SuspiciousSYNRate = avgSYNRate * 5.0
}

// applyTimeDecay applies exponential decay to a score based on time elapsed
// Score decreases exponentially: newScore = oldScore * (decayRate ^ hours)
// At decayRate=0.85: after 6h=38%, after 24h=8%, after 48h=0.6%
func (ts *ThreatScorer) applyTimeDecay(score float64, lastSeen time.Time) float64 {
	if score <= 0 {
		return 0
	}

	hoursSince := time.Since(lastSeen).Hours()
	if hoursSince <= 0 {
		return score // No decay for current/future times
	}

	// Exponential decay: score * (decayRate ^ hours)
	decayFactor := math.Pow(ts.ScoreDecayRate, hoursSince)
	decayedScore := score * decayFactor

	// Minimum threshold - scores below 5 effectively become 0
	if decayedScore < 5 {
		return 0
	}

	return decayedScore
}
