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
}

func NewThreatScorer() *ThreatScorer {
	ts := &ThreatScorer{
		SYNRateWeight:         10.0,
		UniquePortsWeight:     2.0,
		FailedHandshakeWeight: 15.0,
		ServiceAbuseWeight:    8.0,

		NormalSYNRate:         0.1,
		SuspiciousSYNRate:     1.0,
		PortScanThreshold:     5,
		FailedHandshakeRate:   0.5,
		ServiceAbuseThreshold: 10,

		SuspiciousThreshold: 30,
		MaliciousThreshold:  60,
		AutoBlockThreshold:  60,

		MinWindowDuration: 10 * time.Second,
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
	portComponent := ts.calculatePortScore(metrics.UniquePorts, connectionRate, windowDuration)
	failedComponent := ts.calculateFailedScore(failedRate, metrics)
	burstComponent := ts.calculateBurstScore(connectionRate, windowDuration)
	serviceComponent := ts.calculateServiceAbuseScore(metrics)

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

	if metrics.PreviousScore > 0 {
		adjustedScore = (float64(metrics.PreviousScore) * 0.7) + (adjustedScore * 0.3)
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

func (ts *ThreatScorer) calculatePortScore(uniquePorts int, connectionRate float64, duration float64) float64 {
	if uniquePorts < ts.PortScanThreshold {
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

func (ts *ThreatScorer) calculateServiceAbuseScore(metrics IPMetrics) float64 {
	if metrics.MaxPortHits < ts.ServiceAbuseThreshold {
		return 0
	}

	hits := metrics.MaxPortHits

	if hits < 10 {
		return 0
	}

	var severity float64
	switch {
	case hits >= 100:
		severity = 10.0
	case hits >= 50:
		severity = 7.0
	case hits >= 25:
		severity = 5.0
	default:
		severity = 3.0
	}

	return severity
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

func (ts *ThreatScorer) classifyThreat(score int) ThreatLevel {
	if score >= ts.MaliciousThreshold {
		return ThreatLevelMalicious
	} else if score >= ts.SuspiciousThreshold {
		return ThreatLevelSuspicious
	}
	return ThreatLevelNormal
}

func (ts *ThreatScorer) classifyThreatType(metrics IPMetrics, syn, port, failed, service, burst float64) ThreatType {
	maxComponent := syn
	threatType := ThreatTypeNone

	if port > maxComponent && metrics.UniquePorts >= ts.PortScanThreshold {
		maxComponent = port
		threatType = ThreatTypePortScan
	}

	if service > maxComponent && metrics.MaxPortHits >= ts.ServiceAbuseThreshold {
		maxComponent = service
		threatType = ThreatTypeServiceAbuse
	}

	if syn > maxComponent && syn > 0 {
		maxComponent = syn
		threatType = ThreatTypeSynFlood
	}

	if failed > maxComponent && failed > 0 {
		maxComponent = failed
		threatType = ThreatTypeFailedHandshake
	}

	if burst > maxComponent && burst > 5.0 {
		threatType = ThreatTypeConnectionBurst
	}

	return threatType
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
