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

	NormalSYNRate       float64
	SuspiciousSYNRate   float64
	PortScanThreshold   int
	FailedHandshakeRate float64

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

		NormalSYNRate:       1.0,
		SuspiciousSYNRate:   5.0,
		PortScanThreshold:   20,
		FailedHandshakeRate: 2.0,

		SuspiciousThreshold: 30,
		MaliciousThreshold:  60,
		AutoBlockThreshold:  80,

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

	if windowDuration < 1.0 {
		windowDuration = 1.0
	}

	if metrics.PreviousScore > 100 {
		metrics.PreviousScore = 100
	} else if metrics.PreviousScore < 0 {
		metrics.PreviousScore = 0
	}

	synRate := float64(metrics.SYNCount) / windowDuration
	failedRate := float64(metrics.FailedHandshakes) / windowDuration
	connectionRate := float64(metrics.TotalConnections) / windowDuration

	synComponent := ts.calculateSYNScore(synRate, metrics)
	portComponent := ts.calculatePortScore(metrics.UniquePorts, connectionRate, windowDuration)
	failedComponent := ts.calculateFailedScore(failedRate, metrics)
	burstComponent := ts.calculateBurstScore(connectionRate, windowDuration)

	if metrics.RSTCount > 5 {
		if metrics.EstablishedConnections == 0 ||
			metrics.RSTCount > metrics.EstablishedConnections*2 {
			burstComponent += 3.0
		}
	}

	rawScore := (synComponent * ts.SYNRateWeight) +
		(portComponent * ts.UniquePortsWeight) +
		(failedComponent * ts.FailedHandshakeWeight) +
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

	adjustedScore := rawScore * confidence

	if metrics.PreviousScore > 0 {
		adjustedScore = (float64(metrics.PreviousScore) * 0.7) + (adjustedScore * 0.3)
	}

	if adjustedScore > 100 {
		adjustedScore = 100
	}
	finalScore := int(adjustedScore)

	level := ts.classifyThreat(finalScore, confidence)
	reasons := ts.generateReasons(metrics, synRate, failedRate, connectionRate, windowDuration, confidence)

	return ThreatScore{
		Score:           finalScore,
		FinalScoreFloat: adjustedScore,
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

func (ts *ThreatScorer) IsBlockWorthy(score ThreatScore) bool {
	return score.Level == ThreatLevelMalicious &&
		score.Score >= ts.AutoBlockThreshold &&
		score.Confidence >= 0.8
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
