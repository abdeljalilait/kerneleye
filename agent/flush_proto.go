package main

import (
	"time"

	pb "github.com/kerneleye/proto/kerneleye/v1"
	"github.com/kerneleye/shared/scoring"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Proto conversion helpers for building traffic event batches.
// Converts internal IPStats snapshots and scored metrics into protobuf
// ConnectionEvent messages for gRPC submission to the backend.

func (a *Aggregator) buildProtoEventsFromSnapshot(snapshot map[string]IPStatsSnapshot, scored map[string]scoredMetrics, now time.Time) []*pb.ConnectionEvent {
	pbEvents := make([]*pb.ConnectionEvent, 0, len(snapshot))

	for ip, stats := range snapshot {
		var primaryPort uint16
		maxCount := 0
		for port, count := range stats.PortCounts {
			if count > maxCount {
				maxCount = count
				primaryPort = port
			}
		}
		portsAccessed := make([]uint32, 0, 10)
		for p := range stats.UniquePorts {
			portsAccessed = append(portsAccessed, uint32(p))
			if len(portsAccessed) >= 10 {
				break
			}
		}
		// Set source/destination IPs based on direction
		var sourceIP, destIP string
		if stats.Direction == DirInbound {
			sourceIP = ip          // Remote caller
			destIP = stats.LocalIP // Our server
		} else {
			sourceIP = stats.LocalIP // Our server
			destIP = ip              // Remote server we connected to
		}
		firstSeen, lastSeen := sanitizeStatsWindow(stats.FirstSeen, stats.LastSeen, now)
		score := scoring.ThreatScore{}
		if ctx, ok := scored[ip]; ok {
			score = ctx.Score
			if !ctx.Metrics.WindowStart.IsZero() {
				firstSeen = ctx.Metrics.WindowStart
			}
			if !ctx.Metrics.WindowEnd.IsZero() {
				lastSeen = ctx.Metrics.WindowEnd
			}
		}

		// Connection duration: time between first and last event in this flush window.
		// This is a window-level approximation useful for detecting slow scans vs bursts.
		connDurationMs := uint64(lastSeen.Sub(firstSeen).Milliseconds())
		if lastSeen.Before(firstSeen) || connDurationMs > uint64(24*60*60*1000) {
			connDurationMs = 0 // clamp nonsensical values
		}

		// Per-port byte breakdown — cap at top 10 ports by bytes_in to bound proto size.
		portBytesIn := make(map[uint32]uint64, len(stats.PortBytesIn))
		portBytesOut := make(map[uint32]uint64, len(stats.PortBytesOut))
		const maxPortBreakdown = 10
		added := 0
		for port, b := range stats.PortBytesIn {
			if added >= maxPortBreakdown {
				break
			}
			portBytesIn[uint32(port)] = b
			added++
		}
		added = 0
		for port, b := range stats.PortBytesOut {
			if added >= maxPortBreakdown {
				break
			}
			portBytesOut[uint32(port)] = b
			added++
		}

		pbEvents = append(pbEvents, &pb.ConnectionEvent{
			SourceIp: sourceIP, DestinationIp: destIP, DestinationPort: uint32(primaryPort),
			Protocol: getProtocolFromNumber(stats.Protocol), SynCount: uint32(stats.SYNCount),
			AckCount: uint32(stats.ACKCount), FailedHandshakes: uint32(stats.FailedHandshakes),
			BytesIn: stats.BytesIn, BytesOut: stats.BytesOut,
			FirstSeen: timestamppb.New(firstSeen), LastSeen: timestamppb.New(lastSeen),
			UniquePortsCount: uint32(len(stats.UniquePorts)), PortsAccessed: portsAccessed,
			Direction:            pb.Direction(stats.Direction + 1),
			ThreatScore:          uint32(max(score.Score, 0)),
			ThreatLevel:          toProtoThreatLevel(score.Level),
			ThreatType:           toProtoThreatType(score.Type),
			Reasons:              score.Reasons,
			IcmpPacketsIn:        stats.ICMPPacketsIn,
			IcmpPacketsOut:       stats.ICMPPacketsOut,
			ConnectionDurationMs: connDurationMs,
			PortBytesIn:          portBytesIn,
			PortBytesOut:         portBytesOut,
			ProcessName:          stats.ProcessName,
		})
	}
	return pbEvents
}

func (a *Aggregator) calculateScoreContexts(snapshot map[string]IPStatsSnapshot, now time.Time) map[string]scoredMetrics {
	if a.scorer == nil {
		return map[string]scoredMetrics{}
	}

	result := make(map[string]scoredMetrics, len(snapshot))
	for ip, stats := range snapshot {
		metrics := a.buildMetrics(stats)
		metrics.WindowStart, metrics.WindowEnd = sanitizeStatsWindow(stats.FirstSeen, stats.LastSeen, now)

		if a.history != nil {
			signals, err := a.history.LoadSignals(ip, stats.Direction, now)
			if err != nil {
				Logger.Warnf("⚠️  Failed to load history signals for %s: %v", ip, err)
			} else {
				if signals.MaxThreatScore > metrics.PreviousScore {
					metrics.PreviousScore = signals.MaxThreatScore
				}
				if signals.MaxPortHits > metrics.MaxPortHits {
					metrics.MaxPortHits = signals.MaxPortHits
				}
			}
		}

		score := a.scorer.CalculateScore(metrics)
		result[ip] = scoredMetrics{
			Score:   score,
			Metrics: metrics,
		}

		if a.history != nil {
			if err := a.history.PersistBucket(ip, stats.Direction, stats.Protocol, stats.ProcessName, metrics, score, now); err != nil {
				Logger.Warnf("⚠️  Failed to persist history bucket for %s: %v", ip, err)
			}
		}
	}

	return result
}

// buildMetrics converts IPStatsSnapshot to scoring.IPMetrics for threat scoring
func (a *Aggregator) buildMetrics(stats IPStatsSnapshot) scoring.IPMetrics {
	// Calculate max port hits and primary port
	maxHits := 0
	primaryPort := 0
	portHits := make(map[int]int)
	for port, hits := range stats.PortHits {
		portHits[int(port)] = hits
		if hits > maxHits {
			maxHits = hits
			primaryPort = int(port)
		}
	}

	// Calculate unique ports as int slice
	uniquePorts := 0
	for range stats.UniquePorts {
		uniquePorts++
	}

	// Determine primary port from PortCounts if not set
	if primaryPort == 0 && len(stats.PortCounts) > 0 {
		maxCount := 0
		for port, count := range stats.PortCounts {
			if count > maxCount {
				maxCount = count
				primaryPort = int(port)
			}
		}
		if maxHits == 0 && primaryPort > 0 {
			maxHits = maxCount
		}
	}

	// Estimate established connections (rough approximation)
	established := stats.ACKCount - stats.SYNCount
	if established < 0 {
		established = 0
	}

	return scoring.IPMetrics{
		SYNCount:               stats.SYNCount,
		ACKCount:               stats.ACKCount,
		FailedHandshakes:       stats.FailedHandshakes,
		UniquePorts:            uniquePorts,
		TotalConnections:       stats.SYNCount + stats.ACKCount,
		BytesIn:                stats.BytesIn,
		BytesOut:               stats.BytesOut,
		WindowStart:            stats.FirstSeen,
		WindowEnd:              stats.LastSeen,
		EstablishedConnections: established,
		PortHits:               portHits,
		MaxPortHits:            maxHits,
		PrimaryPort:            primaryPort,
		Direction:              getScoringDirection(stats.Direction),
	}
}

func getScoringDirection(dir uint8) scoring.Direction {
	if dir == DirOutbound {
		return scoring.DirectionOutbound
	}
	return scoring.DirectionInbound
}

func sanitizeStatsWindow(firstSeen, lastSeen, now time.Time) (time.Time, time.Time) {
	oneYearAgo := now.AddDate(-1, 0, 0)
	oneYearFromNow := now.AddDate(1, 0, 0)

	if firstSeen.IsZero() || firstSeen.Before(oneYearAgo) || firstSeen.After(oneYearFromNow) {
		firstSeen = now
	}
	if lastSeen.IsZero() || lastSeen.Before(oneYearAgo) || lastSeen.After(oneYearFromNow) {
		lastSeen = now
	}
	if lastSeen.Before(firstSeen) {
		lastSeen = firstSeen
	}
	return firstSeen, lastSeen
}

func toProtoThreatLevel(level scoring.ThreatLevel) pb.ThreatLevel {
	switch level {
	case scoring.ThreatLevelMalicious:
		return pb.ThreatLevel_THREAT_LEVEL_MALICIOUS
	case scoring.ThreatLevelSuspicious:
		return pb.ThreatLevel_THREAT_LEVEL_SUSPICIOUS
	default:
		return pb.ThreatLevel_THREAT_LEVEL_NORMAL
	}
}

func toProtoThreatType(threatType scoring.ThreatType) pb.ThreatType {
	switch threatType {
	case scoring.ThreatTypePortScan:
		return pb.ThreatType_THREAT_TYPE_PORT_SCAN
	case scoring.ThreatTypeServiceAbuse:
		return pb.ThreatType_THREAT_TYPE_SERVICE_ABUSE
	case scoring.ThreatTypeSynFlood:
		return pb.ThreatType_THREAT_TYPE_SYN_FLOOD
	case scoring.ThreatTypeFailedHandshake:
		return pb.ThreatType_THREAT_TYPE_FAILED_HANDSHAKE
	case scoring.ThreatTypeConnectionBurst:
		return pb.ThreatType_THREAT_TYPE_CONNECTION_BURST
	default:
		return pb.ThreatType_THREAT_TYPE_NONE
	}
}
