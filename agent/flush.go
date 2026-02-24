package main

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	pb "github.com/kerneleye/proto/kerneleye/v1"
	"github.com/kerneleye/shared/scoring"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// FlushToAPI sends aggregated stats to the backend with fault tolerance
func (a *Aggregator) FlushToAPI() {
	// 1. First, try to send any pending batches from buffer
	a.retryPendingBatches()

	if a.stats.Len() == 0 {
		return
	}
	log.Printf("Flushing %d IPs to API...", a.stats.Len())

	// Fetch byte counters using thread-safe iteration
	if byteCounterMap != nil {
		a.stats.ForEachMutable(func(ip string, stats *IPStats) {
			key := ipToNetworkOrder(ip)
			var counters IpBytes
			if err := byteCounterMap.Lookup(&key, &counters); err == nil {
				stats.mu.Lock()
				stats.BytesIn = counters.BytesIn
				stats.BytesOut = counters.BytesOut
				stats.mu.Unlock()
			}
		})
	}

	// Build proto events using thread-safe snapshot
	pbEvents := a.buildProtoEvents()

	// Process scores with AutoBlocker (if enabled)
	if a.autoBlocker != nil && a.scorer != nil {
		snapshot := a.stats.SnapshotDeep()
		for ip, stats := range snapshot {
			metrics := a.buildMetrics(stats)
			score := a.scorer.CalculateScore(metrics)

			// Log high-score events for debugging
			if score.Score >= 30 {
				log.Printf("⚠️  IP %s: score=%d level=%s type=%s reasons=%v",
					ip, score.Score, score.Level, score.Type, score.Reasons)
			}

			// Process score for auto-blocking
			if err := a.autoBlocker.ProcessScore(ip, score); err != nil {
				log.Printf("❌ AutoBlocker error for %s: %v", ip, err)
			}
		}
	}

	a.grpcMu.RLock()
	client := a.grpcClient
	if client == nil {
		a.grpcMu.RUnlock()
		log.Printf("❌ gRPC client not initialized, buffering events")
		a.bufferEvents(pbEvents)
		a.scheduleReconnect()
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := client.SubmitTraffic(ctx, &pb.TrafficBatch{
		ApiKey: a.apiKey, Events: pbEvents,
		TotalEvents: uint64(len(pbEvents)), AggregationWindowSeconds: 10,
	})
	a.grpcMu.RUnlock()
	if err != nil {
		log.Printf("❌ gRPC error, buffering %d events: %v", len(pbEvents), err)
		a.bufferEvents(pbEvents)
		a.scheduleReconnect()
		if strings.Contains(err.Error(), "Server not active") ||
			strings.Contains(err.Error(), "PermissionDenied") {
			log.Printf("🚫 Server deleted or inactive. Agent terminating...")
			os.Exit(0)
		}
		return
	}

	if resp.Success {
		log.Printf("✅ Successfully sent %d events to gRPC API", len(pbEvents))
		a.stats.Clear() // Thread-safe clear
	} else {
		log.Printf("❌ gRPC API returned failure: %s", resp.Message)
		a.bufferEvents(pbEvents)
	}
}

// bufferEvents saves events to SQLite buffer
func (a *Aggregator) bufferEvents(events []*pb.ConnectionEvent) {
	if a.buffer == nil {
		log.Printf("⚠️  Buffer not initialized, events will be lost")
		return
	}
	if err := a.buffer.Save(a.apiKey, events); err != nil {
		log.Printf("❌ Failed to buffer events: %v", err)
		return
	}
	// Clear stats only after successful persistence.
	a.stats.Clear()
}

// retryPendingBatches attempts to send buffered events
func (a *Aggregator) retryPendingBatches() {
	if a.buffer == nil {
		return
	}

	pending, err := a.buffer.LoadAll()
	if err != nil || len(pending) == 0 {
		return
	}

	log.Printf("📤 Retrying %d pending batches...", len(pending))

	var sentIDs []int64
	for _, p := range pending {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

		a.grpcMu.RLock()
		client := a.grpcClient
		if client == nil {
			a.grpcMu.RUnlock()
			cancel()
			a.scheduleReconnect()
			return
		}
		resp, err := client.SubmitTraffic(ctx, p.Batch)
		a.grpcMu.RUnlock()
		cancel()

		if err != nil {
			log.Printf("❌ Retry failed for batch %d: %v", p.ID, err)
			a.scheduleReconnect()
			return // Stop on first failure - backend still down
		}

		if resp.Success {
			sentIDs = append(sentIDs, p.ID)
			log.Printf("✅ Sent pending batch %d (%d events)", p.ID, len(p.Batch.Events))
		}
	}

	if len(sentIDs) > 0 {
		if err := a.buffer.Delete(sentIDs); err != nil {
			log.Printf("⚠️  Failed to delete sent batches: %v", err)
		}
		log.Printf("🗑️  Cleared %d sent batches from buffer", len(sentIDs))
	}
}

// buildProtoEvents converts stats to protobuf events using thread-safe snapshot
func (a *Aggregator) buildProtoEvents() []*pb.ConnectionEvent {
	snapshot := a.stats.SnapshotDeep()
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
		pbEvents = append(pbEvents, &pb.ConnectionEvent{
			SourceIp: sourceIP, DestinationIp: destIP, DestinationPort: uint32(primaryPort),
			Protocol: getProtocolFromNumber(stats.Protocol), SynCount: uint32(stats.SYNCount),
			AckCount: uint32(stats.ACKCount), FailedHandshakes: uint32(stats.FailedHandshakes),
			BytesIn: stats.BytesIn, BytesOut: stats.BytesOut,
			FirstSeen: timestamppb.New(stats.FirstSeen), LastSeen: timestamppb.New(stats.LastSeen),
			UniquePortsCount: uint32(len(stats.UniquePorts)), PortsAccessed: portsAccessed,
			Direction: pb.Direction(stats.Direction + 1),
		})
	}
	return pbEvents
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
