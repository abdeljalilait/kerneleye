package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	pb "github.com/kerneleye/proto/kerneleye/v1"
	"github.com/kerneleye/shared/scoring"
)

type scoredMetrics struct {
	Score   scoring.ThreatScore
	Metrics scoring.IPMetrics
}

func isFullyAccepted(resp *pb.TrafficResponse, submitted int) (bool, string) {
	if resp == nil {
		return false, "empty response"
	}
	if !resp.Success {
		return false, resp.Message
	}
	if resp.EventsProcessed != uint64(submitted) {
		return false, fmt.Sprintf("partial processing: processed=%d submitted=%d message=%q", resp.EventsProcessed, submitted, resp.Message)
	}
	return true, ""
}

// FlushToAPI sends aggregated stats to the backend with fault tolerance
func (a *Aggregator) FlushToAPI() {
	// 1. First, try to send any pending batches from buffer
	a.retryPendingBatches()

	if a.stats.Len() == 0 {
		return
	}
	Logger.Infof("Flushing %d IPs to API...", a.stats.Len())

	// Log details for debugging
	snapshot := a.stats.SnapshotDeep()
	for ip, stats := range snapshot {
		dir := "inbound"
		if stats.Direction == DirOutbound {
			dir = "outbound"
		}
		var primaryPort uint16
		maxCount := 0
		for port, count := range stats.PortCounts {
			if count > maxCount {
				maxCount = count
				primaryPort = port
			}
		}
		Logger.Debugf("  → IP: %s port: %d dir: %s syn: %d ack: %d failed: %d unique_ports: %d",
			ip, primaryPort, dir, stats.SYNCount, stats.ACKCount, stats.FailedHandshakes, len(stats.UniquePorts))
	}

	// Fetch byte/ICMP/per-port counters from BPF maps using thread-safe iteration.
	// All three maps are keyed by IPv4 host-byte-order uint32 (same convention).
	a.stats.ForEachMutable(func(ip string, stats *IPStats) {
		key := ipToNetworkOrder(ip)

		// Total byte counters
		if byteCounterMap != nil {
			var counters IpBytes
			if err := byteCounterMap.Lookup(&key, &counters); err == nil {
				stats.mu.Lock()
				stats.BytesIn = counters.BytesIn
				stats.BytesOut = counters.BytesOut
				stats.mu.Unlock()
			}
		}

		// ICMP packet counters
		if icmpCounterMap != nil {
			var icmp IpICMP
			if err := icmpCounterMap.Lookup(&key, &icmp); err == nil {
				stats.mu.Lock()
				stats.ICMPPacketsIn = icmp.PacketsIn
				stats.ICMPPacketsOut = icmp.PacketsOut
				stats.mu.Unlock()
			}
		}

		// Per-port byte counters: look up each port we've seen for this IP.
		if ipPortBytesMap != nil {
			stats.mu.Lock()
			ports := make([]uint16, 0, len(stats.UniquePorts))
			for p := range stats.UniquePorts {
				ports = append(ports, p)
			}
			stats.mu.Unlock()

			for _, port := range ports {
				pkey := IpPortKey{IP: key, Port: port}
				var pb PortBytes
				if err := ipPortBytesMap.Lookup(&pkey, &pb); err == nil {
					stats.mu.Lock()
					if stats.PortBytesIn == nil {
						stats.PortBytesIn = make(map[uint16]uint64)
					}
					if stats.PortBytesOut == nil {
						stats.PortBytesOut = make(map[uint16]uint64)
					}
					stats.PortBytesIn[port] = pb.BytesIn
					stats.PortBytesOut[port] = pb.BytesOut
					stats.mu.Unlock()
				}
			}
		}
	})

	snapshot = a.stats.SnapshotDeep()
	now := time.Now()
	scored := a.calculateScoreContexts(snapshot, now)
	pbEvents := a.buildProtoEventsFromSnapshot(snapshot, scored, now)

	// Process scores with AutoBlocker (if enabled)
	if a.autoBlocker != nil && a.scorer != nil {
		for ip, ctx := range scored {
			if a.IsWhitelistedIPString(ip) {
				continue
			}
			score := ctx.Score

			// Log high-score events for debugging
			if score.Score >= 30 {
				Logger.Warnf("⚠️  IP %s: score=%d level=%s type=%s reasons=%v",
					ip, score.Score, score.Level, score.Type, score.Reasons)
			}

			// Process score for auto-blocking
			if err := a.autoBlocker.ProcessScore(ip, score); err != nil {
				Logger.Errorf("❌ AutoBlocker error for %s: %v", ip, err)
			}
		}
	}

	a.grpcMu.RLock()
	client := a.grpcClient
	if client == nil {
		a.grpcMu.RUnlock()
		Logger.Error("❌ gRPC client not initialized, buffering events")
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
		Logger.Errorf("❌ gRPC error, buffering %d events: %v", len(pbEvents), err)
		a.bufferEvents(pbEvents)
		a.scheduleReconnect()
		if strings.Contains(err.Error(), "Server not active") ||
			strings.Contains(err.Error(), "PermissionDenied") {
			Logger.Fatal("🚫 Server deleted or inactive. Agent terminating...")
			os.Exit(0)
		}
		return
	}

	if ok, reason := isFullyAccepted(resp, len(pbEvents)); ok {
		totalSyn := 0
		totalAck := 0
		totalFailed := 0
		for _, e := range pbEvents {
			totalSyn += int(e.SynCount)
			totalAck += int(e.AckCount)
			totalFailed += int(e.FailedHandshakes)
		}
		Logger.Infof("✅ Sent %d IPs (%d events) to gRPC API - syn=%d ack=%d failed=%d",
			len(pbEvents), len(pbEvents), totalSyn, totalAck, totalFailed)
		a.stats.Clear() // Thread-safe clear
	} else {
		Logger.Errorf("❌ gRPC API did not fully accept batch, buffering %d events: %s", len(pbEvents), reason)
		a.bufferEvents(pbEvents)
	}
}

// bufferEvents saves events to SQLite buffer.
// Stats are cleared only on successful persistence so no data is lost on write failure.
func (a *Aggregator) bufferEvents(events []*pb.ConnectionEvent) {
	if a.buffer == nil {
		Logger.Warn("⚠️  Buffer not initialized, events will be lost")
		return
	}
	if err := a.buffer.Save(a.apiKey, events); err != nil {
		Logger.Errorf("❌ Failed to buffer %d events (keeping in memory): %v", len(events), err)
		// Do NOT clear stats — they remain in memory for the next flush attempt.
		return
	}
	count := a.buffer.Count()
	Logger.Infof("📦 Buffered %d events (total pending batches: %d)", len(events), count)
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

	Logger.Info("📤 Retrying %d pending batches...", len(pending))

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
			Logger.Errorf("❌ Retry failed for batch %d: %v", p.ID, err)
			a.scheduleReconnect()
			return // Stop on first failure - backend still down
		}

		if ok, reason := isFullyAccepted(resp, len(p.Batch.Events)); ok {
			sentIDs = append(sentIDs, p.ID)
			Logger.Infof("✅ Sent pending batch %d (%d events)", p.ID, len(p.Batch.Events))
		} else {
			Logger.Errorf("❌ Pending batch %d was not fully accepted, keeping buffered: %s", p.ID, reason)
			return
		}
	}

	if len(sentIDs) > 0 {
		if err := a.buffer.Delete(sentIDs); err != nil {
			Logger.Warnf("⚠️  Failed to delete sent batches: %v", err)
		}
		Logger.Infof("🗑️  Cleared %d sent batches from buffer", len(sentIDs))
	}
}

// buildProtoEvents converts stats to protobuf events using thread-safe snapshot
func (a *Aggregator) buildProtoEvents() []*pb.ConnectionEvent {
	snapshot := a.stats.SnapshotDeep()
	now := time.Now()
	scored := a.calculateScoreContexts(snapshot, now)
	return a.buildProtoEventsFromSnapshot(snapshot, scored, now)
}

