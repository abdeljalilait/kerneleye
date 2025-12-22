package main

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	pb "github.com/kerneleye/proto/kerneleye/v1"
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
				stats.BytesIn = counters.BytesIn
				stats.BytesOut = counters.BytesOut
			}
		})
	}

	// Build proto events using thread-safe snapshot
	pbEvents := a.buildProtoEvents()

	if a.grpcClient == nil {
		log.Printf("❌ gRPC client not initialized, buffering events")
		a.bufferEvents(pbEvents)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := a.grpcClient.SubmitTraffic(ctx, &pb.TrafficBatch{
		ApiKey: a.apiKey, Events: pbEvents,
		TotalEvents: uint64(len(pbEvents)), AggregationWindowSeconds: 10,
	})
	if err != nil {
		log.Printf("❌ gRPC error, buffering %d events: %v", len(pbEvents), err)
		a.bufferEvents(pbEvents)
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
	}
	// Clear stats even on buffer - we've saved them
	a.stats.Clear()
}

// retryPendingBatches attempts to send buffered events
func (a *Aggregator) retryPendingBatches() {
	if a.buffer == nil || a.grpcClient == nil {
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
		resp, err := a.grpcClient.SubmitTraffic(ctx, p.Batch)
		cancel()

		if err != nil {
			log.Printf("❌ Retry failed for batch %d: %v", p.ID, err)
			break // Stop on first failure - backend still down
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
	snapshot := a.stats.Snapshot()
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
			Protocol: getProtocolFromPort(primaryPort), SynCount: uint32(stats.SYNCount),
			AckCount: uint32(stats.ACKCount), FailedHandshakes: uint32(stats.FailedHandshakes),
			BytesIn: stats.BytesIn, BytesOut: stats.BytesOut,
			FirstSeen: timestamppb.New(stats.FirstSeen), LastSeen: timestamppb.New(stats.LastSeen),
			UniquePortsCount: uint32(len(stats.UniquePorts)), PortsAccessed: portsAccessed,
			Direction: pb.Direction(stats.Direction + 1),
		})
	}
	return pbEvents
}
