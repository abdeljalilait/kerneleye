package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/kerneleye/agent/remediation"
	pb "github.com/kerneleye/proto/kerneleye/v1"
	"google.golang.org/grpc"
)

// Aggregator holds per-IP statistics and manages flushing to the API
type Aggregator struct {
	stats              *SafeStats // Thread-safe stats map
	flushChan          chan struct{}
	stopChan           chan struct{}
	apiKey, serverHost string
	grpcConn           *grpc.ClientConn
	grpcClient         pb.IngestServiceClient
	remediator         remediation.Remediator
	analyzer           *remediation.Analyzer
	buffer             *BufferDB       // SQLite buffer for fault tolerance
	cachedPublicIP     string          // Cached public IP
	serverIPs          map[string]bool // Server's local IPs for direction detection
	flushTicker        *time.Ticker
	heartbeatTicker    *time.Ticker
}

// NewAggregator creates a new aggregator with gRPC connection
func NewAggregator(apiKey, serverHost string, rem remediation.Remediator, ana *remediation.Analyzer) (*Aggregator, error) {
	grpcTarget := buildGRPCTarget(serverHost)
	conn, err := grpc.NewClient("passthrough:///"+grpcTarget, buildGRPCOpts(grpcTarget)...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to gRPC server: %w", err)
	}

	// Initialize SQLite buffer for fault tolerance
	buffer, err := NewBufferDB("")
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("buffer init: %w", err)
	}

	// Get server's local IPs at startup
	serverIPs := getServerIPs()

	// Cache public IP once at startup
	cachedPublicIP := getPublicIP()

	return &Aggregator{
		stats:          NewSafeStats(),
		flushChan:      make(chan struct{}),
		stopChan:       make(chan struct{}),
		apiKey:         apiKey,
		serverHost:     serverHost,
		grpcConn:       conn,
		grpcClient:     pb.NewIngestServiceClient(conn),
		remediator:     rem,
		analyzer:       ana,
		buffer:         buffer,
		cachedPublicIP: cachedPublicIP,
		serverIPs:      serverIPs,
	}, nil
}

// getServerIPs retrieves all local IP addresses for the server
func getServerIPs() map[string]bool {
	ips := make(map[string]bool)
	ifaces, err := net.Interfaces()
	if err != nil {
		return ips
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.To4() != nil {
				ips[ip.String()] = true
			}
		}
	}
	return ips
}

// ProcessEvent processes a single eBPF event (thread-safe via SafeStats)
func (a *Aggregator) ProcessEvent(event Event) {
	ipObj := intToIP(event.Saddr)
	if isPrivateIP(ipObj) {
		return
	}
	ip := ipObj.String()
	localIP := a.cachedPublicIP

	// Use event timestamp if available, otherwise use current time
	eventTime := time.Now()
	if event.Timestamp > 0 {
		eventTime = time.Unix(0, int64(event.Timestamp))
	}

	// GetOrCreate atomically gets or creates stats entry
	stats := a.stats.GetOrCreate(ip, func() *IPStats {
		return &IPStats{
			UniquePorts: make(map[uint16]bool),
			PortCounts:  make(map[uint16]int),
			FirstSeen:   eventTime,
			Direction:   event.Direction,
			LocalIP:     localIP,
		}
	})

	// Update stats (still needs lock since IPStats internals are mutated)
	stats.LastSeen = eventTime
	if event.Flags&0x01 != 0 {
		stats.SYNCount++
	}
	if event.Flags&0x02 != 0 {
		stats.ACKCount++
	}
	stats.UniquePorts[event.Lport] = true
	stats.PortCounts[event.Lport]++

	// Analyze traffic for remediation
	if a.analyzer != nil && a.remediator != nil {
		te := remediation.TrafficEvent{
			SourceIP: ipObj,
			DestPort: event.Lport,
			Protocol: event.Protocol,
			Flags:    event.Flags,
			Time:     eventTime,
		}
		if decision := a.analyzer.Evaluate(te); decision != nil {
			switch decision.Action {
			case remediation.ActionBlock:
				if err := a.remediator.Block(decision.IP, decision.Duration); err != nil {
					log.Printf("❌ Failed to block IP %s: %v", decision.IP, err)
				}
			case remediation.ActionRateLimit:
				if err := a.remediator.RateLimit(decision.IP, decision.Duration); err != nil {
					log.Printf("❌ Failed to rate-limit IP %s: %v", decision.IP, err)
				}
			}
		}
	}
}

// StartFlushTimer starts periodic flushing and heartbeat with stoppable timers
func (a *Aggregator) StartFlushTimer(interval time.Duration) {
	a.flushTicker = time.NewTicker(interval)
	a.heartbeatTicker = time.NewTicker(30 * time.Second)

	go func() {
		for {
			select {
			case <-a.flushTicker.C:
				a.FlushToAPI()
			case <-a.heartbeatTicker.C:
				a.SendHeartbeat()
			case <-a.stopChan:
				return
			}
		}
	}()
}

// SendHeartbeat sends a heartbeat to the backend
func (a *Aggregator) SendHeartbeat() {
	if a.grpcClient == nil {
		log.Printf("⚠️  gRPC client not initialized, skipping heartbeat")
		return
	}
	hostname, _ := os.Hostname()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := a.grpcClient.Heartbeat(ctx, &pb.HeartbeatRequest{
		ApiKey: a.apiKey, Hostname: hostname, AgentVersion: "0.1.0", IpAddress: a.cachedPublicIP,
	})
	if err != nil {
		log.Printf("❌ gRPC heartbeat error: %v", err)
		return
	}
	if !resp.Success {
		log.Printf("⚠️  Server status: %s - Agent will exit", resp.Message)
		a.Stop()
	}
}

// Stop signals the aggregator to stop
func (a *Aggregator) Stop() {
	select {
	case <-a.stopChan:
		// Already closed
	default:
		close(a.stopChan)
	}
}

// Close releases all resources held by the aggregator
func (a *Aggregator) Close() error {
	// Stop timers
	if a.flushTicker != nil {
		a.flushTicker.Stop()
	}
	if a.heartbeatTicker != nil {
		a.heartbeatTicker.Stop()
	}

	// Flush remaining data
	a.FlushToAPI()

	// Close gRPC connection
	if a.grpcConn != nil {
		if err := a.grpcConn.Close(); err != nil {
			log.Printf("⚠️  Error closing gRPC connection: %v", err)
		}
	}

	// Close buffer database
	if a.buffer != nil {
		if err := a.buffer.Close(); err != nil {
			log.Printf("⚠️  Error closing buffer DB: %v", err)
		}
	}

	return nil
}

// GetStats returns a snapshot of the stats map (for testing/debugging)
func (a *Aggregator) GetStats() map[string]*IPStats {
	return a.stats.Snapshot()
}
