package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/kerneleye/agent/remediation"
	pb "github.com/kerneleye/proto/kerneleye/v1"
	"github.com/kerneleye/shared/scoring"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

// Aggregator holds per-IP statistics and manages flushing to the API
type Aggregator struct {
	stats              *SafeStats // Thread-safe stats map
	flushChan          chan struct{}
	stopChan           chan struct{}
	apiKey, serverHost string
	grpcURL            string
	serverID           string
	grpcConn           *grpc.ClientConn
	grpcClient         pb.IngestServiceClient
	grpcMu             sync.RWMutex // Protects grpcConn/grpcClient during RPCs and reconnect swaps
	remediator         remediation.Remediator
	analyzer           *remediation.Analyzer
	autoBlocker        *remediation.AutoBlocker
	scorer             *scoring.ThreatScorer
	buffer             *BufferDB       // SQLite buffer for fault tolerance
	cachedPublicIP     string          // Cached public IP
	serverIPs          map[string]bool // Server's local IPs for direction detection
	flushTicker        *time.Ticker
	heartbeatTicker    *time.Ticker
	bootTime           time.Time      // System boot time for eBPF timestamp conversion
	wg                 sync.WaitGroup // Tracks background goroutines for graceful shutdown

	// Reconnection state
	reconnectMu       sync.Mutex
	reconnectCount    int           // Number of reconnection attempts
	lastReconnect     time.Time     // Last reconnection attempt
	maxReconnectDelay time.Duration // Max delay between reconnects
	reconnecting      bool
}

// NewAggregator creates a new aggregator with gRPC connection
func NewAggregator(apiKey, serverHost, grpcURL string, rem remediation.Remediator, ana *remediation.Analyzer, autoBlocker *remediation.AutoBlocker, scorer *scoring.ThreatScorer) (*Aggregator, error) {
	grpcTarget := buildGRPCTarget(serverHost, grpcURL)
	conn, err := grpc.NewClient("dns:///"+grpcTarget, buildGRPCOpts(grpcTarget)...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to gRPC server: %w", err)
	}

	// Initialize SQLite buffer for fault tolerance
	buffer, err := NewBufferDB("")
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("buffer init: %w", err)
	}

	// Get server's local IPs at startup (IPv4 + IPv6)
	serverIPs := getServerIPs()

	// Cache public IP once at startup, fall back to local IP
	cachedPublicIP := getPublicIP()
	if cachedPublicIP == "" {
		log.Printf("⚠️  Could not detect public IP, falling back to local IP")
		for ip := range serverIPs {
			cachedPublicIP = ip
			break
		}
	}

	// Compute boot time for eBPF monotonic timestamp conversion
	bootTime := getBootTime()
	serverID := extractServerIDFromAPIKey(apiKey)
	if serverID == "" {
		log.Printf("⚠️  Could not extract server UUID from API key; server_id will be omitted in block reports")
	}

	agg := &Aggregator{
		stats:             NewSafeStats(),
		flushChan:         make(chan struct{}),
		stopChan:          make(chan struct{}),
		apiKey:            apiKey,
		serverHost:        serverHost,
		grpcURL:           grpcTarget,
		serverID:          serverID,
		grpcConn:          conn,
		grpcClient:        pb.NewIngestServiceClient(conn),
		remediator:        rem,
		analyzer:          ana,
		buffer:            buffer,
		cachedPublicIP:    cachedPublicIP,
		serverIPs:         serverIPs,
		bootTime:          bootTime,
		maxReconnectDelay: 5 * time.Minute,
	}

	// Start connection monitor
	agg.wg.Add(1)
	go agg.monitorConnection()

	return agg, nil
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
			if ip != nil && !ip.IsLoopback() {
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

	// Convert eBPF monotonic timestamp (nanoseconds since boot) to wall clock
	eventTime := time.Now()
	if event.Timestamp > 0 {
		eventTime = a.bootTime.Add(time.Duration(event.Timestamp))
	}

	// GetOrCreate atomically gets or creates stats entry
	stats := a.stats.GetOrCreate(ip, func() *IPStats {
		return &IPStats{
			Protocol:    event.Protocol,
			UniquePorts: make(map[uint16]bool),
			PortCounts:  make(map[uint16]int),
			PortHits:    make(map[uint16]int),
			FirstSeen:   eventTime,
			Direction:   event.Direction,
			LocalIP:     localIP,
		}
	})

	// Update stats under per-entry lock to prevent concurrent map writes and data races
	stats.mu.Lock()
	stats.LastSeen = eventTime
	stats.Protocol = event.Protocol
	if event.Flags&0x01 != 0 {
		stats.SYNCount++
	}
	if event.Flags&0x02 != 0 {
		stats.ACKCount++
	}
	stats.UniquePorts[event.Lport] = true
	stats.PortCounts[event.Lport]++
	stats.PortHits[event.Lport]++ // Track hits per port for service abuse detection
	stats.mu.Unlock()

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

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
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
	hostname, _ := os.Hostname()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	a.grpcMu.RLock()
	client := a.grpcClient
	if client == nil {
		a.grpcMu.RUnlock()
		log.Printf("⚠️  gRPC client not initialized, skipping heartbeat")
		a.scheduleReconnect()
		return
	}
	resp, err := client.Heartbeat(ctx, &pb.HeartbeatRequest{
		ApiKey: a.apiKey, Hostname: hostname, AgentVersion: Version, IpAddress: a.cachedPublicIP,
	})
	a.grpcMu.RUnlock()
	if err != nil {
		log.Printf("❌ gRPC heartbeat error: %v", err)
		a.scheduleReconnect()
		return
	}
	if !resp.Success {
		log.Printf("⚠️  Server status: %s - Agent will exit", resp.Message)
		a.Stop()
	}
}

// monitorConnection monitors gRPC connection health and reconnects on failure
func (a *Aggregator) monitorConnection() {
	defer a.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			a.checkConnection()
		case <-a.stopChan:
			return
		}
	}
}

// checkConnection verifies connection is alive and reconnects if needed
func (a *Aggregator) checkConnection() {
	a.grpcMu.RLock()
	conn := a.grpcConn
	if conn == nil {
		a.grpcMu.RUnlock()
		a.scheduleReconnect()
		return
	}
	state := conn.GetState()
	a.grpcMu.RUnlock()
	if state == connectivity.TransientFailure || state == connectivity.Shutdown {
		log.Printf("🔄 gRPC connection state: %v - attempting reconnect", state)
		a.scheduleReconnect()
	}
}

// scheduleReconnect schedules a reconnection attempt with exponential backoff
func (a *Aggregator) scheduleReconnect() {
	a.reconnectMu.Lock()
	if a.reconnecting {
		a.reconnectMu.Unlock()
		return
	}

	// Calculate delay with exponential backoff
	delay := time.Duration(1<<uint(a.reconnectCount)) * time.Second
	if delay > a.maxReconnectDelay {
		delay = a.maxReconnectDelay
	}

	a.reconnectCount++
	attempt := a.reconnectCount
	a.lastReconnect = time.Now()
	a.reconnecting = true
	a.reconnectMu.Unlock()

	log.Printf("⏳ Scheduling reconnection attempt %d in %v", attempt, delay)

	go func() {
		select {
		case <-time.After(delay):
			a.attemptReconnect(attempt)
		case <-a.stopChan:
			a.reconnectMu.Lock()
			a.reconnecting = false
			a.reconnectMu.Unlock()
			return
		}
	}()
}

// attemptReconnect tries to reconnect to the gRPC server
func (a *Aggregator) attemptReconnect(attempt int) {
	log.Printf("🔄 Attempting to reconnect to gRPC server %s (attempt %d)...", a.grpcURL, attempt)

	// Create new connection
	conn, err := grpc.NewClient("dns:///"+a.grpcURL, buildGRPCOpts(a.grpcURL)...)
	if err != nil {
		log.Printf("❌ Failed to create new gRPC connection: %v", err)
		a.reconnectMu.Lock()
		a.reconnecting = false
		a.reconnectMu.Unlock()
		a.scheduleReconnect()
		return
	}

	// Test connection with a simple call
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	testClient := pb.NewIngestServiceClient(conn)
	_, err = testClient.Heartbeat(ctx, &pb.HeartbeatRequest{
		ApiKey: a.apiKey,
	})

	if err != nil {
		log.Printf("❌ Reconnection test failed: %v", err)
		conn.Close()
		a.reconnectMu.Lock()
		a.reconnecting = false
		a.reconnectMu.Unlock()
		a.scheduleReconnect()
		return
	}

	// Success - update connection
	a.grpcMu.Lock()
	oldConn := a.grpcConn
	a.grpcConn = conn
	a.grpcClient = testClient
	if oldConn != nil {
		_ = oldConn.Close()
	}
	a.grpcMu.Unlock()

	a.reconnectMu.Lock()
	a.reconnectCount = 0 // Reset counter on success
	a.reconnecting = false
	a.reconnectMu.Unlock()

	log.Printf("✅ Successfully reconnected to gRPC server")
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

// Close releases all resources held by the aggregator.
// It signals the background goroutine to stop, waits for it to exit,
// then performs a final flush and tears down resources.
func (a *Aggregator) Close() error {
	// Signal background goroutine to stop and wait for it to exit
	a.Stop()
	a.wg.Wait()

	// Stop timers
	if a.flushTicker != nil {
		a.flushTicker.Stop()
	}
	if a.heartbeatTicker != nil {
		a.heartbeatTicker.Stop()
	}

	// Flush remaining data (safe now — goroutine has exited)
	a.FlushToAPI()

	// Close gRPC connection
	a.grpcMu.Lock()
	if a.grpcConn != nil {
		if err := a.grpcConn.Close(); err != nil {
			log.Printf("⚠️  Error closing gRPC connection: %v", err)
		}
		a.grpcConn = nil
		a.grpcClient = nil
	}
	a.grpcMu.Unlock()

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

// ReportBlockedIP sends a blocked IP event to the backend via gRPC
func (a *Aggregator) ReportBlockedIP(ip net.IP, action remediation.Action, reason string, duration time.Duration) {
	var blockAction pb.BlockAction
	switch action {
	case remediation.ActionBlock:
		blockAction = pb.BlockAction_BLOCK_ACTION_BLOCK
	case remediation.ActionRateLimit:
		blockAction = pb.BlockAction_BLOCK_ACTION_RATE_LIMIT
	default:
		blockAction = pb.BlockAction_BLOCK_ACTION_ALLOW
	}

	req := &pb.BlockedIPEvent{
		ApiKey:          a.apiKey,
		ServerId:        a.serverID,
		IpAddress:       ip.String(),
		Action:          blockAction,
		DurationSeconds: uint32(duration.Seconds()),
		Reason:          reason,
	}

	// Retry up to 3 times with exponential backoff
	var err error
	for attempt := range 3 {
		a.grpcMu.RLock()
		client := a.grpcClient
		if client == nil {
			a.grpcMu.RUnlock()
			log.Printf("⚠️  gRPC client not initialized, cannot report blocked IP")
			a.scheduleReconnect()
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err = client.ReportBlockedIP(ctx, req)
		a.grpcMu.RUnlock()
		cancel()
		if err == nil {
			log.Printf("📡 Reported blocked IP %s (%s) to backend", ip, action)
			return
		}
		log.Printf("⚠️  Attempt %d/3 failed to report blocked IP %s: %v", attempt+1, ip, err)
		if attempt < 2 {
			time.Sleep(time.Duration(1<<attempt) * time.Second) // 1s, 2s backoff
		}
	}
	a.scheduleReconnect()
	log.Printf("❌ Failed to report blocked IP %s after 3 attempts: %v", ip, err)
}
