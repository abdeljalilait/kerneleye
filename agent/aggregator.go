package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kerneleye/agent/remediation"
	pb "github.com/kerneleye/proto/kerneleye/v1"
	"github.com/kerneleye/shared/scoring"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Aggregator holds per-IP statistics and manages flushing to the API
type Aggregator struct {
	stats              *SafeStats // Thread-safe stats map
	flushChan          chan struct{}
	stopChan           chan struct{}
	apiKey, serverHost string
	grpcURL            string
	serverID           string
	agentVersion       string
	grpcConn           *grpc.ClientConn
	grpcClient         pb.IngestServiceClient
	grpcMu             sync.RWMutex // Protects grpcConn/grpcClient during RPCs and reconnect swaps
	remediator         remediation.Remediator
	analyzer           *remediation.Analyzer
	autoBlocker        *remediation.AutoBlocker
	scorer             *scoring.ThreatScorer
	history            *HistoryStore
	buffer             *BufferDB       // SQLite buffer for fault tolerance
	cachedPublicIP     string          // Cached public IP
	serverIPs          map[string]bool // Server's local IPs for direction detection
	flushTicker        *time.Ticker
	heartbeatTicker    *time.Ticker
	bootTime           time.Time      // System boot time for eBPF timestamp conversion
	wg                 sync.WaitGroup // Tracks background goroutines for graceful shutdown
	agentPID           uint32         // Current agent process ID for self-traffic filtering
	controlPlaneIPs    map[string]bool
	controlPlaneHost   string
	controlPlanePort   uint16

	blockCmdClient *BlockCommandClient // Receives block commands from backend

	// Reconnection state
	reconnectMu       sync.Mutex
	reconnectCount    int           // Number of reconnection attempts
	lastReconnect     time.Time     // Last reconnection attempt
	maxReconnectDelay time.Duration // Max delay between reconnects
	reconnecting      bool
}

// SetBlockCommandClient sets the block command client for connection sharing
func (a *Aggregator) SetBlockCommandClient(client *BlockCommandClient) {
	a.blockCmdClient = client
}

// GetGRPCConn returns the gRPC connection (for sharing with other clients)
func (a *Aggregator) GetGRPCConn() *grpc.ClientConn {
	a.grpcMu.RLock()
	defer a.grpcMu.RUnlock()
	return a.grpcConn
}

// ServerID returns the server ID
func (a *Aggregator) ServerID() string {
	return a.serverID
}

// NewAggregator creates a new aggregator with gRPC connection
func NewAggregator(apiKey, serverHost, grpcURL, agentVersion string, rem remediation.Remediator, ana *remediation.Analyzer, autoBlocker *remediation.AutoBlocker, scorer *scoring.ThreatScorer) (*Aggregator, error) {
	grpcTarget := buildGRPCTarget(serverHost, grpcURL)
	controlPlaneHost, controlPlanePort, controlPlaneIPs := resolveControlPlaneEndpoint(grpcTarget)
	conn, err := grpc.NewClient(grpcDialTargetPrefix+buildGRPCDialTarget(grpcTarget), buildGRPCOpts(grpcTarget)...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to gRPC server: %w", err)
	}

	// Initialize SQLite buffer for fault tolerance
	buffer, err := NewBufferDB("")
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("buffer init: %w", err)
	}

	// Initialize local history store for persistent periodic threat context.
	history, err := NewHistoryStore("", DefaultHistoryStoreConfig())
	if err != nil {
		Logger.Warnf("⚠️  History store unavailable; persistent periodic scoring disabled: %v", err)
	}

	// Detect the kernel's ephemeral port range once at startup so
	// trackedPortForEvent can skip transient local ports (DNS, NTP replies, …).
	initEphemeralPortRange()

	// Get server's local IPs at startup (IPv4 + IPv6)
	serverIPs := getServerIPs()

	// Cache public IP once at startup, fall back to local IP
	cachedPublicIP := getPublicIP()
	if cachedPublicIP == "" {
		Logger.Warn("⚠️  Could not detect public IP, falling back to local IP")
		for ip := range serverIPs {
			cachedPublicIP = ip
			break
		}
	}

	// Compute boot time for eBPF monotonic timestamp conversion
	bootTime := getBootTime()
	serverID := extractServerIDFromAPIKey(apiKey)
	if serverID == "" {
		Logger.Warn("⚠️  Could not extract server UUID from API key; server_id will be omitted in block reports")
	}

	agg := &Aggregator{
		stats:             NewSafeStats(),
		flushChan:         make(chan struct{}),
		stopChan:          make(chan struct{}),
		apiKey:            apiKey,
		serverHost:        serverHost,
		grpcURL:           grpcTarget,
		serverID:          serverID,
		agentVersion:      agentVersion,
		grpcConn:          conn,
		grpcClient:        pb.NewIngestServiceClient(conn),
		remediator:        rem,
		analyzer:          ana,
		history:           history,
		buffer:            buffer,
		cachedPublicIP:    cachedPublicIP,
		serverIPs:         serverIPs,
		bootTime:          bootTime,
		agentPID:          uint32(os.Getpid()),
		controlPlaneIPs:   controlPlaneIPs,
		controlPlaneHost:  controlPlaneHost,
		controlPlanePort:  controlPlanePort,
		maxReconnectDelay: 5 * time.Minute,
	}
	if len(controlPlaneIPs) > 0 {
		Logger.Infof("ℹ️  Control-plane filter enabled: host=%s port=%d resolved_ips=%d", controlPlaneHost, controlPlanePort, len(controlPlaneIPs))
	}

	// Start connection monitor
	agg.wg.Add(1)
	go agg.monitorConnection()

	// Start periodic buffer maintenance (TTL eviction + size enforcement)
	agg.wg.Add(1)
	go agg.runBufferMaintenance()

	return agg, nil
}

// runBufferMaintenance runs an hourly loop that evicts expired SQLite buffer batches.
// This prevents unbounded disk growth during extended backend outages.
func (a *Aggregator) runBufferMaintenance() {
	defer a.wg.Done()
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if a.buffer == nil {
				continue
			}
			evicted, err := a.buffer.EvictExpired(24 * time.Hour)
			if err != nil {
				Logger.Warnf("⚠️  Buffer TTL eviction error: %v", err)
			} else if evicted > 0 {
				Logger.Infof("🗑️  Buffer maintenance: evicted %d expired batches (>24h old)", evicted)
			}
		case <-a.stopChan:
			return
		}
	}
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

// ephemeralPortMin/Max define the kernel's local ephemeral port range.
// Initialised once at startup from /proc/sys/net/ipv4/ip_local_port_range;
// falls back to the Linux kernels default range (32768–60999).
var (
	ephemeralPortMin uint16 = 32768
	ephemeralPortMax uint16 = 60999
)

// initEphemeralPortRange reads the kernel's ephemeral port range so we can
// distinguish service ports (22, 80, 443 …) from transient client-side ports.
func initEphemeralPortRange() {
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		Logger.Debugf("Could not read ephemeral port range, using defaults 32768-60999: %v", err)
		return
	}
	var lo, hi int
	// The file contains two numbers separated by a tab
	if _, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%d %d", &lo, &hi); err != nil {
		Logger.Debugf("Could not parse ephemeral port range, using defaults: %v", err)
		return
	}
	if lo > 0 && hi > 0 && lo < hi && hi <= 65535 {
		ephemeralPortMin = uint16(lo)
		ephemeralPortMax = uint16(hi)
		Logger.Infof("ℹ️  Ephemeral port range: %d–%d", lo, hi)
	}
}

// isEphemeralPort reports whether port is in the kernel's ephemeral range.
// These ports are assigned by the OS for outbound connections, not bound services.
func isEphemeralPort(port uint16) bool {
	return port >= ephemeralPortMin && port <= ephemeralPortMax
}

// trackedPortForEvent returns the service/destination port to use as the
// aggregation key for a given eBPF event.
//
// Outbound events: Lport is an ephemeral client port → use Rport.
//
// Inbound events: Lport is normally the server's bound service port (22, 80, …).
// Exception: UDP responses arriving at an ephemeral Lport — these are replies to
// an outbound query the kernel sent (e.g. DNS, NTP).  In that case Lport is the
// transient source port we used, so we fall back to Rport (the remote service).
// This prevents dozens of one-off ephemeral ports filling the dashboard.
func trackedPortForEvent(event Event) uint16 {
	if event.Direction == DirOutbound {
		if event.Rport != 0 {
			return event.Rport
		}
		return event.Lport
	}
	// Inbound: use Lport unless it is itself ephemeral (= UDP response to our query).
	if event.Lport != 0 && !isEphemeralPort(event.Lport) {
		return event.Lport
	}
	return event.Rport
}

func resolveControlPlaneEndpoint(target string) (host string, port uint16, ips map[string]bool) {
	ips = make(map[string]bool)

	dialTarget := buildGRPCDialTarget(target)
	host = dialTarget
	port = 0
	if h, p, err := net.SplitHostPort(dialTarget); err == nil {
		host = h
		if parsed, err := strconv.Atoi(p); err == nil && parsed >= 0 && parsed <= 65535 {
			port = uint16(parsed)
		}
	}

	if parsedIP := net.ParseIP(host); parsedIP != nil {
		ips[parsedIP.String()] = true
		return host, port, ips
	}

	resolved, err := net.LookupIP(host)
	if err != nil {
		Logger.Warnf("⚠️  Could not resolve gRPC host %q for control-plane filtering: %v", host, err)
		return host, port, ips
	}

	for _, ip := range resolved {
		ips[ip.String()] = true
	}

	return host, port, ips
}

func eventCommName(event Event) string {
	name := event.Comm[:]
	if idx := bytes.IndexByte(name, 0); idx >= 0 {
		name = name[:idx]
	}
	return strings.TrimSpace(string(name))
}

func (a *Aggregator) isControlPlaneTraffic(event Event, remoteIP net.IP) bool {
	if event.Direction != DirOutbound {
		return false
	}
	if len(a.controlPlaneIPs) == 0 {
		return false
	}
	return a.controlPlaneIPs[remoteIP.String()]
}

func (a *Aggregator) isAgentSelfTraffic(event Event) bool {
	// Primary check: TGID equals current agent process.
	if a.agentPID != 0 && event.Tgid == a.agentPID {
		return true
	}

	// Fallback for environments where TGID might be unavailable in event data.
	comm := eventCommName(event)
	return comm == "kerneleye-agent" || comm == "kerneleye"
}

// ProcessEvent processes a single eBPF event (thread-safe via SafeStats)
func (a *Aggregator) ProcessEvent(event Event) {
	if a.isAgentSelfTraffic(event) {
		return
	}

	ipObj := bytesToIP(event.Saddr[:], event.Family)
	if a.isControlPlaneTraffic(event, ipObj) {
		return
	}
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
	trackedPort := trackedPortForEvent(event)

	// GetOrCreate atomically gets or creates stats entry
	stats, isNew := a.stats.GetOrCreate(ip, func() *IPStats {
		return &IPStats{
			Protocol:     event.Protocol,
			UniquePorts:  make(map[uint16]bool),
			PortCounts:   make(map[uint16]int),
			PortHits:     make(map[uint16]int),
			PortBytesIn:  make(map[uint16]uint64),
			PortBytesOut: make(map[uint16]uint64),
			FirstSeen:    eventTime,
			Direction:    event.Direction,
			LocalIP:      localIP,
		}
	})

	// Update stats under per-entry lock to prevent concurrent map writes and data races
	stats.mu.Lock()
	stats.LastSeen = eventTime
	stats.Protocol = event.Protocol

	// SYN detection: If this is the first time we've seen this IP, it's a SYN
	// (Every TCP connection starts with SYN, so first event = SYN)
	if isNew {
		stats.SYNCount++
		if Logger != nil {
			Logger.Debugf("First event for IP %s - marking as SYN (syn detection via first-event inference)", ip)
		}
	} else {
		// For subsequent events, use actual flags
		if event.Flags&0x01 != 0 {
			stats.SYNCount++
			if Logger != nil {
				Logger.Debugf("Event from existing IP %s has SYN flag set", ip)
			}
		}
	}
	if event.Flags&0x02 != 0 {
		stats.ACKCount++
	}
	stats.UniquePorts[trackedPort] = true
	stats.PortCounts[trackedPort]++
	stats.PortHits[trackedPort]++ // Track hits per port for service abuse detection
	if comm := eventCommName(event); comm != "" {
		stats.ProcessName = comm
	}
	stats.mu.Unlock()

	// Analyze traffic for remediation
	if a.analyzer != nil && a.remediator != nil {
		te := remediation.TrafficEvent{
			SourceIP: ipObj,
			DestPort: trackedPort,
			Protocol: event.Protocol,
			Flags:    event.Flags,
			Time:     eventTime,
		}
		if decision := a.analyzer.Evaluate(te); decision != nil {
			switch decision.Action {
			case remediation.ActionBlock:
				if err := a.remediator.Block(decision.IP, decision.Duration); err != nil {
					Logger.Errorf("❌ Failed to block IP %s: %v", decision.IP, err)
				}
				a.ReportBlockedIPWithContext(decision.IP, remediation.ActionBlock, decision.Reason, decision.Duration, decision.DestPort, decision.Protocol)
			case remediation.ActionRateLimit:
				if err := a.remediator.RateLimit(decision.IP, decision.Duration); err != nil {
					Logger.Errorf("❌ Failed to rate-limit IP %s: %v", decision.IP, err)
				}
				a.ReportBlockedIPWithContext(decision.IP, remediation.ActionRateLimit, decision.Reason, decision.Duration, decision.DestPort, decision.Protocol)
			}
		}
	}
}

// StartFlushTimer starts periodic flushing and heartbeat with stoppable timers
func (a *Aggregator) StartFlushTimer(interval time.Duration) {
	a.flushTicker = time.NewTicker(interval)
	a.heartbeatTicker = time.NewTicker(30 * time.Second)

	a.wg.Go(func() {
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
	})
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
		Logger.Warn("⚠️  gRPC client not initialized, skipping heartbeat")
		a.scheduleReconnect()
		return
	}
	resp, err := client.Heartbeat(ctx, &pb.HeartbeatRequest{
		ApiKey: a.apiKey, Hostname: hostname, AgentVersion: Version, IpAddress: a.cachedPublicIP,
	})
	a.grpcMu.RUnlock()
	if err != nil {
		Logger.Errorf("❌ gRPC heartbeat error: %v", err)
		a.scheduleReconnect()
		return
	}
	if !resp.Success {
		Logger.Warnf("⚠️  Server status: %s - Agent will exit", resp.Message)
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
		Logger.Infof("🔄 gRPC connection state: %v - attempting reconnect", state)
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

	Logger.Infof("⏳ Scheduling reconnection attempt %d in %v", attempt, delay)

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
	Logger.Infof("🔄 Attempting to reconnect to gRPC server %s (attempt %d)...", a.grpcURL, attempt)

	// Create new connection
	conn, err := grpc.NewClient(grpcDialTargetPrefix+buildGRPCDialTarget(a.grpcURL), buildGRPCOpts(a.grpcURL)...)
	if err != nil {
		Logger.Errorf("❌ Failed to create new gRPC connection: %v", err)
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
		Logger.Errorf("❌ Reconnection test failed: %v", err)
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

	// Update block command client if set
	if a.blockCmdClient != nil {
		a.blockCmdClient.UpdateClient(conn)
	}

	a.reconnectMu.Lock()
	a.reconnectCount = 0 // Reset counter on success
	a.reconnecting = false
	a.reconnectMu.Unlock()

	Logger.Info("✅ Successfully reconnected to gRPC server")
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
	Logger.Debug("[Aggregator.Close] Waiting for background goroutines...")
	a.wg.Wait()
	Logger.Debug("[Aggregator.Close] Background goroutines stopped")

	// Stop timers
	if a.flushTicker != nil {
		a.flushTicker.Stop()
	}
	if a.heartbeatTicker != nil {
		a.heartbeatTicker.Stop()
	}
	Logger.Debug("[Aggregator.Close] Timers stopped")

	// Stop block command client (prevents reconnect attempts after shutdown)
	if a.blockCmdClient != nil {
		a.blockCmdClient.Stop()
	}
	Logger.Debug("[Aggregator.Close] BlockCommandClient stopped")

	// Flush remaining data (safe now — goroutine has exited)
	Logger.Debug("[Aggregator.Close] Flushing remaining data...")
	a.FlushToAPI()
	Logger.Debug("[Aggregator.Close] Flush complete")

	// Close gRPC connection
	Logger.Debug("[Aggregator.Close] Closing gRPC connection...")
	a.grpcMu.Lock()
	if a.grpcConn != nil {
		if err := a.grpcConn.Close(); err != nil {
			Logger.Warnf("⚠️  Error closing gRPC connection: %v", err)
		}
		a.grpcConn = nil
		a.grpcClient = nil
	}
	a.grpcMu.Unlock()
	Logger.Debug("[Aggregator.Close] gRPC connection closed")

	// Close buffer database
	if a.buffer != nil {
		Logger.Debug("[Aggregator.Close] Closing buffer DB...")
		if err := a.buffer.Close(); err != nil {
			Logger.Warnf("⚠️  Error closing buffer DB: %v", err)
		}
		Logger.Debug("[Aggregator.Close] Buffer DB closed")
	}

	if a.history != nil {
		Logger.Debug("[Aggregator.Close] Closing history DB...")
		if err := a.history.Close(); err != nil {
			Logger.Warnf("⚠️  Error closing history DB: %v", err)
		}
		Logger.Debug("[Aggregator.Close] History DB closed")
	}

	Logger.Info("[Aggregator] Closed successfully")
	return nil
}

// GetStats returns a snapshot of the stats map (for testing/debugging)
func (a *Aggregator) GetStats() map[string]*IPStats {
	return a.stats.Snapshot()
}

// GetPrimaryPortForIP returns the most frequently targeted port and its
// protocol for a given IP address, as recorded in the current stats window.
// Returns (0, 6) when the IP is unknown (fall back to no-port reporting).
func (a *Aggregator) GetPrimaryPortForIP(ip string) (port uint16, protocol uint8) {
	stats, ok := a.stats.Get(ip)
	if !ok {
		return 0, 6
	}
	stats.mu.Lock()
	defer stats.mu.Unlock()
	var maxCount int
	for p, count := range stats.PortCounts {
		if count > maxCount {
			maxCount = count
			port = p
		}
	}
	return port, stats.Protocol
}

// ReportBlockedPacket sends a blocked packet event to the backend via gRPC
// This is called by the XDP remediator when a packet is blocked
func (a *Aggregator) ReportBlockedPacket(ip string, port uint16, protocol uint8, reason uint8) {
	// Map protocol number to protobuf enum
	var proto pb.Protocol
	switch protocol {
	case 6:
		proto = pb.Protocol_PROTOCOL_TCP
	case 17:
		proto = pb.Protocol_PROTOCOL_UDP
	case 1:
		proto = pb.Protocol_PROTOCOL_ICMP
	default:
		proto = pb.Protocol_PROTOCOL_UNKNOWN
	}

	// Map reason to protobuf enum
	var blockReason pb.BlockReason
	switch reason {
	case 1:
		blockReason = pb.BlockReason_BLOCK_REASON_BLOCKLIST
	case 2:
		blockReason = pb.BlockReason_BLOCK_REASON_CIDR
	case 3:
		blockReason = pb.BlockReason_BLOCK_REASON_RATE_LIMIT
	default:
		blockReason = pb.BlockReason_BLOCK_REASON_UNKNOWN
	}

	req := &pb.BlockedPacketEvent{
		ApiKey:          a.apiKey,
		ServerId:        a.serverID,
		SourceIp:        ip,
		DestinationPort: uint32(port),
		Protocol:        proto,
		Reason:          blockReason,
		Timestamp:       timestamppb.New(time.Now()),
	}

	// Send asynchronously to avoid blocking the ring buffer reader
	go func() {
		a.grpcMu.RLock()
		client := a.grpcClient
		if client == nil {
			a.grpcMu.RUnlock()
			Logger.Warn("⚠️  gRPC client not initialized, cannot report blocked packet")
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := client.ReportBlockedPacket(ctx, req)
		a.grpcMu.RUnlock()
		cancel()

		if err != nil {
			Logger.Warnf("⚠️  Failed to report blocked packet from %s: %v", ip, err)
		} else {
			Logger.Debugf("📡 Reported blocked packet from %s:%d (reason: %d) to backend", ip, port, reason)
		}
	}()
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
		AgentVersion:    a.agentVersion,
	}

	// Retry up to 3 times with exponential backoff
	var err error
	for attempt := range 3 {
		a.grpcMu.RLock()
		client := a.grpcClient
		if client == nil {
			a.grpcMu.RUnlock()
			Logger.Warn("⚠️  gRPC client not initialized, cannot report blocked IP")
			a.scheduleReconnect()
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err = client.ReportBlockedIP(ctx, req)
		a.grpcMu.RUnlock()
		cancel()
		if err == nil {
			Logger.Infof("📡 Reported blocked IP %s (%s) to backend", ip, action)
			return
		}
		Logger.Warnf("⚠️  Attempt %d/3 failed to report blocked IP %s: %v", attempt+1, ip, err)
		if attempt < 2 {
			time.Sleep(time.Duration(1<<attempt) * time.Second) // 1s, 2s backoff
		}
	}
	a.scheduleReconnect()
	Logger.Errorf("❌ Failed to report blocked IP %s after 3 attempts: %v", ip, err)
}

// SyncIPSetToBackend reports any IP currently in the local ipset that the backend
// doesn't already know about. Called once on startup so IPs that survived a restart
// (via Restore()) appear in the dashboard without waiting for a new block event.
func (a *Aggregator) SyncIPSetToBackend(ipsetRem *remediation.IPSetRemediator) {
	if ipsetRem == nil {
		return
	}
	entries, err := ipsetRem.ListCurrentlyBlocked()
	if err != nil {
		Logger.Warnf("⚠️  SyncIPSetToBackend: failed to read ipset: %v", err)
		return
	}
	if len(entries) == 0 {
		Logger.Info("📋 SyncIPSetToBackend: ipset is empty, nothing to sync")
		return
	}
	Logger.Infof("📋 SyncIPSetToBackend: syncing %d locally-blocked IPs to backend", len(entries))
	now := time.Now()
	for _, e := range entries {
		action := remediation.ActionBlock
		reason := "ipset_block"
		if e.BlockType == remediation.BlockTypeRateLimit {
			action = remediation.ActionRateLimit
			reason = "ipset_ratelimit"
		}
		port, proto := a.history.GetContext(e.IP.String(), 0, now)
		if port > 0 {
			a.ReportBlockedIPWithContext(e.IP, action, reason, 0, port, proto)
		} else {
			a.ReportBlockedIP(e.IP, action, reason, 0)
		}
	}
	Logger.Infof("✅ SyncIPSetToBackend: sync complete")
}

// SyncXDPToBackend reports IPs currently in the XDP blocklist BPF maps to the
// backend so the dashboard reflects kernel-level XDP state on startup.
func (a *Aggregator) SyncXDPToBackend(xdpRem *remediation.XDPRemediator) {
	if xdpRem == nil {
		return
	}
	entries, err := xdpRem.ListCurrentlyBlocked()
	if err != nil {
		Logger.Warnf("⚠️  SyncXDPToBackend: failed to read XDP maps: %v", err)
		return
	}
	if len(entries) == 0 {
		Logger.Info("📋 SyncXDPToBackend: XDP blocklist is empty, nothing to sync")
		return
	}
	Logger.Infof("📋 SyncXDPToBackend: syncing %d XDP-blocked IPs to backend", len(entries))
	now := time.Now()
	for _, e := range entries {
		port, proto := a.history.GetContext(e.IP.String(), 0, now)
		if port > 0 {
			a.ReportBlockedIPWithContext(e.IP, remediation.ActionBlock, "xdp_block", 0, port, proto)
		} else {
			a.ReportBlockedIP(e.IP, remediation.ActionBlock, "xdp_block", 0)
		}
	}
	Logger.Infof("✅ SyncXDPToBackend: sync complete")
}

// ReportBlockedIPWithContext sends a blocked IP event with port/protocol context
func (a *Aggregator) ReportBlockedIPWithContext(ip net.IP, action remediation.Action, reason string, duration time.Duration, targetPort uint16, protocol uint8) {
	var blockAction pb.BlockAction
	switch action {
	case remediation.ActionBlock:
		blockAction = pb.BlockAction_BLOCK_ACTION_BLOCK
	case remediation.ActionRateLimit:
		blockAction = pb.BlockAction_BLOCK_ACTION_RATE_LIMIT
	default:
		blockAction = pb.BlockAction_BLOCK_ACTION_ALLOW
	}

	// Convert protocol number to Protocol enum
	var proto pb.Protocol
	switch protocol {
	case 6:
		proto = pb.Protocol_PROTOCOL_TCP
	case 17:
		proto = pb.Protocol_PROTOCOL_UDP
	case 1:
		proto = pb.Protocol_PROTOCOL_ICMP
	default:
		proto = pb.Protocol_PROTOCOL_UNKNOWN
	}

	req := &pb.BlockedIPEvent{
		ApiKey:          a.apiKey,
		ServerId:        a.serverID,
		IpAddress:       ip.String(),
		Action:          blockAction,
		DurationSeconds: uint32(duration.Seconds()),
		Reason:          reason,
		TargetPort:      uint32(targetPort),
		Protocol:        proto,
		AgentVersion:    a.agentVersion,
	}

	// Retry up to 3 times with exponential backoff
	var err error
	for attempt := range 3 {
		a.grpcMu.RLock()
		client := a.grpcClient
		if client == nil {
			a.grpcMu.RUnlock()
			Logger.Warn("⚠️  gRPC client not initialized, cannot report blocked IP")
			a.scheduleReconnect()
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err = client.ReportBlockedIP(ctx, req)
		a.grpcMu.RUnlock()
		cancel()
		if err == nil {
			Logger.Infof("📡 Reported blocked IP %s (%s) to backend", ip, action)
			return
		}
		Logger.Warnf("⚠️  Attempt %d/3 failed to report blocked IP %s: %v", attempt+1, ip, err)
		if attempt < 2 {
			time.Sleep(time.Duration(1<<attempt) * time.Second) // 1s, 2s backoff
		}
	}
	a.scheduleReconnect()
	Logger.Errorf("❌ Failed to report blocked IP %s after 3 attempts: %v", ip, err)
}
