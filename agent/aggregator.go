package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kerneleye/agent/remediation"
	pb "github.com/kerneleye/proto/kerneleye/v1"
	"github.com/kerneleye/shared/scoring"
	"google.golang.org/grpc"
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
	whitelistMu        sync.RWMutex
	whitelistedIPs     map[string]bool

	blockCmdClient *BlockCommandClient // Receives block commands from backend

	tlsCfg *TLSTransportConfig // TLS configuration for all gRPC connections

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
func NewAggregator(apiKey, serverHost, grpcURL, agentVersion string, tlsCfg *TLSTransportConfig, rem remediation.Remediator, ana *remediation.Analyzer, autoBlocker *remediation.AutoBlocker, scorer *scoring.ThreatScorer) (*Aggregator, error) {
	grpcTarget := buildGRPCTarget(serverHost, grpcURL)
	controlPlaneHost, controlPlanePort, controlPlaneIPs := resolveControlPlaneEndpoint(grpcTarget)
	conn, err := grpc.NewClient(grpcDialTargetPrefix+buildGRPCDialTarget(grpcTarget), buildGRPCOpts(tlsCfg)...)
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
		whitelistedIPs:    make(map[string]bool),
		tlsCfg:            tlsCfg,
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

// GetPrimaryPortForIP returns the most frequently targeted port, its protocol,
// and the process name for a given IP address, as recorded in the current stats window.
// Returns (0, 6, "") when the IP is unknown (fall back to no-port reporting).
func (a *Aggregator) GetPrimaryPortForIP(ip string) (port uint16, protocol uint8, processName string) {
	stats, ok := a.stats.Get(ip)
	if !ok {
		return 0, 6, ""
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
	return port, stats.Protocol, stats.ProcessName
}

// resolveAgentService derives the service name from process name and/or port/protocol.
// Mirrors the logic in backend/internal/services for consistent block reporting.
func resolveAgentService(processName string, port uint16, protocol uint8) string {
	processToService := map[string]string{
		"nginx":      "nginx",
		"apache2":    "apache",
		"httpd":      "apache",
		"sshd":       "ssh",
		"mysqld":     "mysql",
		"postgres":   "postgresql",
		"redis-serv": "redis",
		"mongod":     "mongodb",
		"vsftpd":     "ftp",
		"proftpd":    "ftp",
		"postfix":    "smtp",
		"dovecot":    "imap",
		"named":      "dns",
		"dnsmasq":    "dns",
		"openvpn":    "vpn",
	}
	if processName != "" {
		lp := strings.ToLower(processName)
		if svc, ok := processToService[lp]; ok {
			return svc
		}
		for proc, svc := range processToService {
			if strings.HasPrefix(lp, proc) || strings.HasPrefix(proc, lp) {
				return svc
			}
		}
	}
	portToService := map[uint16]string{
		22:    "ssh",
		80:    "http",
		443:   "https",
		53:    "dns",
		3306:  "mysql",
		5432:  "postgresql",
		6379:  "redis",
		27017: "mongodb",
		21:    "ftp",
		23:    "telnet",
		3389:  "rdp",
		587:   "smtp",
		110:   "pop3",
		143:   "imap",
		8080:  "http-alt",
		8000:  "http-alt",
		3000:  "http-dev",
		993:   "imaps",
		995:   "pop3s",
		25:    "smtp",
		67:    "dhcp",
		68:    "dhcp",
		161:   "snmp",
		389:   "ldap",
		636:   "ldaps",
		1194:  "openvpn",
		8443:  "https-alt",
	}
	if svc, ok := portToService[port]; ok {
		return svc
	}
	if protocol == 17 {
		return "udp"
	}
	return ""
}

// ReportBlockedPacket sends a blocked packet event to the backend via gRPC
// This is called by the XDP remediator when a packet is blocked
