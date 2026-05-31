package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kerneleye/agent/remediation"
)

// Event processing and traffic filtering for the Aggregator.
// Handles ring-buffer event ingestion, control-plane filtering,
// self-traffic detection, and per-IP whitelist evaluation.

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

func normalizeIPString(ip string) string {
	ip = strings.TrimSpace(ip)
	if parsed := net.ParseIP(ip); parsed != nil {
		return parsed.String()
	}
	return ip
}

func eventCommName(event Event) string {
	name := event.Comm[:]
	if idx := bytes.IndexByte(name, 0); idx >= 0 {
		name = name[:idx]
	}
	return strings.TrimSpace(string(name))
}

func (a *Aggregator) isControlPlaneTraffic(event Event, remoteIP net.IP) bool {
	if len(a.controlPlaneIPs) == 0 {
		return false
	}
	if !a.controlPlaneIPs[remoteIP.String()] {
		return false
	}

	// Outbound connections to the control plane should never be scored.
	if event.Direction == DirOutbound {
		return true
	}

	// Some kernel hooks (for example tcp_receive_reset) surface responses from
	// outbound connects as inbound events. Ignore only the matching control-plane
	// remote port to avoid hiding unrelated inbound activity from the same IP.
	return a.controlPlanePort != 0 && event.Rport == a.controlPlanePort
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

func (a *Aggregator) isHostSelfIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ipStr := ip.String()
	if a.cachedPublicIP != "" && ipStr == a.cachedPublicIP {
		return true
	}
	return a.serverIPs[ipStr]
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
	if a.isHostSelfIP(ipObj) {
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
	stats, _ := a.stats.GetOrCreate(ip, func() *IPStats {
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

	// Count flags from actual event data.
	// TCP connections always start with a SYN event (detect_inbound_syn or
	// detect_tcp_connect both set FLAG_SYN), so no first-event inference is needed.
	if event.Flags&0x01 != 0 {
		stats.SYNCount++
	}
	if event.Flags&0x02 != 0 {
		stats.ACKCount++
	}
	if event.Flags&0x08 != 0 {
		stats.FailedHandshakes++
	}
	stats.UniquePorts[trackedPort] = true
	stats.PortCounts[trackedPort]++
	stats.PortHits[trackedPort]++ // Track hits per port for service abuse detection
	if comm := eventCommName(event); comm != "" {
		stats.ProcessName = comm
	}
	processName := stats.ProcessName
	stats.mu.Unlock()

	if a.isWhitelistedIP(ipObj) {
		return
	}

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
				svcName := resolveAgentService(processName, decision.DestPort, decision.Protocol)
				a.ReportBlockedIPWithContext(decision.IP, remediation.ActionBlock, decision.Reason, decision.Duration, decision.DestPort, decision.Protocol, svcName)
			case remediation.ActionRateLimit:
				if err := a.remediator.RateLimit(decision.IP, decision.Duration); err != nil {
					Logger.Errorf("❌ Failed to rate-limit IP %s: %v", decision.IP, err)
				}
				svcName := resolveAgentService(processName, decision.DestPort, decision.Protocol)
				a.ReportBlockedIPWithContext(decision.IP, remediation.ActionRateLimit, decision.Reason, decision.Duration, decision.DestPort, decision.Protocol, svcName)
			}
		}
	}
}
