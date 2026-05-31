package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/kerneleye/backend/internal/database"
	"github.com/kerneleye/backend/internal/geoip"
	"github.com/kerneleye/backend/internal/services"
	pb "github.com/kerneleye/proto/kerneleye/v1"
	"github.com/kerneleye/shared/scoring"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type GrpcIngestHandler struct {
	pb.UnimplementedIngestServiceServer
	queries *database.Queries
	scorer  *scoring.ThreatScorer
	hub     *Hub
	geoIP   *geoip.Service
}

func NewGrpcIngestHandler(queries *database.Queries, scorer *scoring.ThreatScorer, hub *Hub, geoIP *geoip.Service) *GrpcIngestHandler {
	return &GrpcIngestHandler{
		queries: queries,
		scorer:  scorer,
		hub:     hub,
		geoIP:   geoIP,
	}
}

func (h *GrpcIngestHandler) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	// Validate API key with HMAC verification
	server, err := ValidateAPIKey(ctx, h.queries, req.ApiKey)
	if err != nil {
		log.Printf("[gRPC Heartbeat] API key validation failed: %v", err)
		msg := "invalid_key"
		return &pb.HeartbeatResponse{
			Success: false,
			Message: msg,
		}, nil
	}

	log.Printf("[gRPC Heartbeat] Received heartbeat from server_id=%s hostname=%s ip=%s agent_version=%s",
		server.ID.String(), req.Hostname, req.IpAddress, req.AgentVersion)

	// Check if server is rejected or inactive
	if server.Status == "rejected" || server.Status == "deleted" {
		log.Printf("[gRPC Heartbeat] Ignoring heartbeat for server_id=%s due to status=%s", server.ID.String(), server.Status)
		return &pb.HeartbeatResponse{
			Success: false,
			Message: server.Status,
		}, nil
	}

	// Use agent-provided IP address if available
	var ipAddr *netip.Addr
	if req.IpAddress != "" {
		if addr, err := netip.ParseAddr(req.IpAddress); err == nil {
			ipAddr = &addr
		}
	}

	if err := h.queries.UpdateServerHeartbeat(ctx, database.UpdateServerHeartbeatParams{
		AgentVersion: database.ToPgText(req.AgentVersion),
		IpAddress:    ipAddr,
		ApiKey:       database.ToPgText(req.ApiKey),
	}); err != nil {
		log.Printf("[gRPC Heartbeat] Failed to update: %v", err)
		return nil, status.Errorf(codes.Internal, "Failed to update heartbeat")
	}

	log.Printf("[gRPC Heartbeat] Updated heartbeat for server_id=%s", server.ID.String())

	return &pb.HeartbeatResponse{
		Success: true,
		Message: "Heartbeat received",
	}, nil
}

func (h *GrpcIngestHandler) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	log.Printf("[gRPC Register] Received registration request for hostname: %s, IP: %s", req.Hostname, req.IpAddress)

	// The UserId field now contains the pre-generated API key
	apiKey := req.UserId

	// Decode the API key to get the real user/server identity.
	userID, serverID, err := DecodeAPIKey(apiKey)
	if err != nil {
		log.Printf("[gRPC Register] Invalid API key: %v", err)
		return nil, status.Errorf(codes.InvalidArgument, "Invalid API key")
	}
	decodedServerUUID := database.ToPgUUID(serverID)
	if !decodedServerUUID.Valid {
		log.Printf("[gRPC Register] Invalid server ID in API key: %s", serverID)
		return nil, status.Errorf(codes.InvalidArgument, "Invalid API key server ID")
	}

	// Check if a server with this API key already exists
	existingServer, err := h.queries.GetServerByAPIKey(ctx, database.ToPgText(apiKey))
	if err == nil {
		// Server exists with this API key, return its status
		return &pb.RegisterResponse{
			Success:     true,
			Message:     "Server already registered",
			ClientToken: existingServer.ClientToken.String,
			Status:      existingServer.Status,
		}, nil
	}

	// Parse IP address from request
	var ipAddr *netip.Addr
	if req.IpAddress != "" {
		if addr, err := netip.ParseAddr(req.IpAddress); err == nil {
			ipAddr = &addr
		}
	}

	clientToken := uuid.New().String()

	// Check if user already has a server with this IP (re-enrollment after reformat)
	if ipAddr != nil {
		existingByIP, err := h.queries.GetServerByUserAndIP(ctx, database.GetServerByUserAndIPParams{
			UserID:    database.ToPgUUID(userID),
			IpAddress: ipAddr,
		})
		if err == nil {
			// Only re-enroll when the key maps to the same server ID.
			// If IDs differ, treat as a new enrollment.
			if existingByIP.ID == decodedServerUUID {
				log.Printf("[gRPC Register] Re-enrolling existing server %s with new API key", existingByIP.ID)
				updatedServer, err := h.queries.UpdateServerForReenrollment(ctx, database.UpdateServerForReenrollmentParams{
					ID:          existingByIP.ID,
					ApiKey:      database.ToPgText(apiKey),
					Hostname:    req.Hostname,
					ClientToken: database.ToPgText(clientToken),
				})
				if err != nil {
					log.Printf("[gRPC Register] Failed to re-enroll: %v", err)
					return nil, status.Errorf(codes.Internal, "Failed to re-enroll agent")
				}

				h.hub.Broadcast(userID, "new_server", map[string]string{
					"hostname":     req.Hostname,
					"client_token": clientToken,
					"status":       "active",
					"message":      "Server re-enrolled",
				})

				return &pb.RegisterResponse{
					Success:     true,
					Message:     "Server re-enrolled successfully",
					ClientToken: clientToken,
					Status:      updatedServer.Status,
				}, nil
			}
		}
	}

	// No existing server - create pending server using the server ID embedded in API key.
	_, err = h.queries.CreateServerWithIDAndAPIKey(ctx, database.CreateServerWithIDAndAPIKeyParams{
		ID:          decodedServerUUID,
		UserID:      database.ToPgUUID(userID),
		Hostname:    req.Hostname,
		ApiKey:      database.ToPgText(apiKey),
		ClientToken: database.ToPgText(clientToken),
		IpAddress:   ipAddr,
		Status:      "pending",
	})

	if err != nil {
		log.Printf("[gRPC Register] Error: %v", err)
		return nil, status.Errorf(codes.Internal, "Failed to register agent")
	}

	h.hub.Broadcast(userID, "new_server", map[string]string{
		"hostname":     req.Hostname,
		"client_token": clientToken,
		"status":       "pending",
	})

	return &pb.RegisterResponse{
		Success:     true,
		Message:     "Registration successful, pending approval",
		ClientToken: clientToken,
		Status:      "pending",
	}, nil
}

func (h *GrpcIngestHandler) GetStatus(ctx context.Context, req *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	server, err := h.queries.GetServerByClientToken(ctx, database.ToPgText(req.ClientToken))
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "Server not found")
	}

	apiKey := ""
	if server.Status == "active" {
		// Do not return the actual API key - agent already has it
		apiKey = "configured"
	}

	return &pb.GetStatusResponse{
		Status: server.Status,
		ApiKey: apiKey,
	}, nil
}

func (h *GrpcIngestHandler) SubmitTraffic(ctx context.Context, req *pb.TrafficBatch) (*pb.TrafficResponse, error) {
	// 1. Authenticate server with HMAC verification
	server, err := ValidateAPIKey(ctx, h.queries, req.ApiKey)
	if err != nil {
		log.Printf("[gRPC Traffic] API key validation failed: %v", err)
		return nil, status.Errorf(codes.Unauthenticated, "Invalid API Key")
	}

	log.Printf("[gRPC Traffic] Received batch from server_id=%s hostname=%s events=%d reported_total=%d window_seconds=%d",
		server.ID.String(), server.Hostname, len(req.Events), req.TotalEvents, req.AggregationWindowSeconds)

	if server.Status != "active" {
		log.Printf("[gRPC Traffic] Rejecting batch for server_id=%s due to status=%s", server.ID.String(), server.Status)
		return nil, status.Errorf(codes.PermissionDenied, "Server not active")
	}

	const maxBatchSize = 10000
	if len(req.Events) > maxBatchSize {
		log.Printf("[gRPC Traffic] Rejecting oversized batch from %s: %d events (max %d)", server.Hostname, len(req.Events), maxBatchSize)
		return nil, status.Errorf(codes.InvalidArgument, "Batch too large: %d events (max %d)", len(req.Events), maxBatchSize)
	}

	// Update last_seen
	_ = h.queries.UpdateServerHeartbeat(ctx, database.UpdateServerHeartbeatParams{
		ApiKey:       server.ApiKey,
		AgentVersion: server.AgentVersion,
	})

	eventsProcessed := uint64(0)
	for _, event := range req.Events {
		metrics := buildMetricsFromEvent(event)
		score := h.scorer.CalculateScore(metrics)
		if agentScore, ok := scoreFromAgentEvent(event); ok && agentScore.Score >= score.Score {
			score = agentScore
		}

		sourceIP, err := database.ToNetAddr(event.SourceIp)
		if err != nil {
			log.Printf("Invalid source IP: %v", err)
			continue
		}

		// Parse destination IP if provided
		var destIP *netip.Addr
		if event.DestinationIp != "" {
			if addr, err := netip.ParseAddr(event.DestinationIp); err == nil {
				destIP = &addr
			}
		}

		var country, countryCode, city, isp, asnStr string
		if h.geoIP != nil {
			country, countryCode, city, isp, asnStr, _ = h.geoIP.Lookup(event.SourceIp)
		}

		// Convert protobuf direction to string
		direction := directionLabel(event.Direction)

		protocol := protocolToString(event.Protocol)
		processName := sanitizeProcessName(event.ProcessName)
		serviceName := resolveServiceName(processName, int(event.DestinationPort), event.Protocol)

		_, err = h.queries.UpsertTrafficEvent(ctx, database.UpsertTrafficEventParams{
			ServerID:             server.ID,
			SourceIp:             sourceIP,
			DestinationIp:        destIP,
			DestinationPort:      int32(event.DestinationPort),
			Protocol:             protocol,
			Direction:            direction,
			SynCount:             int32(event.SynCount),
			AckCount:             int32(event.AckCount),
			FailedHandshakes:     int32(event.FailedHandshakes),
			UniquePorts:          int32(event.UniquePortsCount),
			BytesIn:              int64(event.BytesIn),
			BytesOut:             int64(event.BytesOut),
			ThreatScore:          int32(score.Score),
			ThreatLevel:          string(score.Level),
			ThreatType:           database.ToPgText(string(score.Type)),
			FirstSeen:            database.ToPgTimestamptz(event.FirstSeen.AsTime()),
			LastSeen:             database.ToPgTimestamptz(event.LastSeen.AsTime()),
			Country:              database.ToPgText(country),
			CountryCode:          database.ToPgText(countryCode),
			City:                 database.ToPgText(city),
			Isp:                  database.ToPgText(isp),
			Asn:                  database.ToPgText(asnStr),
			IcmpPacketsIn:        int64(event.IcmpPacketsIn),
			IcmpPacketsOut:       int64(event.IcmpPacketsOut),
			ConnectionDurationMs: int64(event.ConnectionDurationMs),
			PortBytesIn:          marshalPortBytes(event.PortBytesIn),
			PortBytesOut:         marshalPortBytes(event.PortBytesOut),
			ServiceName:          serviceName,
		})

		if err == nil {
			eventsProcessed++

			// Record into the time-series timeline table for accurate charts
			_ = h.queries.UpsertTrafficTimeline(ctx, database.UpsertTrafficTimelineParams{
				ServerID:         server.ID,
				SourceIp:         sourceIP,
				Column3:          database.ToPgTimestamptz(event.LastSeen.AsTime()),
				HitCount:         1,
				SynCount:         int32(event.SynCount),
				AckCount:         int32(event.AckCount),
				FailedHandshakes: int32(event.FailedHandshakes),
				BytesIn:          int64(event.BytesIn),
				BytesOut:         int64(event.BytesOut),
				ThreatScore:      int32(score.Score),
			})
			// Include server info in broadcast for multi-server visibility
			serverIP := ""
			if server.IpAddress != nil {
				serverIP = server.IpAddress.String()
			}
			h.hub.Broadcast(server.UserID.String(), "new_traffic", map[string]any{
				"server_id":        server.ID.String(),
				"server_ip":        serverIP,
				"server_hostname":  server.Hostname,
				"source_ip":        event.SourceIp,
				"destination_ip":   event.DestinationIp,
				"destination_port": event.DestinationPort,
				"protocol":         protocol,
				"direction":        direction,
				"syn_count":        event.SynCount,
				"bytes_in":         event.BytesIn,
				"bytes_out":        event.BytesOut,
			})
		} else {
			log.Printf("[gRPC Traffic] Failed to persist event for server_id=%s source_ip=%s dest_ip=%s dest_port=%d: %v",
				server.ID.String(), event.SourceIp, event.DestinationIp, event.DestinationPort, err)
		}

		// Alerts logic could go here similar to HTTP handler
	}

	log.Printf("[gRPC Traffic] Processed batch for server_id=%s processed=%d dropped=%d",
		server.ID.String(), eventsProcessed, uint64(len(req.Events))-eventsProcessed)

	dropped := uint64(len(req.Events)) - eventsProcessed
	success := dropped == 0
	message := "Traffic data processed"
	if !success {
		message = fmt.Sprintf("Traffic batch partially processed: processed=%d dropped=%d", eventsProcessed, dropped)
	}

	return &pb.TrafficResponse{
		Success:         success,
		Message:         message,
		EventsProcessed: eventsProcessed,
	}, nil
}

func buildMetricsFromEvent(event *pb.ConnectionEvent) scoring.IPMetrics {
	synCount := int(event.SynCount)
	ackCount := int(event.AckCount)
	failed := int(event.FailedHandshakes)

	servicePorts := make([]int, 0, len(event.PortsAccessed))
	for _, port := range event.PortsAccessed {
		servicePorts = append(servicePorts, int(port))
	}

	uniquePorts := int(event.UniquePortsCount)
	if uniquePorts == 0 && len(servicePorts) > 0 {
		uniquePorts = len(servicePorts)
	}

	firstSeen, lastSeen := normalizeWindow(event.FirstSeen.AsTime(), event.LastSeen.AsTime())

	established := ackCount - synCount
	if established < 0 {
		established = 0
	}

	maxPortHits := synCount
	if ackCount > maxPortHits {
		maxPortHits = ackCount
	}
	if failed > maxPortHits {
		maxPortHits = failed
	}

	portHits := map[int]int{}
	if event.DestinationPort > 0 && maxPortHits > 0 {
		portHits[int(event.DestinationPort)] = maxPortHits
	}

	return scoring.IPMetrics{
		SYNCount:               synCount,
		ACKCount:               ackCount,
		FailedHandshakes:       failed,
		UniquePorts:            uniquePorts,
		TotalConnections:       synCount + ackCount,
		BytesIn:                event.BytesIn,
		BytesOut:               event.BytesOut,
		WindowStart:            firstSeen,
		WindowEnd:              lastSeen,
		EstablishedConnections: established,
		PreviousScore:          int(event.ThreatScore),
		ServicePorts:           servicePorts,
		PortHits:               portHits,
		MaxPortHits:            maxPortHits,
		PrimaryPort:            int(event.DestinationPort),
		Direction:              scoringDirection(event.Direction),
	}
}

func scoreFromAgentEvent(event *pb.ConnectionEvent) (scoring.ThreatScore, bool) {
	hasScore := event.ThreatScore > 0 ||
		event.ThreatLevel != pb.ThreatLevel_THREAT_LEVEL_NORMAL ||
		event.ThreatType != pb.ThreatType_THREAT_TYPE_NONE
	if !hasScore {
		return scoring.ThreatScore{}, false
	}

	return scoring.ThreatScore{
		Score:      int(event.ThreatScore),
		Level:      scoringThreatLevel(event.ThreatLevel),
		Type:       scoringThreatType(event.ThreatType),
		Reasons:    event.Reasons,
		Timestamp:  time.Now(),
		Direction:  scoringDirection(event.Direction),
		Confidence: 1.0,
	}, true
}

func normalizeWindow(start, end time.Time) (time.Time, time.Time) {
	now := time.Now()
	oneYearAgo := now.AddDate(-1, 0, 0)
	oneYearFromNow := now.AddDate(1, 0, 0)

	if start.IsZero() || start.Before(oneYearAgo) || start.After(oneYearFromNow) {
		start = now
	}
	if end.IsZero() || end.Before(oneYearAgo) || end.After(oneYearFromNow) {
		end = now
	}
	if end.Before(start) {
		end = start
	}

	return start, end
}

func scoringDirection(direction pb.Direction) scoring.Direction {
	if direction == pb.Direction_DIRECTION_OUTBOUND {
		return scoring.DirectionOutbound
	}
	if direction == pb.Direction_DIRECTION_INBOUND {
		return scoring.DirectionInbound
	}
	return scoring.DirectionUnknown
}

func directionLabel(direction pb.Direction) string {
	if direction == pb.Direction_DIRECTION_OUTBOUND {
		return "outbound"
	}
	return "inbound"
}

func scoringThreatLevel(level pb.ThreatLevel) scoring.ThreatLevel {
	switch level {
	case pb.ThreatLevel_THREAT_LEVEL_MALICIOUS:
		return scoring.ThreatLevelMalicious
	case pb.ThreatLevel_THREAT_LEVEL_SUSPICIOUS:
		return scoring.ThreatLevelSuspicious
	default:
		return scoring.ThreatLevelNormal
	}
}

func scoringThreatType(threatType pb.ThreatType) scoring.ThreatType {
	switch threatType {
	case pb.ThreatType_THREAT_TYPE_PORT_SCAN:
		return scoring.ThreatTypePortScan
	case pb.ThreatType_THREAT_TYPE_SERVICE_ABUSE:
		return scoring.ThreatTypeServiceAbuse
	case pb.ThreatType_THREAT_TYPE_SYN_FLOOD:
		return scoring.ThreatTypeSynFlood
	case pb.ThreatType_THREAT_TYPE_FAILED_HANDSHAKE:
		return scoring.ThreatTypeFailedHandshake
	case pb.ThreatType_THREAT_TYPE_CONNECTION_BURST:
		return scoring.ThreatTypeConnectionBurst
	default:
		return scoring.ThreatTypeNone
	}
}

// getServiceFromPort returns a service name string based on port number
func getServiceFromPort(port int) string {
	return services.ServiceFromPort(port)
}

// resolveServiceName returns the application-layer service name.
// Priority order:
//  1. Process name from eBPF comm field (works for custom ports, e.g. sshd on 2222)
//  2. Well-known port number lookup (fallback when process name is unavailable)
//  3. L4 protocol string as last resort
// sanitizeProcessName strips non-printable characters and truncates to 15 chars
// (TASK_COMM_LEN-1). The eBPF comm field is max 16 bytes including null terminator.
func sanitizeProcessName(name string) string {
	var buf []byte
	for _, r := range name {
		if r >= 0x20 && r < 0x7F {
			buf = append(buf, byte(r))
		}
		if len(buf) >= 15 {
			break
		}
	}
	return string(buf)
}

func resolveServiceName(processName string, port int, proto pb.Protocol) string {
	return services.ResolveService(processName, port, protocolToString(proto))
}

func protocolToString(protocol pb.Protocol) string {
	switch protocol {
	case pb.Protocol_PROTOCOL_TCP:
		return "TCP"
	case pb.Protocol_PROTOCOL_UDP:
		return "UDP"
	case pb.Protocol_PROTOCOL_ICMP:
		return "ICMP"
	default:
		return "UNKNOWN"
	}
}

func normalizeProtocolString(protocol string) string {
	switch protocol {
	case "tcp", "TCP":
		return "TCP"
	case "udp", "UDP":
		return "UDP"
	case "icmp", "ICMP":
		return "ICMP"
	default:
		return "UNKNOWN"
	}
}

// marshalPortBytes serializes a port-to-bytes map as JSON for JSONB storage.
// Returns '{}' when m is nil or empty.
func marshalPortBytes(m map[uint32]uint64) []byte {
	if len(m) == 0 {
		return []byte("{}")
	}
	b, err := json.Marshal(m)
	if err != nil {
		return []byte("{}")
	}
	return b
}

func (h *GrpcIngestHandler) ReportBlockedPacket(ctx context.Context, req *pb.BlockedPacketEvent) (*pb.BlockedPacketResponse, error) {
	// Validate API key
	server, err := ValidateAPIKey(ctx, h.queries, req.ApiKey)
	if err != nil {
		log.Printf("[gRPC ReportBlockedPacket] API key validation failed: %v", err)
		return nil, status.Errorf(codes.Unauthenticated, "Invalid API Key")
	}

	if server.Status != "active" {
		log.Printf("[gRPC ReportBlockedPacket] Rejecting for server_id=%s due to status=%s", server.ID.String(), server.Status)
		return nil, status.Errorf(codes.PermissionDenied, "Server not active")
	}

	// Get protocol string
	protocol := "TCP"
	switch req.Protocol {
	case pb.Protocol_PROTOCOL_UDP:
		protocol = "UDP"
	case pb.Protocol_PROTOCOL_ICMP:
		protocol = "ICMP"
	}

	// Get reason string
	reason := "unknown"
	switch req.Reason {
	case pb.BlockReason_BLOCK_REASON_BLOCKLIST:
		reason = "blocklist"
	case pb.BlockReason_BLOCK_REASON_CIDR:
		reason = "cidr"
	case pb.BlockReason_BLOCK_REASON_RATE_LIMIT:
		reason = "rate_limit"
	}

	log.Printf("[gRPC ReportBlockedPacket] server_id=%s ip=%s port=%d protocol=%s reason=%s",
		server.ID.String(), req.SourceIp, req.DestinationPort, protocol, reason)

	// Get GeoIP info if available
	var country, countryCode string
	if h.geoIP != nil {
		country, countryCode, _, _, _, _ = h.geoIP.Lookup(req.SourceIp)
	}

	// Broadcast to connected dashboard clients
	h.hub.Broadcast(server.UserID.String(), "blocked_packet", map[string]any{
		"server_id":        server.ID.String(),
		"server_hostname":  server.Hostname,
		"source_ip":        req.SourceIp,
		"destination_port": req.DestinationPort,
		"protocol":         protocol,
		"reason":           reason,
		"timestamp":        req.Timestamp.AsTime(),
		"country":          country,
		"country_code":     countryCode,
	})

	return &pb.BlockedPacketResponse{
		Success: true,
	}, nil
}

// enrichContextFromHistory looks up the most recent inbound traffic event for
// the given IP and returns port, service and normalised protocol string.
// Returns zeroed values when nothing is found – callers must check before use.
func enrichContextFromHistory(
	ctx context.Context,
	queries interface {
		GetIPTrafficHistory(context.Context, database.GetIPTrafficHistoryParams) ([]database.GetIPTrafficHistoryRow, error)
	},
	ipAddr netip.Addr,
	server database.Server,
) (port int32, service string, proto string) {
	history, err := queries.GetIPTrafficHistory(ctx, database.GetIPTrafficHistoryParams{
		SourceIp: ipAddr,
		UserID:   server.UserID,
		Limit:    10,
	})
	if err != nil {
		return 0, "", ""
	}

	var best *database.GetIPTrafficHistoryRow
	// Prefer a row from the same server
	for i := range history {
		row := &history[i]
		if database.FromPgUUID(row.ServerID) == database.FromPgUUID(server.ID) && row.Direction == "inbound" {
			best = row
			break
		}
	}
	if best == nil {
		for i := range history {
			row := &history[i]
			if row.Direction == "inbound" {
				best = row
				break
			}
		}
	}
	if best == nil {
		return 0, "", ""
	}

	port = best.DestinationPort
	proto = normalizeProtocolString(best.Protocol)
	// Prefer the service name already resolved and stored in traffic_events
	// (set by resolveServiceName at ingest time, process-aware).
	service = best.ServiceName
	if service == "" && port > 0 {
		service = services.ServiceFromPort(int(port))
	}
	return port, service, proto
}

func (h *GrpcIngestHandler) ReportBlockedIP(ctx context.Context, req *pb.BlockedIPEvent) (*pb.BlockedIPResponse, error) {
	// Validate API key
	server, err := ValidateAPIKey(ctx, h.queries, req.ApiKey)
	if err != nil {
		log.Printf("[gRPC ReportBlockedIP] API key validation failed: %v", err)
		return nil, status.Errorf(codes.Unauthenticated, "Invalid API Key")
	}

	log.Printf("[gRPC ReportBlockedIP] Received block event from server_id=%s ip=%s action=%v duration=%ds reason=%s",
		server.ID.String(), req.IpAddress, req.Action, req.DurationSeconds, req.Reason)

	// Parse IP address
	ipAddr, err := netip.ParseAddr(req.IpAddress)
	if err != nil {
		log.Printf("[gRPC ReportBlockedIP] Invalid IP address: %v", err)
		return nil, status.Errorf(codes.InvalidArgument, "Invalid IP address")
	}

	// Determine if this is an auto-block
	isAutoBlocked := true
	if req.Action == pb.BlockAction_BLOCK_ACTION_ALLOW {
		isAutoBlocked = false
	}

	// Calculate expiry time.
	// Agent-reported XDP blocks are always classified as "malicious" (score 100),
	// so they are permanent blocks - do not use the agent's kernel-level duration
	// (which only reflects how long the XDP rule lives in the kernel, not how long
	// we want the IP to remain blocked in the database).
	var expiresAt pgtype.Timestamptz // Valid=false → permanent block

	// Get GeoIP info if available
	var country, countryCodeISO, city, region, isp string
	var latitude, longitude float64
	var asn int32
	var isVPN, isTor, isDatacenter bool
	if h.geoIP != nil {
		country, countryCodeISO, city, region, latitude, longitude, isp, _, _ = h.geoIP.LookupDetailed(req.IpAddress)
	}

	// Map IP version
	ipVersion := int32(4)
	if ipAddr.Is6() {
		ipVersion = 6
	}

	// Check if IP is already blocked - update instead of creating duplicate
	existingBlock, err := h.queries.GetActiveBlockByIP(ctx, database.GetActiveBlockByIPParams{
		UserID:    server.UserID,
		IpAddress: ipAddr,
	})
	if err == nil {
		// IP already blocked - extend expiry and update reason
		log.Printf("[gRPC ReportBlockedIP] IP %s already blocked (id=%s), extending expiry",
			req.IpAddress, existingBlock.ID.String())

		// Agent XDP blocks are permanent (malicious threat level) - preserve
		// permanent status. If the existing block was already permanent (Valid=false),
		// keep it that way.
		var newExpiresAt pgtype.Timestamptz // Valid=false → permanent block
		if existingBlock.ExpiresAt.Valid {
			// Existing block had an expiry (created before this fix) - upgrade to permanent
			newExpiresAt = pgtype.Timestamptz{Valid: false}
		}

		// Update existing block - permanent block so DurationSeconds=0
		err = h.queries.UpdateBlockExpiry(ctx, database.UpdateBlockExpiryParams{
			ID:              existingBlock.ID,
			ExpiresAt:       newExpiresAt,
			BlockedAt:       pgtype.Timestamptz{Time: time.Now(), Valid: true},
			DurationSeconds: 0,
			EnforcementType: "permanent",
		})
		if err != nil {
			log.Printf("[gRPC ReportBlockedIP] Failed to update block: %v", err)
		}

		// Backfill context (port / service / protocol) if the existing record has
		// NULL values - happens when the block was first created via startup sync.
		if !existingBlock.TargetPort.Valid || !existingBlock.ServiceName.Valid || !existingBlock.Protocol.Valid {
			bfPort, bfService, bfProto := enrichContextFromHistory(ctx, h.queries, ipAddr, server)
			if bfPort > 0 || bfService != "" || (bfProto != "" && bfProto != "UNKNOWN") {
				_ = h.queries.UpdateBlockContext(ctx, database.UpdateBlockContextParams{
					ID:          existingBlock.ID,
					TargetPort:  pgtype.Int4{Int32: bfPort, Valid: bfPort > 0},
					ServiceName: pgtype.Text{String: bfService, Valid: bfService != ""},
					Protocol:    pgtype.Text{String: bfProto, Valid: bfProto != "" && bfProto != "UNKNOWN"},
				})
				log.Printf("[gRPC ReportBlockedIP] Backfilled context for existing block %s: port=%d service=%s proto=%s",
					existingBlock.ID.String(), bfPort, bfService, bfProto)
			}
		}

		return &pb.BlockedIPResponse{Success: true}, nil
	}

	// Convert protocol enum to string
	protocolStr := "TCP"
	switch req.Protocol {
	case pb.Protocol_PROTOCOL_UDP:
		protocolStr = "UDP"
	case pb.Protocol_PROTOCOL_ICMP:
		protocolStr = "ICMP"
	case pb.Protocol_PROTOCOL_UNKNOWN:
		protocolStr = "UNKNOWN"
	}

	// Determine service name: use provided or derive from port
	serviceName := req.ServiceName
	if serviceName == "" && req.TargetPort > 0 {
		serviceName = getServiceFromPort(int(req.TargetPort))
	}

	targetPort := int32(req.TargetPort)

	// Enrich missing block context from latest traffic event for this source IP.
	if targetPort <= 0 || serviceName == "" || protocolStr == "UNKNOWN" {
		bfPort, bfService, bfProto := enrichContextFromHistory(ctx, h.queries, ipAddr, server)
		if bfPort > 0 && targetPort <= 0 {
			targetPort = bfPort
		}
		if bfService != "" && serviceName == "" {
			serviceName = bfService
		}
		if bfProto != "" && bfProto != "UNKNOWN" && protocolStr == "UNKNOWN" {
			protocolStr = bfProto
		}

		// Second fallback: reuse context from the most recent prior block record.
		if targetPort <= 0 || serviceName == "" {
			if prior, prErr := h.queries.GetLatestBlockByIP(ctx, database.GetLatestBlockByIPParams{
				UserID:    server.UserID,
				IpAddress: ipAddr,
			}); prErr == nil {
				if targetPort <= 0 && prior.TargetPort.Valid {
					targetPort = prior.TargetPort.Int32
				}
				if serviceName == "" && prior.ServiceName.Valid {
					serviceName = prior.ServiceName.String
				}
				if protocolStr == "UNKNOWN" && prior.Protocol.Valid {
					protocolStr = prior.Protocol.String
				}
			}
		}
	}

	// Create new block record in database
	block, err := h.queries.CreateBlock(ctx, database.CreateBlockParams{
		ServerID:        server.ID,
		UserID:          server.UserID,
		IpAddress:       ipAddr,
		IpVersion:       pgtype.Int4{Int32: ipVersion, Valid: true},
		ThreatScore:     100, // High score for auto-blocked
		ThreatLevel:     "malicious",
		Reasons:         []string{req.Reason},
		TargetPort:      pgtype.Int4{Int32: targetPort, Valid: targetPort > 0},
		ServiceName:     pgtype.Text{String: serviceName, Valid: serviceName != ""},
		Protocol:        pgtype.Text{String: protocolStr, Valid: protocolStr != "" && protocolStr != "UNKNOWN"},
		CountryCode:     pgtype.Text{String: countryCodeISO, Valid: countryCodeISO != ""},
		CountryName:     pgtype.Text{String: country, Valid: country != ""},
		City:            pgtype.Text{String: city, Valid: city != ""},
		Region:          pgtype.Text{String: region, Valid: region != ""},
		Latitude:        pgtype.Float8{Float64: latitude, Valid: latitude != 0},
		Longitude:       pgtype.Float8{Float64: longitude, Valid: longitude != 0},
		Asn:             pgtype.Int4{Int32: asn, Valid: asn > 0},
		AsnOrg:          pgtype.Text{String: isp, Valid: isp != ""},
		IsVpn:           pgtype.Bool{Bool: isVPN, Valid: true},
		IsTor:           pgtype.Bool{Bool: isTor, Valid: true},
		IsDatacenter:    pgtype.Bool{Bool: isDatacenter, Valid: true},
		BlockedAt:       pgtype.Timestamptz{Time: time.Now(), Valid: true},
		ExpiresAt:       expiresAt, // Valid=false → permanent block
		DurationSeconds: 0,         // permanent block - no duration
		IsAutoBlocked:   pgtype.Bool{Bool: isAutoBlocked, Valid: true},
		AgentVersion:    database.ToPgText(req.AgentVersion),
		RawMetrics:      nil,
		EnforcementType: "permanent",
	})

	if err != nil {
		log.Printf("[gRPC ReportBlockedIP] Failed to create block record: %v", err)
		return nil, status.Errorf(codes.Internal, "Failed to record blocked IP")
	}

	log.Printf("[gRPC ReportBlockedIP] Created block record id=%s for server_id=%s ip=%s",
		block.ID.String(), server.ID.String(), req.IpAddress)

	// Broadcast to connected clients
	h.hub.Broadcast(server.UserID.String(), "new_block", map[string]any{
		"id":              block.ID.String(),
		"block_id":        block.ID.String(),
		"server_id":       server.ID.String(),
		"server_name":     server.Hostname,
		"ip_address":      req.IpAddress,
		"reason":          req.Reason,
		"reasons":         []string{req.Reason},
		"threat_score":    int32(100),
		"threat_level":    "malicious",
		"country_code":    countryCodeISO,
		"country_name":    country,
		"city":            city,
		"blocked_at":      time.Now(),
		"duration":        req.DurationSeconds,
		"is_auto_blocked": isAutoBlocked,
	})

	return &pb.BlockedIPResponse{
		Success: true,
	}, nil
}

// ReportIntegrity handles periodic integrity attestation reports from agents.
// It validates agent-reported state against expected values and broadcasts
// integrity alerts to the dashboard via WebSocket.
func (h *GrpcIngestHandler) ReportIntegrity(ctx context.Context, req *pb.IntegrityReport) (*pb.IntegrityReportResponse, error) {
	// Authenticate the agent
	server, err := ValidateAPIKey(ctx, h.queries, req.ApiKey)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid API key")
	}

	if server.Status != "active" {
		return nil, status.Errorf(codes.PermissionDenied, "server not active")
	}

	log.Printf("[Integrity] Received report from %s (agent=%s): healthy=%v programs=%d maps=%d",
		server.Hostname, req.AgentVersion, req.Status.Healthy,
		len(req.Programs), len(req.Maps))

	// Broadcast integrity status to dashboard
	integrityData := map[string]interface{}{
		"server_id":          server.ID.String(),
		"server_name":        server.Hostname,
		"agent_version":      req.AgentVersion,
		"agent_binary_hash":  req.AgentBinaryHash,
		"healthy":            req.Status.Healthy,
		"warnings":           req.Status.Warnings,
		"errors":             req.Status.Errors,
		"program_count":      len(req.Programs),
		"map_count":          len(req.Maps),
		"timestamp":          time.Now(),
	}

	eventType := "integrity_report"

	// Escalate to alert if integrity check fails
	if !req.Status.Healthy {
		eventType = "integrity_alert"
		log.Printf("[Integrity] ALERT: agent %s reports unhealthy state — errors: %v",
			server.Hostname, req.Status.Errors)
	}

	h.hub.BroadcastToUser(database.FromPgUUID(server.UserID), eventType, integrityData)

	// Check for high-severity map issues
	for _, m := range req.Maps {
		if m.PinnedPathChanged || m.ConfigHashChanged || m.UnexpectedWriterDetected {
			log.Printf("[Integrity] Map integrity violation on %s: map=%s pinned_changed=%v hash_changed=%v unexpected_writer=%v",
				server.Hostname, m.Name, m.PinnedPathChanged, m.ConfigHashChanged, m.UnexpectedWriterDetected)
		}
	}

	// Check for program hash mismatches
	for _, p := range req.Programs {
		if !p.HashMatches && p.ExpectedHash != "" {
			log.Printf("[Integrity] Program hash mismatch on %s: %s (expected=%s actual=%s)",
				server.Hostname, p.Name, p.ExpectedHash, p.ActualHash)
		}
	}

	return &pb.IntegrityReportResponse{
		Success:      true,
		Message:      "integrity report acknowledged",
		Acknowledged: true,
	}, nil
}
