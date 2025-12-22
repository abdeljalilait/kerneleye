package api

import (
	"context"
	"log"
	"net/netip"

	"github.com/google/uuid"
	"github.com/kerneleye/backend/internal/database"
	"github.com/kerneleye/backend/internal/geoip"
	"github.com/kerneleye/backend/internal/scoring"
	pb "github.com/kerneleye/proto/kerneleye/v1"
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
	// First check if server exists and is active
	server, err := h.queries.GetServerByAPIKey(ctx, database.ToPgText(req.ApiKey))
	if err != nil {
		// Server not found - likely deleted
		log.Printf("[gRPC Heartbeat] Server not found for API key (possibly deleted)")
		return &pb.HeartbeatResponse{
			Success: false,
			Message: "deleted",
		}, nil
	}

	// Check if server is rejected or inactive
	if server.Status == "rejected" || server.Status == "deleted" {
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

	return &pb.HeartbeatResponse{
		Success: true,
		Message: "Heartbeat received",
	}, nil
}

func (h *GrpcIngestHandler) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	log.Printf("[gRPC Register] Received registration request for hostname: %s, IP: %s", req.Hostname, req.IpAddress)

	// The UserId field now contains the pre-generated API key
	apiKey := req.UserId

	// Decode the API key to get the real user ID
	userID, _, err := DecodeAPIKey(apiKey)
	if err != nil {
		log.Printf("[gRPC Register] Invalid API key: %v", err)
		return nil, status.Errorf(codes.InvalidArgument, "Invalid API key")
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
			// Server with same IP exists - update it (re-enrollment)
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

	// No existing server - create new one in pending state
	_, err = h.queries.CreateServerWithAPIKey(ctx, database.CreateServerWithAPIKeyParams{
		UserID:      database.ToPgUUID(userID),
		Hostname:    req.Hostname,
		ApiKey:      database.ToPgText(apiKey),
		ClientToken: database.ToPgText(clientToken),
		IpAddress:   ipAddr,
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
		apiKey = server.ApiKey.String
	}

	return &pb.GetStatusResponse{
		Status: server.Status,
		ApiKey: apiKey,
	}, nil
}

func (h *GrpcIngestHandler) SubmitTraffic(ctx context.Context, req *pb.TrafficBatch) (*pb.TrafficResponse, error) {
	// 1. Authenticate server
	server, err := h.queries.GetServerByAPIKey(ctx, database.ToPgText(req.ApiKey))
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Invalid API Key")
	}

	if server.Status != "active" {
		return nil, status.Errorf(codes.PermissionDenied, "Server not active")
	}

	// Update last_seen
	_ = h.queries.UpdateServerHeartbeat(ctx, database.UpdateServerHeartbeatParams{
		ApiKey:       server.ApiKey,
		AgentVersion: server.AgentVersion,
	})

	eventsProcessed := uint64(0)
	for _, event := range req.Events {
		metrics := scoring.IPMetrics{
			SYNCount:         int(event.SynCount),
			ACKCount:         int(event.AckCount),
			FailedHandshakes: int(event.FailedHandshakes),
			UniquePorts:      int(event.UniquePortsCount),
			TotalConnections: int(event.SynCount + event.AckCount),
			BytesIn:          event.BytesIn,
			BytesOut:         event.BytesOut,
			WindowStart:      event.FirstSeen.AsTime(),
			WindowEnd:        event.LastSeen.AsTime(),
		}

		score := h.scorer.CalculateScore(metrics)

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

		var country, city, isp string
		if h.geoIP != nil {
			country, city, isp, _ = h.geoIP.Lookup(event.SourceIp)
		}

		// Convert protobuf direction to string
		direction := "inbound"
		if event.Direction == pb.Direction_DIRECTION_OUTBOUND {
			direction = "outbound"
		}

		_, err = h.queries.UpsertTrafficEvent(ctx, database.UpsertTrafficEventParams{
			ServerID:         server.ID,
			SourceIp:         sourceIP,
			DestinationIp:    destIP,
			DestinationPort:  int32(event.DestinationPort),
			Protocol:         getServiceFromPort(int(event.DestinationPort)), // Derive service name from port
			Direction:        direction,
			SynCount:         int32(event.SynCount),
			AckCount:         int32(event.AckCount),
			FailedHandshakes: int32(event.FailedHandshakes),
			UniquePorts:      int32(event.UniquePortsCount),
			BytesIn:          int64(event.BytesIn),
			BytesOut:         int64(event.BytesOut),
			ThreatScore:      int32(score.Score),
			ThreatLevel:      string(score.Level),
			FirstSeen:        database.ToPgTimestamptz(event.FirstSeen.AsTime()),
			LastSeen:         database.ToPgTimestamptz(event.LastSeen.AsTime()),
			Country:          database.ToPgText(country),
			City:             database.ToPgText(city),
			Isp:              database.ToPgText(isp),
		})

		if err == nil {
			eventsProcessed++
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
				"protocol":         getServiceFromPort(int(event.DestinationPort)),
				"direction":        direction,
				"syn_count":        event.SynCount,
				"bytes_in":         event.BytesIn,
				"bytes_out":        event.BytesOut,
			})
		} else {
			log.Printf("Failed to create traffic event: %v", err)
		}

		// Alerts logic could go here similar to HTTP handler
	}

	return &pb.TrafficResponse{
		Success:         true,
		Message:         "Traffic data processed",
		EventsProcessed: eventsProcessed,
	}, nil
}

// getServiceFromPort returns a service name string based on port number
func getServiceFromPort(port int) string {
	switch port {
	case 22:
		return "SSH"
	case 80:
		return "HTTP"
	case 443:
		return "HTTPS"
	case 53:
		return "DNS"
	case 3306:
		return "MySQL"
	case 5432:
		return "PostgreSQL"
	case 6379:
		return "Redis"
	case 8080, 8000, 3000:
		return "HTTP-Alt"
	case 21:
		return "FTP"
	case 25, 587:
		return "SMTP"
	case 110:
		return "POP3"
	case 143:
		return "IMAP"
	case 27017:
		return "MongoDB"
	default:
		return "TCP"
	}
}
