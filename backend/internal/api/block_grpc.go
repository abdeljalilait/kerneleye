package api

import (
	"context"
	"log"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/kerneleye/backend/internal/database"
	"github.com/kerneleye/backend/internal/geoip"
	kerneleyev1 "github.com/kerneleye/proto/kerneleye/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// BlockHandler implements the BlockService gRPC interface
type BlockHandler struct {
	kerneleyev1.UnimplementedBlockServiceServer
	queries *database.Queries
	hub     *Hub
	geoIP   *geoip.Service
}

// NewBlockHandler creates a new block handler
func NewBlockHandler(queries *database.Queries, hub *Hub, geoIP *geoip.Service) *BlockHandler {
	return &BlockHandler{
		queries: queries,
		hub:     hub,
		geoIP:   geoIP,
	}
}

// ReportBlock handles block reports from agents
func (h *BlockHandler) ReportBlock(ctx context.Context, req *kerneleyev1.BlockReportRequest) (*kerneleyev1.BlockReportResponse, error) {
	// 1. Authenticate server
	server, err := h.queries.GetServerByAPIKey(ctx, database.ToPgText(req.ApiKey))
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid API key")
	}

	if server.Status != "active" {
		return nil, status.Errorf(codes.PermissionDenied, "server not active")
	}

	// 2. Parse IP
	ip, err := netip.ParseAddr(req.IpAddress)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid IP address: %v", err)
	}

	// 3. Lookup GeoIP if available
	var countryCode, countryName, city, region, asnOrg string
	var asn int32

	if h.geoIP != nil {
		countryName, city, asnOrg, _ = h.geoIP.Lookup(req.IpAddress)
	}

	// 4. Detect if datacenter/VPN/Tor (simplified)
	isDatacenter := h.isDatacenterIP(req.IpAddress)
	isVPN := false
	isTor := false

	// 5. Store block in database
	expiresAt := time.Now().Add(time.Duration(req.DurationSeconds) * time.Second)

	block, err := h.queries.CreateBlock(ctx, database.CreateBlockParams{
		ServerID:        server.ID,
		UserID:          server.UserID,
		IpAddress:       ip,
		IpVersion:       pgtype.Int4{Int32: req.IpVersion, Valid: true},
		ThreatScore:     req.ThreatScore,
		ThreatLevel:     req.ThreatLevel,
		Reasons:         req.Reasons,
		TargetPort:      pgtype.Int4{Int32: req.TargetPort, Valid: req.TargetPort > 0},
		ServiceName:     pgtype.Text{String: req.ServiceName, Valid: req.ServiceName != ""},
		Protocol:        pgtype.Text{String: req.Protocol, Valid: req.Protocol != ""},
		CountryCode:     pgtype.Text{String: countryCode, Valid: countryCode != ""},
		CountryName:     pgtype.Text{String: countryName, Valid: countryName != ""},
		City:            pgtype.Text{String: city, Valid: city != ""},
		Region:          pgtype.Text{String: region, Valid: region != ""},
		Asn:             pgtype.Int4{Int32: asn, Valid: asn > 0},
		AsnOrg:          pgtype.Text{String: asnOrg, Valid: asnOrg != ""},
		IsVpn:           pgtype.Bool{Bool: isVPN, Valid: true},
		IsTor:           pgtype.Bool{Bool: isTor, Valid: true},
		IsDatacenter:    pgtype.Bool{Bool: isDatacenter, Valid: true},
		BlockedAt:       database.ToPgTimestamptz(time.Now()),
		ExpiresAt:       database.ToPgTimestamptz(expiresAt),
		DurationSeconds: int32(req.DurationSeconds),
		IsAutoBlocked:   pgtype.Bool{Bool: true, Valid: true},
		AgentVersion:    pgtype.Text{String: req.AgentVersion, Valid: req.AgentVersion != ""},
	})

	if err != nil {
		log.Printf("[BlockHandler] Failed to create block: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to record block")
	}

	// 6. Broadcast to user's other agents (cross-server blocking)
	h.hub.BroadcastToUser(database.FromPgUUID(server.UserID), "new_block", map[string]interface{}{
		"block_id":  block.ID.String(),
		"ip":        req.IpAddress,
		"duration":  req.DurationSeconds,
		"reason":    req.Reasons,
		"server_id": server.ID.String(),
		"service":   req.ServiceName,
		"score":     req.ThreatScore,
	})

	// 7. Send WebSocket update to dashboard
	h.hub.BroadcastToUser(database.FromPgUUID(server.UserID), "new_block", map[string]interface{}{
		"id":            block.ID.String(),
		"ip_address":    req.IpAddress,
		"server_id":     server.ID.String(),
		"server_name":   server.Hostname,
		"threat_score":  req.ThreatScore,
		"threat_level":  req.ThreatLevel,
		"reasons":       req.Reasons,
		"service_name":  req.ServiceName,
		"target_port":   req.TargetPort,
		"country_code":  countryCode,
		"country_name":  countryName,
		"city":          city,
		"blocked_at":    time.Now(),
		"expires_at":    expiresAt,
		"is_datacenter": isDatacenter,
	})

	log.Printf("[BlockHandler] Block recorded: %s (score: %d, service: %s, country: %s)",
		req.IpAddress, req.ThreatScore, req.ServiceName, countryCode)

	return &kerneleyev1.BlockReportResponse{
		Success: true,
		BlockId: block.ID.String(),
		Message: "Block recorded successfully",
	}, nil
}

// GetBlockStatus checks if an IP should be blocked (for agent sync)
func (h *BlockHandler) GetBlockStatus(ctx context.Context, req *kerneleyev1.BlockStatusRequest) (*kerneleyev1.BlockStatusResponse, error) {
	// Authenticate
	server, err := h.queries.GetServerByAPIKey(ctx, database.ToPgText(req.ApiKey))
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid API key")
	}

	// Check if this IP is blocked for this user
	ip := netip.MustParseAddr(req.IpAddress)
	blocked, err := h.queries.IsIPBlocked(ctx, database.IsIPBlockedParams{
		UserID:    server.UserID,
		IpAddress: ip,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "database error")
	}

	if !blocked {
		return &kerneleyev1.BlockStatusResponse{ShouldBlock: false}, nil
	}

	// Get remaining time
	remaining, err := h.queries.GetBlockRemainingTime(ctx, database.GetBlockRemainingTimeParams{
		UserID:    server.UserID,
		IpAddress: ip,
	})
	if err != nil {
		return &kerneleyev1.BlockStatusResponse{ShouldBlock: true}, nil
	}

	return &kerneleyev1.BlockStatusResponse{
		ShouldBlock:      true,
		Reason:           "Blocked by user policy",
		RemainingSeconds: remaining,
	}, nil
}

// StreamBlockCommands streams block/unblock commands to agents
func (h *BlockHandler) StreamBlockCommands(req *kerneleyev1.StreamBlockRequest, stream kerneleyev1.BlockService_StreamBlockCommandsServer) error {
	// Authenticate
	server, err := h.queries.GetServerByAPIKey(stream.Context(), database.ToPgText(req.ApiKey))
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "invalid API key")
	}

	// Create a channel for this agent
	cmdChan := make(chan map[string]interface{}, 10)
	clientID := req.ClientToken
	if clientID == "" {
		clientID = server.ID.String()
	}

	h.hub.RegisterAgent(clientID, cmdChan)
	defer h.hub.UnregisterAgent(clientID)

	log.Printf("[BlockHandler] Agent %s connected for block commands", clientID)

	// Stream commands to agent
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case cmd := <-cmdChan:
			action := kerneleyev1.BlockCommand_BLOCK
			if cmd["action"] == "unblock" {
				action = kerneleyev1.BlockCommand_UNBLOCK
			}

			duration := int64(0)
			if d, ok := cmd["duration"].(int64); ok {
				duration = d
			}

			pbCmd := &kerneleyev1.BlockCommand{
				Action:          action,
				IpAddress:       cmd["ip"].(string),
				DurationSeconds: duration,
				Reason:          cmd["reason"].(string),
				BlockId:         cmd["block_id"].(string),
			}
			if err := stream.Send(pbCmd); err != nil {
				log.Printf("[BlockHandler] Failed to send command: %v", err)
				return err
			}
		}
	}
}

// isDatacenterIP checks if IP is from known cloud provider
func (h *BlockHandler) isDatacenterIP(ip string) bool {
	// Simplified check - in production, use IP intelligence service
	datacenterASNs := []int{
		15169,  // Google
		16509,  // Amazon AWS
		8075,   // Microsoft
		396982, // Google Cloud
	}
	_ = datacenterASNs
	return false
}
