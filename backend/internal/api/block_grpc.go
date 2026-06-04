package api

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/kerneleye/backend/internal/database"
	"github.com/kerneleye/backend/internal/geoip"
	kerneleyev1 "github.com/kerneleye/proto/kerneleye/v1"
	"github.com/kerneleye/shared/cmdsigning"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
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
	server, err := ValidateAPIKey(ctx, h.queries, req.ApiKey)
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
	var latitude, longitude float64
	var asn int32

	if h.geoIP != nil {
		countryName, countryCode, city, region, latitude, longitude, asnOrg, _, _ = h.geoIP.LookupDetailed(req.IpAddress)
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
		Latitude:        pgtype.Float8{Float64: latitude, Valid: latitude != 0},
		Longitude:       pgtype.Float8{Float64: longitude, Valid: longitude != 0},
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

	// 6. Broadcast new block to WebSocket dashboard clients and cross-server agents
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
	server, err := ValidateAPIKey(ctx, h.queries, req.ApiKey)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid API key")
	}

	// Check if this IP is blocked for this user
	ip, err := netip.ParseAddr(req.IpAddress)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid IP address: %s", req.IpAddress)
	}
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
	server, err := ValidateAPIKey(stream.Context(), h.queries, req.ApiKey)
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

	// Push current whitelist snapshot so agents can enforce local bypass without
	// REST polling. We send UNBLOCK for both blocklist and ratelimit types.
	if whitelisted, err := h.queries.GetWhitelistedIPs(stream.Context(), server.UserID); err != nil {
		log.Printf("[BlockHandler] Failed to load whitelist for agent %s: %v", clientID, err)
	} else {
		signingKey := cmdsigning.Key()
		for _, ip := range whitelisted {
			for _, bt := range []kerneleyev1.BlockListEntry_BlockType{
				kerneleyev1.BlockListEntry_BLOCK_TYPE_BLOCKLIST,
				kerneleyev1.BlockListEntry_BLOCK_TYPE_RATE_LIMIT,
			} {
				nonce := time.Now().UnixNano()
				issuedAt := time.Now()
				payload := cmdsigning.BuildCanonicalPayload(
					int32(kerneleyev1.BlockCommand_UNBLOCK),
					ip.String(), 0, "whitelisted", "", int32(bt), issuedAt.UnixNano(),
				)
				var signature []byte
				if signingKey != "" {
					signature = cmdsigning.Sign(signingKey, nonce, payload)
				}
				if err := stream.Send(&kerneleyev1.BlockCommand{
					Action:    kerneleyev1.BlockCommand_UNBLOCK,
					IpAddress: ip.String(),
					Reason:    "whitelisted",
					BlockType: bt,
					IssuedAt:  timestamppb.New(issuedAt),
					Signature: signature,
					Nonce:     nonce,
				}); err != nil {
					log.Printf("[BlockHandler] Failed to send whitelist snapshot command: %v", err)
					return err
				}
			}
		}
		if len(whitelisted) > 0 {
			log.Printf("[BlockHandler] Sent whitelist snapshot (%d IPs) to agent %s", len(whitelisted), clientID)
		}
	}

	// Stream commands to agent
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case cmd := <-cmdChan:
			action := kerneleyev1.BlockCommand_BLOCK
			if cmd["action"] == "unblock" {
				action = kerneleyev1.BlockCommand_UNBLOCK
			} else if cmd["action"] == "ratelimit" {
				action = kerneleyev1.BlockCommand_RATE_LIMIT
			}

			// Read block_type from the command map (set by block_manager based on EnforcementDecision).
			// This is authoritative — do not infer from reason strings.
			blockType := kerneleyev1.BlockListEntry_BLOCK_TYPE_BLOCKLIST
			if bt, ok := cmd["block_type"].(string); ok {
				switch bt {
				case "ratelimit":
					blockType = kerneleyev1.BlockListEntry_BLOCK_TYPE_RATE_LIMIT
					if action == kerneleyev1.BlockCommand_BLOCK {
						action = kerneleyev1.BlockCommand_RATE_LIMIT
					}
				case "cidr":
					blockType = kerneleyev1.BlockListEntry_BLOCK_TYPE_CIDR
				}
			}

			duration := int64(0)
			if d, ok := cmd["duration"].(int64); ok {
				duration = d
			}

			ip, ok := cmd["ip"].(string)
			if !ok || ip == "" {
				log.Printf("[BlockHandler] Skipping command with missing or invalid 'ip' field")
				continue
			}
			reason, _ := cmd["reason"].(string)
			blockID, _ := cmd["block_id"].(string)

			// Propagate command signature and nonce for agent-side verification
			var signature []byte
			var nonce int64
			if sig, ok := cmd["signature"].([]byte); ok {
				signature = sig
			}
			if nStr, ok := cmd["nonce"].(string); ok {
				if n, err := strconv.ParseInt(nStr, 10, 64); err == nil {
					nonce = n
				}
			}

			// Use the signed issued_at timestamp so the agent can verify the
			// signature against the same bytes that were signed. Fall back to
			// timestamppb.Now() for unsigned commands or missing field.
			issuedAt := timestamppb.Now()
			if issuedStr, ok := cmd["issued_at_unix_nano"].(string); ok {
				if issuedNano, err := strconv.ParseInt(issuedStr, 10, 64); err == nil {
					issuedAt = timestamppb.New(time.Unix(0, issuedNano))
				}
			}

			pbCmd := &kerneleyev1.BlockCommand{
				Action:          action,
				IpAddress:       ip,
				DurationSeconds: duration,
				Reason:          reason,
				BlockId:         blockID,
				BlockType:       blockType,
				IssuedAt:        issuedAt,
				Signature:       signature,
				Nonce:           nonce,
			}
			if err := stream.Send(pbCmd); err != nil {
				log.Printf("[BlockHandler] Failed to send command: %v", err)
				return err
			}
		}
	}
}

// isDatacenterIP uses ISP/ASN org metadata as a lightweight signal for cloud/DC IPs.
func (h *BlockHandler) isDatacenterIP(ip string) bool {
	if h.geoIP == nil {
		return false
	}

	_, _, _, isp, _, err := h.geoIP.Lookup(ip)
	if err != nil || isp == "" {
		return false
	}

	ispLower := strings.ToLower(isp)
	indicators := []string{
		"amazon",
		"aws",
		"google",
		"gcp",
		"microsoft",
		"azure",
		"digitalocean",
		"linode",
		"ovh",
		"hetzner",
		"vultr",
		"cloudflare",
	}
	for _, indicator := range indicators {
		if strings.Contains(ispLower, indicator) {
			return true
		}
	}

	return false
}

// GetBlockList returns current active blocks for a server for state reconciliation
func (h *BlockHandler) GetBlockList(ctx context.Context, req *kerneleyev1.GetBlockListRequest) (*kerneleyev1.GetBlockListResponse, error) {
	// 1. Authenticate server
	server, err := ValidateAPIKey(ctx, h.queries, req.ApiKey)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid API key")
	}

	if server.Status != "active" {
		return nil, status.Errorf(codes.PermissionDenied, "server not active")
	}

	// 2. Get active blocks for this server
	blocks, err := h.queries.GetActiveBlocksForServer(ctx, server.ID)
	if err != nil {
		log.Printf("[GetBlockList] Failed to get blocks for server %s: %v", server.ID, err)
		return &kerneleyev1.GetBlockListResponse{
			Blocks:          nil,
			ServerTimestamp: time.Now().Unix(),
		}, nil
	}

	// 3. Convert to proto
	result := make([]*kerneleyev1.BlockListEntry, 0, len(blocks))
	for _, block := range blocks {
		expiresAt := int64(0)
		if block.ExpiresAt.Valid {
			expiresAt = block.ExpiresAt.Time.Unix()
		}

		// Determine block type from enforcement_type DB column (authoritative)
		blockType := kerneleyev1.BlockListEntry_BLOCK_TYPE_BLOCKLIST
		switch block.EnforcementType {
		case "ratelimit":
			blockType = kerneleyev1.BlockListEntry_BLOCK_TYPE_RATE_LIMIT
		case "permanent", "block":
			blockType = kerneleyev1.BlockListEntry_BLOCK_TYPE_BLOCKLIST
		}

		result = append(result, &kerneleyev1.BlockListEntry{
			IpAddress:       block.IpAddress.String(),
			IpVersion:       int32(block.IpVersion.Int32),
			DurationSeconds: int64(block.DurationSeconds),
			Reason:          strings.Join(block.Reasons, ", "),
			BlockId:         block.ID.String(),
			ExpiresAt:       expiresAt,
			BlockType:       blockType,
		})
	}

	log.Printf("[GetBlockList] Returning %d active blocks for server %s", len(result), server.Hostname)

	// Sign the response blob for integrity verification by agent
	var sig []byte
	var nonce int64
	key := cmdsigning.Key()
	if key != "" {
		nonce = time.Now().UnixNano()
		entries := make([]cmdsigning.BlockListEntry, 0, len(result))
		for _, b := range result {
			entries = append(entries, cmdsigning.BlockListEntry{
				IPAddress:       b.IpAddress,
				DurationSeconds: b.DurationSeconds,
				Reason:          b.Reason,
				BlockType:       int32(b.BlockType),
				ExpiresAt:       b.ExpiresAt,
			})
		}
		payload := cmdsigning.BuildBlockListPayload(entries)
		sig = cmdsigning.Sign(key, nonce, payload)
	} else {
		log.Printf("[GetBlockList] CMD_SIGNING_KEY not set — block list response is unsigned")
	}

	return &kerneleyev1.GetBlockListResponse{
		Blocks:          result,
		ServerTimestamp: time.Now().Unix(),
		Signature:       sig,
		Nonce:           nonce,
	}, nil
}

// signHubCommand signs a command map with HMAC-SHA256 and sends it to an agent
// via the Hub. When CMD_SIGNING_KEY is not set, the command is sent unsigned
// (the agent will reject it if hardened — dev environments only).
func signHubCommand(hub *Hub, agentID, action, ip, reason, blockType string, duration int64) {
	cmd := map[string]interface{}{
		"action":     action,
		"ip":         ip,
		"reason":     reason,
		"block_type": blockType,
	}
	if duration > 0 {
		cmd["duration"] = duration
	}

	key := cmdsigning.Key()
	if key == "" {
		log.Printf("[signHubCommand] CMD_SIGNING_KEY not set — sending unsigned command to %s (agent will reject if hardened)", agentID)
	} else {
		nonce := time.Now().UnixNano()
		issuedAt := time.Now()

		var actionCode int32
		switch action {
		case "block":
			actionCode = 0
		case "unblock":
			actionCode = 1
		case "ratelimit":
			actionCode = 2
		}

		var blockTypeCode int32
		switch blockType {
		case "ratelimit":
			blockTypeCode = 1
		case "cidr":
			blockTypeCode = 2
		default:
			blockTypeCode = 0
		}

		payload := cmdsigning.BuildCanonicalPayload(actionCode, ip, duration, reason, "", blockTypeCode, issuedAt.UnixNano())
		sig := cmdsigning.Sign(key, nonce, payload)

		cmd["signature"] = sig
		cmd["nonce"] = fmt.Sprintf("%d", nonce)
		cmd["issued_at_unix_nano"] = fmt.Sprintf("%d", issuedAt.UnixNano())
	}

	hub.SendCommandToAgent(agentID, cmd)
}
