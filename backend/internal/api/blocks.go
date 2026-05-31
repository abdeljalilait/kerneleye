package api

import (
	"context"
	"log"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/kerneleye/backend/internal/database"
)

// BlockListResponse for paginated block list
type BlockListResponse struct {
	Items    []BlockView `json:"items"`
	Total    int64       `json:"total"`
	Page     int         `json:"page"`
	PageSize int         `json:"page_size"`
}

// BlockView represents a block record for the dashboard
type BlockView struct {
	ID              string     `json:"id"`
	IPAddress       string     `json:"ip_address"`
	IPVersion       int32      `json:"ip_version"`
	ServerID        string     `json:"server_id"`
	ServerName      string     `json:"server_name"`
	ThreatScore     int32      `json:"threat_score"`
	ThreatLevel     string     `json:"threat_level"`
	Reasons         []string   `json:"reasons"`
	TargetPort      int32      `json:"target_port"`
	ServiceName     string     `json:"service_name"`
	Protocol        string     `json:"protocol"`
	CountryCode     string     `json:"country_code"`
	CountryName     string     `json:"country_name"`
	City            string     `json:"city"`
	Region          string     `json:"region"`
	ASN             int32      `json:"asn"`
	ASNOrg          string     `json:"asn_org"`
	IsVPN           bool       `json:"is_vpn"`
	IsTor           bool       `json:"is_tor"`
	IsDatacenter    bool       `json:"is_datacenter"`
	BlockedAt       time.Time  `json:"blocked_at"`
	ExpiresAt       time.Time  `json:"expires_at"`
	DurationSeconds int32      `json:"duration_seconds"`
	IsActive        bool       `json:"is_active"`
	IsAutoBlocked   bool       `json:"is_auto_blocked"`
	UnblockedAt     *time.Time `json:"unblocked_at,omitempty"`
}

// BlockStatsResponse for dashboard statistics
type BlockStatsResponse struct {
	TotalActive   int64            `json:"total_active"`
	TotalToday    int64            `json:"total_today"`
	ByService     map[string]int64 `json:"by_service"`
	ByCountry     map[string]int64 `json:"by_country"`
	ByServer      map[string]int64 `json:"by_server"`
	ByThreatLevel map[string]int64 `json:"by_threat_level"`
}

// HandleListBlocks returns paginated block list with filters
func HandleListBlocks(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := c.Locals("user_id").(string)
		userUUID := database.ToPgUUID(userID)

		// Parse query parameters
		page, _ := strconv.Atoi(c.Query("page", "1"))
		pageSize, _ := strconv.Atoi(c.Query("page_size", "20"))
		if pageSize > 100 {
			pageSize = 100
		}

		serverFilter := c.Query("server", "all")
		serviceFilter := c.Query("service", "all")
		countryFilter := c.Query("country", "all")
		statusFilter := c.Query("status", "active")

		offset := (page - 1) * pageSize

		// Build query parameters
		params := database.ListBlocksParams{
			UserID: userUUID,
			Limit:  int32(pageSize),
			Offset: int32(offset),
		}

		// Apply filters
		if serverFilter != "all" {
			if serverID, err := uuid.Parse(serverFilter); err == nil {
				params.ServerID = database.ToPgUUID(serverID.String())
			}
		}

		if serviceFilter != "all" {
			params.ServiceName = pgtype.Text{String: serviceFilter, Valid: true}
		}

		if countryFilter != "all" {
			params.CountryCode = pgtype.Text{String: countryFilter, Valid: true}
		}

		switch statusFilter {
		case "active":
			params.IsActive = pgtype.Bool{Bool: true, Valid: true}
		case "expired":
			params.IsActive = pgtype.Bool{Bool: false, Valid: true}
		}

		// Search filter not implemented in current SQL schema

		// Fetch blocks from database
		rows, err := queries.ListBlocks(c.Context(), params)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "failed to fetch blocks")
		}

		// Get total count for pagination
		total, err := queries.CountBlocks(c.Context(), userUUID)
		if err != nil {
			total = 0
		}

		// Convert to view model
		items := make([]BlockView, 0, len(rows))
		for _, row := range rows {
			items = append(items, BlockView{
				ID:              row.ID.String(),
				IPAddress:       row.IpAddress.String(),
				IPVersion:       row.IpVersion.Int32,
				ServerID:        row.ServerID.String(),
				ServerName:      row.ServerName,
				ThreatScore:     row.ThreatScore,
				ThreatLevel:     row.ThreatLevel,
				Reasons:         row.Reasons,
				TargetPort:      row.TargetPort.Int32,
				ServiceName:     row.ServiceName.String,
				Protocol:        row.Protocol.String,
				CountryCode:     row.CountryCode.String,
				CountryName:     row.CountryName.String,
				City:            row.City.String,
				Region:          row.Region.String,
				ASN:             row.Asn.Int32,
				ASNOrg:          row.AsnOrg.String,
				IsVPN:           row.IsVpn.Bool,
				IsTor:           row.IsTor.Bool,
				IsDatacenter:    row.IsDatacenter.Bool,
				BlockedAt:       row.BlockedAt.Time,
				ExpiresAt:       row.ExpiresAt.Time,
				DurationSeconds: row.DurationSeconds,
				IsActive:        row.IsActive.Bool,
				IsAutoBlocked:   row.IsAutoBlocked.Bool,
				UnblockedAt:     timePtr(row.UnblockedAt),
			})
		}

		return c.JSON(BlockListResponse{
			Items:    items,
			Total:    total,
			Page:     page,
			PageSize: pageSize,
		})
	}
}

// HandleGetBlockStats returns statistics for dashboard
func HandleGetBlockStats(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := c.Locals("user_id").(string)
		userUUID := database.ToPgUUID(userID)

		// Get active blocks count
		activeCount, err := queries.CountActiveBlocks(c.Context(), userUUID)
		if err != nil {
			activeCount = 0
		}

		// Get today's blocks
		todayCount, err := queries.CountBlocksToday(c.Context(), userUUID)
		if err != nil {
			todayCount = 0
		}

		// Get breakdown by service
		serviceStats, err := queries.GetBlockStatsByService(c.Context(), userUUID)
		if err != nil {
			serviceStats = []database.GetBlockStatsByServiceRow{}
		}

		// Get breakdown by country
		countryStats, err := queries.GetBlockStatsByCountry(c.Context(), userUUID)
		if err != nil {
			countryStats = []database.GetBlockStatsByCountryRow{}
		}

		// Get breakdown by server
		serverStats, err := queries.GetBlockStatsByServer(c.Context(), userUUID)
		if err != nil {
			serverStats = []database.GetBlockStatsByServerRow{}
		}

		// Get breakdown by threat level
		levelStats, err := queries.GetBlockStatsByThreatLevel(c.Context(), userUUID)
		if err != nil {
			levelStats = []database.GetBlockStatsByThreatLevelRow{}
		}

		// Convert to maps
		byService := make(map[string]int64)
		for _, s := range serviceStats {
			byService[s.ServiceName] = s.Count
		}

		byCountry := make(map[string]int64)
		for _, s := range countryStats {
			byCountry[s.CountryCode] = s.Count
		}

		byServer := make(map[string]int64)
		for _, s := range serverStats {
			byServer[s.ServerName] = s.Count
		}

		byLevel := make(map[string]int64)
		for _, s := range levelStats {
			byLevel[s.ThreatLevel] = s.Count
		}

		return c.JSON(BlockStatsResponse{
			TotalActive:   activeCount,
			TotalToday:    todayCount,
			ByService:     byService,
			ByCountry:     byCountry,
			ByServer:      byServer,
			ByThreatLevel: byLevel,
		})
	}
}

// BlockManager interface for unblock operations
type BlockManager interface {
	Unblock(ctx context.Context, ip string, reason string) error
}

// HandleUnblockIP handles manual unblocking
func HandleUnblockIP(queries *database.Queries, hub *Hub, blockManager BlockManager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := c.Locals("user_id").(string)
		userUUID := database.ToPgUUID(userID)
		ip := c.Params("ip")

		var req struct {
			Reason string `json:"reason"`
		}
		c.BodyParser(&req)

		// Find the block
		block, err := queries.GetActiveBlockByIP(c.Context(), database.GetActiveBlockByIPParams{
			UserID:    userUUID,
			IpAddress: database.ToInet(ip),
		})
		if err != nil {
			return fiber.NewError(fiber.StatusNotFound, "active block not found")
		}

		// Mark as unblocked in database
		err = queries.UnblockIP(c.Context(), database.UnblockIPParams{
			ID:            block.ID,
			UnblockedAt:   database.ToPgTimestamptz(time.Now()),
			UnblockedBy:   userUUID,
			UnblockReason: pgtype.Text{String: req.Reason, Valid: req.Reason != ""},
		})
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "failed to unblock")
		}

		// Reset threat score for this IP to prevent immediate re-blocking
		// Keeps traffic history for future scoring calculations
		// (The IP can still be re-blocked if new malicious traffic arrives)
		err = queries.ResetTrafficScoreForIP(c.Context(), database.ResetTrafficScoreForIPParams{
			ServerID: block.ServerID,
			SourceIp: block.IpAddress,
		})
		if err != nil {
			log.Printf("[Unblock] Warning: failed to reset traffic score for %s: %v", ip, err)
			// Don't fail the unblock if this errors
		}

		// Update BlockManager's activeBlocks to prevent re-block until restart.
		// BlockManager.Unblock sends a signed command to the agent via the Hub.
		if blockManager != nil {
			if err := blockManager.Unblock(c.Context(), ip, req.Reason); err != nil {
				log.Printf("[Unblock] Warning: failed to update block manager: %v", err)
			}
		}

		// Also send to dashboard via WebSocket for UI update
		hub.BroadcastToUser(userID, "unblock_ip", map[string]interface{}{
			"ip":     ip,
			"reason": req.Reason,
		})

		return c.JSON(fiber.Map{
			"success": true,
			"message": "IP unblocked successfully",
			"ip":      ip,
		})
	}
}

// Helper functions
func timePtr(t pgtype.Timestamptz) *time.Time {
	if t.Valid {
		return &t.Time
	}
	return nil
}
