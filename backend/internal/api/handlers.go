package api

import (
	"fmt"
	"log"
	"math"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/kerneleye/backend/internal/database"
)

// HandleListServers returns all servers for a user
func HandleListServers(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := c.Locals("user_id")
		if userID == nil {
			log.Printf("[HandleListServers] Error: user_id is nil")
			return fiber.NewError(fiber.StatusUnauthorized, "User not authenticated")
		}

		servers, err := queries.ListServersByUser(c.Context(), database.ToPgUUID(userID.(string)))
		if err != nil {
			log.Printf("[HandleListServers] Error fetching servers for user %s: %v", userID, err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to fetch servers")
		}

		return c.JSON(servers)
	}
}

// HandleGetServer returns a specific server
func HandleGetServer(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		serverID := c.Params("id")
		userID := c.Locals("user_id")

		server, err := queries.GetServerByID(c.Context(), database.ToPgUUID(serverID))
		if err != nil {
			log.Printf("[HandleGetServer] Error fetching server %s: %v", serverID, err)
			return fiber.NewError(fiber.StatusNotFound, "Server not found")
		}

		if database.FromPgUUID(server.UserID) != userID.(string) {
			return fiber.NewError(fiber.StatusForbidden, "Access denied")
		}

		return c.JSON(server)
	}
}

// HandleServerTraffic returns traffic events for a specific server
func HandleServerTraffic(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		serverID := c.Params("id")
		userID := c.Locals("user_id")

		// Verify ownership
		server, err := queries.GetServerByID(c.Context(), database.ToPgUUID(serverID))
		if err != nil {
			return fiber.NewError(fiber.StatusNotFound, "Server not found")
		}
		if database.FromPgUUID(server.UserID) != userID.(string) {
			return fiber.NewError(fiber.StatusForbidden, "Access denied")
		}

		// Parse query parameters
		page := c.QueryInt("page", 1)
		pageSize := c.QueryInt("page_size", 50)
		if pageSize > 100 {
			pageSize = 100
		}
		if pageSize < 1 {
			pageSize = 1
		}
		offset := (page - 1) * pageSize

		// Optional filters
		search := c.Query("search")
		threatLevel := c.Query("threat_level")
		sortBy := c.Query("sort_by", "last_seen")

		// Date range filters
		var fromTime, toTime *time.Time
		if from := c.Query("from"); from != "" {
			if t, err := time.Parse(time.RFC3339, from); err == nil {
				fromTime = &t
			}
		}
		if to := c.Query("to"); to != "" {
			if t, err := time.Parse(time.RFC3339, to); err == nil {
				toTime = &t
			}
		}

		// Build query params
		params := database.ListTrafficEventsByServerParams{
			ServerID: database.ToPgUUID(serverID),
			Limit:    int32(pageSize),
			Offset:   int32(offset),
			Column8:  sortBy,
		}

		// Apply search filter
		if search != "" {
			params.Column2 = search
		}

		// Apply threat_level filter
		if threatLevel != "" {
			params.Column3 = threatLevel
		}

		// Apply date range
		if fromTime != nil {
			params.Column4 = pgtype.Timestamptz{Time: *fromTime, Valid: true}
		}
		if toTime != nil {
			params.Column5 = pgtype.Timestamptz{Time: *toTime, Valid: true}
		}

		// Get total count for pagination
		countParams := database.CountTrafficEventsByServerParams{
			ServerID: database.ToPgUUID(serverID),
		}
		if search != "" {
			countParams.Column2 = search
		}
		if threatLevel != "" {
			countParams.Column3 = threatLevel
		}
		if fromTime != nil {
			countParams.Column4 = pgtype.Timestamptz{Time: *fromTime, Valid: true}
		}
		if toTime != nil {
			countParams.Column5 = pgtype.Timestamptz{Time: *toTime, Valid: true}
		}

		totalCount, err := queries.CountTrafficEventsByServer(c.Context(), countParams)
		if err != nil {
			log.Printf("[HandleServerTraffic] Count error: %v", err)
			totalCount = 0
		}

		events, err := queries.ListTrafficEventsByServer(c.Context(), params)
		if err != nil {
			log.Printf("[HandleServerTraffic] Error: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to fetch traffic events")
		}

		// Return with pagination metadata
		totalPages := int(math.Ceil(float64(totalCount) / float64(pageSize)))
		return c.JSON(fiber.Map{
			"data": events,
			"pagination": fiber.Map{
				"page":        page,
				"page_size":   pageSize,
				"total_count": totalCount,
				"total_pages": totalPages,
			},
		})
	}
}

// HandleServerStats returns stats for a specific server
func HandleServerStats(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		serverID := c.Params("id")
		userID := c.Locals("user_id")

		// Verify ownership
		server, err := queries.GetServerByID(c.Context(), database.ToPgUUID(serverID))
		if err != nil {
			return fiber.NewError(fiber.StatusNotFound, "Server not found")
		}
		if database.FromPgUUID(server.UserID) != userID.(string) {
			return fiber.NewError(fiber.StatusForbidden, "Access denied")
		}

		stats, err := queries.GetServerStats(c.Context(), database.ToPgUUID(serverID))
		if err != nil {
			log.Printf("[HandleServerStats] Error: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to fetch server stats")
		}

		return c.JSON(stats)
	}
}

// HandleListThreats returns detected threats
func HandleListThreats(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := c.Locals("user_id")
		if userID == nil {
			log.Printf("[HandleListThreats] Error: user_id is nil")
			return fiber.NewError(fiber.StatusUnauthorized, "User not authenticated")
		}

		limit := c.QueryInt("limit", 100)
		if limit > 1000 {
			limit = 1000
		}

		threats, err := queries.ListThreats(c.Context(), database.ListThreatsParams{
			UserID: database.ToPgUUID(userID.(string)),
			Limit:  int32(limit),
		})
		if err != nil {
			log.Printf("[HandleListThreats] Error fetching threats for user %s: %v", userID, err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to fetch threats")
		}

		return c.JSON(threats)
	}
}

// HandleListAlerts returns alerts for a user
func HandleListAlerts(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := c.Locals("user_id")
		if userID == nil {
			return fiber.NewError(fiber.StatusUnauthorized, "User not authenticated")
		}

		limit := c.QueryInt("limit", 100)
		if limit > 1000 {
			limit = 1000
		}

		alerts, err := queries.ListAlerts(c.Context(), database.ListAlertsParams{
			UserID: database.ToPgUUID(userID.(string)),
			Limit:  int32(limit),
		})
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to fetch alerts")
		}

		return c.JSON(alerts)
	}
}

// HandleStatsOverview returns aggregated statistics
func HandleStatsOverview(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := c.Locals("user_id")
		if userID == nil {
			return fiber.NewError(fiber.StatusUnauthorized, "User not authenticated")
		}

		serverStats, err := queries.GetStatsServerCounts(c.Context(), database.ToPgUUID(userID.(string)))
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to fetch server stats")
		}

		eventStats, err := queries.GetStatsEventCounts(c.Context(), database.ToPgUUID(userID.(string)))
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to fetch event stats")
		}

		alertStats, err := queries.GetStatsAlertCounts(c.Context(), database.ToPgUUID(userID.(string)))
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to fetch alert stats")
		}

		return c.JSON(fiber.Map{
			"total_servers":   serverStats.TotalServers,
			"active_servers":  serverStats.ActiveServers,
			"total_events":    eventStats.TotalEvents,
			"unique_sources":  eventStats.UniqueSources,
			"total_alerts":    alertStats.TotalAlerts,
			"critical_alerts": alertStats.CriticalAlerts,
			"warning_alerts":  alertStats.WarningAlerts,
			"blocked_ips":     0,
		})
	}
}

// HandleGenerateAPIKey generates an API key for agent installation
// The server is NOT created here - it will be created when the agent registers
func HandleGenerateAPIKey(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		log.Printf("[API] GET /servers/generate-api-key - Starting API key generation")

		userID := c.Locals("user_id")
		if userID == nil {
			log.Printf("[API] GET /servers/generate-api-key - ERROR: user_id is nil")
			return fiber.NewError(fiber.StatusUnauthorized, "User not authenticated")
		}

		userIDStr := userID.(string)
		log.Printf("[API] GET /servers/generate-api-key - User: %s", userIDStr)

		// Get user's subscription details
		user, err := queries.GetUserByID(c.Context(), database.ToPgUUID(userIDStr))
		if err != nil {
			log.Printf("[API] GET /servers/generate-api-key - ERROR: Failed to get user %s: %v", userIDStr, err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to verify subscription")
		}
		log.Printf("[API] GET /servers/generate-api-key - User plan: %s, status: %s, max_servers: %d",
			user.Plan, user.SubscriptionStatus.String, user.MaxServers)

		// Check if user has an active subscription or trial
		isTrialing := user.TrialEndsAt.Valid && user.TrialEndsAt.Time.After(time.Now())
		hasActiveSub := user.SubscriptionStatus.String == "active" || isTrialing

		if !hasActiveSub {
			log.Printf("[API] GET /servers/generate-api-key - ERROR: User %s has no active subscription (status: %s, trialing: %v)",
				userIDStr, user.SubscriptionStatus.String, isTrialing)
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":         "No active subscription",
				"message":       "You need an active subscription or trial to add servers.",
				"code":          "NO_SUBSCRIPTION",
				"subscribe_url": "/subscription",
			})
		}

		// Count current servers
		serverCount, err := queries.CountServersByUser(c.Context(), database.ToPgUUID(userIDStr))
		if err != nil {
			log.Printf("[API] GET /servers/generate-api-key - ERROR: Failed to count servers for user %s: %v", userIDStr, err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to count servers")
		}
		log.Printf("[API] GET /servers/generate-api-key - Current servers: %d/%d", serverCount, user.MaxServers)

		// Check if user has reached their server limit
		if int32(serverCount) >= user.MaxServers {
			log.Printf("[API] GET /servers/generate-api-key - ERROR: User %s has reached server limit (%d/%d)", userIDStr, serverCount, user.MaxServers)
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":       "Server limit reached",
				"message":     fmt.Sprintf("Your %s plan allows up to %d servers. Please upgrade to add more.", user.Plan, user.MaxServers),
				"current":     serverCount,
				"limit":       user.MaxServers,
				"upgrade_url": "/subscription",
			})
		}

		// Generate a placeholder server ID for the API key
		// The actual server will be created when the agent registers
		placeholderServerID := uuid.New().String()

		// Generate unique API key
		apiKey := GenerateAPIKey(userIDStr, placeholderServerID)

		log.Printf("[API] GET /servers/generate-api-key - SUCCESS: Generated API key for user %s", userIDStr)

		return c.JSON(fiber.Map{
			"api_key": apiKey,
		})
	}
}

// HandleUpdateServerStatus allows user to accept/reject/pause servers
func HandleUpdateServerStatus(queries *database.Queries, hub *Hub) fiber.Handler {
	return func(c *fiber.Ctx) error {
		serverID := c.Params("id")
		userID := c.Locals("user_id")

		type UpdateStatusRequest struct {
			Status string `json:"status"`
		}

		var req UpdateStatusRequest
		if err := c.BodyParser(&req); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
		}

		if req.Status != "active" && req.Status != "rejected" && req.Status != "inactive" {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid status")
		}

		// Verify ownership
		server, err := queries.GetServerByID(c.Context(), database.ToPgUUID(serverID))
		if err != nil {
			return fiber.NewError(fiber.StatusNotFound, "Server not found")
		}

		if database.FromPgUUID(server.UserID) != userID.(string) {
			return fiber.NewError(fiber.StatusForbidden, "Access denied")
		}

		// Update status
		if err := queries.UpdateServerStatus(c.Context(), database.UpdateServerStatusParams{
			ID:     database.ToPgUUID(serverID),
			Status: req.Status,
		}); err != nil {
			log.Printf("Failed to update server status: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to update status")
		}

		// Notify dashboard via WebSocket
		hub.Broadcast(userID.(string), "server_updated", map[string]interface{}{
			"id":     serverID,
			"status": req.Status,
		})

		return c.JSON(fiber.Map{
			"success": true,
			"status":  req.Status,
		})
	}
}

// HandleDeleteServer removes a server and its associated data
func HandleDeleteServer(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		serverID := c.Params("id")
		userID := c.Locals("user_id")

		if userID == nil {
			return fiber.NewError(fiber.StatusUnauthorized, "User not authenticated")
		}

		// First verify the server belongs to this user
		_, err := queries.GetServerByID(c.Context(), database.ToPgUUID(serverID))
		if err != nil {
			log.Printf("[HandleDeleteServer] Server not found: %v", err)
			return fiber.NewError(fiber.StatusNotFound, "Server not found")
		}

		err = queries.DeleteServer(c.Context(), database.ToPgUUID(serverID))

		if err != nil {
			log.Printf("[HandleDeleteServer] Error: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to delete server")
		}

		return c.JSON(fiber.Map{
			"success": true,
			"message": "Server deleted successfully",
		})
	}
}
