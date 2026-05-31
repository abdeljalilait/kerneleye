package api

import (
	"log"
	"net/netip"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/kerneleye/backend/internal/database"
)

type WhitelistRequest struct {
	IPAddress string `json:"ip_address"`
	Reason    string `json:"reason"`
}

type WhitelistResponse struct {
	ID        string `json:"id"`
	IPAddress string `json:"ip_address"`
	IPVersion int    `json:"ip_version"`
	Reason    string `json:"reason"`
	IsManual  bool   `json:"is_manual"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

func HandleAddToWhitelist(queries *database.Queries, hub *Hub) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userIDVal := c.Locals("user_id")
		if userIDVal == nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
		}
		userIDStr := userIDVal.(string)
		userID := database.ToPgUUID(userIDStr)

		var req WhitelistRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
		}

		if req.IPAddress == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "ip_address is required"})
		}

		ip, err := netip.ParseAddr(req.IPAddress)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid IP address"})
		}

		ipVersion := int32(4)
		if ip.Is6() {
			ipVersion = 6
		}

		whitelistEntry, err := queries.AddToWhitelist(c.Context(), database.AddToWhitelistParams{
			UserID:    userID,
			IpAddress: ip,
			IpVersion: ipVersion,
			Reason:    pgtype.Text{String: req.Reason, Valid: req.Reason != ""},
		})
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to add to whitelist"})
		}

		// If hub is available, send unblock commands to all user agents so the
		// whitelist takes effect immediately for both blocklist and ratelimit.
		if hub != nil {
			servers, err := queries.ListServersByUser(c.Context(), userID)
			if err != nil {
				log.Printf("[Whitelist] Could not list user servers for unblock fanout user=%s ip=%s: %v", userIDStr, ip.String(), err)
			} else {
				for _, server := range servers {
					agentID := server.ID.String()
					if agentID == "" {
						continue
					}
					signHubCommand(hub, agentID, "unblock", req.IPAddress, "whitelisted", "blocklist", 0)
					signHubCommand(hub, agentID, "unblock", req.IPAddress, "whitelisted", "ratelimit", 0)
				}
				log.Printf("[Whitelist] Sent unblock fanout for %s to %d agents", req.IPAddress, len(servers))
			}
		}

		return c.Status(fiber.StatusCreated).JSON(WhitelistResponse{
			ID:        whitelistEntry.ID.String(),
			IPAddress: whitelistEntry.IpAddress.String(),
			IPVersion: int(whitelistEntry.IpVersion),
			Reason:    whitelistEntry.Reason.String,
			IsManual:  whitelistEntry.IsManual,
			CreatedAt: whitelistEntry.CreatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
			UpdatedAt: whitelistEntry.UpdatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
		})
	}
}

func HandleRemoveFromWhitelist(queries *database.Queries, hub *Hub) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userIDVal := c.Locals("user_id")
		if userIDVal == nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
		}
		userIDStr := userIDVal.(string)
		userID := database.ToPgUUID(userIDStr)

		ipStr := c.Params("ip")
		if ipStr == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "ip address is required"})
		}

		ip, err := netip.ParseAddr(ipStr)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid IP address"})
		}

		err = queries.RemoveFromWhitelist(c.Context(), database.RemoveFromWhitelistParams{
			UserID:    userID,
			IpAddress: ip,
		})
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to remove from whitelist"})
		}

		// Notify all user agents so local whitelist caches are updated immediately.
		// Use UNBLOCK action with reason=whitelist_removed as control signal to
		// clear local whitelist bypass state.
		if hub != nil {
			servers, listErr := queries.ListServersByUser(c.Context(), userID)
			if listErr != nil {
				log.Printf("[Whitelist] Could not list user servers for whitelist removal fanout user=%s ip=%s: %v", userIDStr, ip.String(), listErr)
			} else {
				for _, server := range servers {
					agentID := server.ID.String()
					if agentID == "" {
						continue
					}
					signHubCommand(hub, agentID, "unblock", ipStr, "whitelist_removed", "blocklist", 0)
					signHubCommand(hub, agentID, "unblock", ipStr, "whitelist_removed", "ratelimit", 0)
				}
				log.Printf("[Whitelist] Sent whitelist removal fanout for %s to %d agents", ipStr, len(servers))
			}
		}

		return c.JSON(fiber.Map{"message": "removed from whitelist"})
	}
}

func HandleListWhitelist(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userIDVal := c.Locals("user_id")
		if userIDVal == nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
		}
		userIDStr := userIDVal.(string)
		userID := database.ToPgUUID(userIDStr)

		entries, err := queries.GetWhitelistByUser(c.Context(), userID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get whitelist"})
		}

		result := make([]WhitelistResponse, len(entries))
		for i, entry := range entries {
			result[i] = WhitelistResponse{
				ID:        entry.ID.String(),
				IPAddress: entry.IpAddress.String(),
				IPVersion: int(entry.IpVersion),
				Reason:    entry.Reason.String,
				IsManual:  entry.IsManual,
				CreatedAt: entry.CreatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
				UpdatedAt: entry.UpdatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
			}
		}

		return c.JSON(result)
	}
}

func HandleCheckWhitelist(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userIDVal := c.Locals("user_id")
		if userIDVal == nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
		}
		userIDStr := userIDVal.(string)
		userID := database.ToPgUUID(userIDStr)

		ipStr := c.Query("ip")
		if ipStr == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "ip query parameter is required"})
		}

		ip, err := netip.ParseAddr(ipStr)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid IP address"})
		}

		result, err := queries.IsIPWhitelisted(c.Context(), database.IsIPWhitelistedParams{
			UserID:    userID,
			IpAddress: ip,
		})
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to check whitelist"})
		}

		return c.JSON(fiber.Map{"is_whitelisted": result})
	}
}
