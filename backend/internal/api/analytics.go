package api

import (
	"log"
	"net/netip"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kerneleye/backend/internal/database"
)

// HandleGetDailyAttackStats returns daily attack statistics for the reports page
func HandleGetDailyAttackStats(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := c.Locals("user_id").(string)

		// Parse date range from query params
		startDate := c.Query("start_date")
		endDate := c.Query("end_date")

		// Default to last 7 days if not provided
		if startDate == "" {
			startDate = time.Now().AddDate(0, 0, -7).Format("2006-01-02")
		}
		if endDate == "" {
			endDate = time.Now().Format("2006-01-02")
		}

		// Parse dates
		start, err := time.Parse("2006-01-02", startDate)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid start_date format")
		}
		end, err := time.Parse("2006-01-02", endDate)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid end_date format")
		}
		end = end.Add(24 * time.Hour) // Include the full end date

		stats, err := queries.GetDailyAttackStats(c.Context(), database.GetDailyAttackStatsParams{
			UserID:      database.ToPgUUID(userID),
			CreatedAt:   database.ToPgTimestamptz(start),
			CreatedAt_2: database.ToPgTimestamptz(end),
		})
		if err != nil {
			log.Printf("[API] GetDailyAttackStats error: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to get daily stats")
		}

		return c.JSON(fiber.Map{
			"data": stats,
		})
	}
}

// HandleGetDailyBlockStats returns daily block statistics (actually prevented attacks)
func HandleGetDailyBlockStats(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := c.Locals("user_id").(string)

		// Parse date range from query params
		startDate := c.Query("start_date")
		endDate := c.Query("end_date")

		// Default to last 7 days if not provided
		if startDate == "" {
			startDate = time.Now().AddDate(0, 0, -7).Format("2006-01-02")
		}
		if endDate == "" {
			endDate = time.Now().Format("2006-01-02")
		}

		// Parse dates
		start, err := time.Parse("2006-01-02", startDate)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid start_date format")
		}
		end, err := time.Parse("2006-01-02", endDate)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid end_date format")
		}
		end = end.Add(24 * time.Hour) // Include the full end date

		stats, err := queries.GetDailyBlockStats(c.Context(), database.GetDailyBlockStatsParams{
			UserID:      database.ToPgUUID(userID),
			BlockedAt:   database.ToPgTimestamptz(start),
			BlockedAt_2: database.ToPgTimestamptz(end),
		})
		if err != nil {
			log.Printf("[API] GetDailyBlockStats error: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to get block stats")
		}

		return c.JSON(fiber.Map{
			"data": stats,
		})
	}
}

// HandleGetAttackTypeBreakdown returns attack type distribution
func HandleGetAttackTypeBreakdown(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := c.Locals("user_id").(string)

		// Parse date range from query params
		startDate := c.Query("start_date")
		endDate := c.Query("end_date")

		// Default to last 7 days
		if startDate == "" {
			startDate = time.Now().AddDate(0, 0, -7).Format("2006-01-02")
		}
		if endDate == "" {
			endDate = time.Now().Format("2006-01-02")
		}

		start, err := time.Parse("2006-01-02", startDate)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid start_date format")
		}
		end, err := time.Parse("2006-01-02", endDate)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid end_date format")
		}
		end = end.Add(24 * time.Hour)

		breakdown, err := queries.GetAttackTypeBreakdown(c.Context(), database.GetAttackTypeBreakdownParams{
			UserID:      database.ToPgUUID(userID),
			CreatedAt:   database.ToPgTimestamptz(start),
			CreatedAt_2: database.ToPgTimestamptz(end),
		})
		if err != nil {
			log.Printf("[API] GetAttackTypeBreakdown error: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to get attack breakdown")
		}

		return c.JSON(fiber.Map{
			"data": breakdown,
		})
	}
}

// HandleGetTopSourceCountries returns top attacking countries
func HandleGetTopSourceCountries(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := c.Locals("user_id").(string)

		// Parse date range and limit
		startDate := c.Query("start_date")
		endDate := c.Query("end_date")
		limit := int32(10)
		if l := c.QueryInt("limit"); l > 0 {
			limit = int32(l)
		}

		// Default to last 7 days
		if startDate == "" {
			startDate = time.Now().AddDate(0, 0, -7).Format("2006-01-02")
		}
		if endDate == "" {
			endDate = time.Now().Format("2006-01-02")
		}

		start, err := time.Parse("2006-01-02", startDate)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid start_date format")
		}
		end, err := time.Parse("2006-01-02", endDate)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid end_date format")
		}
		end = end.Add(24 * time.Hour)

		countries, err := queries.GetTopSourceCountries(c.Context(), database.GetTopSourceCountriesParams{
			UserID:      database.ToPgUUID(userID),
			CreatedAt:   database.ToPgTimestamptz(start),
			CreatedAt_2: database.ToPgTimestamptz(end),
			Limit:       limit,
		})
		if err != nil {
			log.Printf("[API] GetTopSourceCountries error: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to get top countries")
		}

		return c.JSON(fiber.Map{
			"data": countries,
		})
	}
}

// HandleGetHourlyAttackDistribution returns hourly attack patterns
func HandleGetHourlyAttackDistribution(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := c.Locals("user_id").(string)

		// Parse date range
		startDate := c.Query("start_date")
		endDate := c.Query("end_date")

		// Default to last 7 days
		if startDate == "" {
			startDate = time.Now().AddDate(0, 0, -7).Format("2006-01-02")
		}
		if endDate == "" {
			endDate = time.Now().Format("2006-01-02")
		}

		start, err := time.Parse("2006-01-02", startDate)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid start_date format")
		}
		end, err := time.Parse("2006-01-02", endDate)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid end_date format")
		}
		end = end.Add(24 * time.Hour)

		hourly, err := queries.GetHourlyAttackDistribution(c.Context(), database.GetHourlyAttackDistributionParams{
			UserID:      database.ToPgUUID(userID),
			CreatedAt:   database.ToPgTimestamptz(start),
			CreatedAt_2: database.ToPgTimestamptz(end),
		})
		if err != nil {
			log.Printf("[API] GetHourlyAttackDistribution error: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to get hourly distribution")
		}

		return c.JSON(fiber.Map{
			"data": hourly,
		})
	}
}

// HandleGetTopSourceIPs returns top attacking IPs for visualizer
func HandleGetTopSourceIPs(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := c.Locals("user_id").(string)

		// Parse date range and limit
		startDate := c.Query("start_date")
		endDate := c.Query("end_date")
		limit := int32(20)
		if l := c.QueryInt("limit"); l > 0 {
			limit = int32(l)
		}

		// Default to last 24 hours
		if startDate == "" {
			startDate = time.Now().AddDate(0, 0, -1).Format("2006-01-02")
		}
		if endDate == "" {
			endDate = time.Now().Format("2006-01-02")
		}

		start, err := time.Parse("2006-01-02", startDate)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid start_date format")
		}
		end, err := time.Parse("2006-01-02", endDate)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid end_date format")
		}
		end = end.Add(24 * time.Hour)

		ips, err := queries.GetTopSourceIPs(c.Context(), database.GetTopSourceIPsParams{
			UserID:      database.ToPgUUID(userID),
			CreatedAt:   database.ToPgTimestamptz(start),
			CreatedAt_2: database.ToPgTimestamptz(end),
			Limit:       limit,
		})
		if err != nil {
			log.Printf("[API] GetTopSourceIPs error: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to get top source IPs")
		}

		return c.JSON(fiber.Map{
			"data": ips,
		})
	}
}

// HandleGetTopASNs returns top autonomous systems
func HandleGetTopASNs(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := c.Locals("user_id").(string)

		// Parse date range and limit
		startDate := c.Query("start_date")
		endDate := c.Query("end_date")
		limit := int32(10)
		if l := c.QueryInt("limit"); l > 0 {
			limit = int32(l)
		}

		// Default to last 24 hours
		if startDate == "" {
			startDate = time.Now().AddDate(0, 0, -1).Format("2006-01-02")
		}
		if endDate == "" {
			endDate = time.Now().Format("2006-01-02")
		}

		start, err := time.Parse("2006-01-02", startDate)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid start_date format")
		}
		end, err := time.Parse("2006-01-02", endDate)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid end_date format")
		}
		end = end.Add(24 * time.Hour)

		asns, err := queries.GetTopASNs(c.Context(), database.GetTopASNsParams{
			UserID:      database.ToPgUUID(userID),
			CreatedAt:   database.ToPgTimestamptz(start),
			CreatedAt_2: database.ToPgTimestamptz(end),
			Limit:       limit,
		})
		if err != nil {
			log.Printf("[API] GetTopASNs error: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to get top ASNs")
		}

		return c.JSON(fiber.Map{
			"data": asns,
		})
	}
}

// HandleGetSourceIPTimeline returns timeline data for a specific IP
func HandleGetSourceIPTimeline(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := c.Locals("user_id").(string)
		ip := c.Query("ip")
		startDate := c.Query("start_date")
		endDate := c.Query("end_date")

		if ip == "" {
			return fiber.NewError(fiber.StatusBadRequest, "IP address is required")
		}

		// Default to last 24 hours if range is not provided.
		if startDate == "" {
			startDate = time.Now().AddDate(0, 0, -1).Format("2006-01-02")
		}
		if endDate == "" {
			endDate = time.Now().Format("2006-01-02")
		}

		start, err := time.Parse("2006-01-02", startDate)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid start_date format")
		}
		end, err := time.Parse("2006-01-02", endDate)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid end_date format")
		}
		end = end.Add(24 * time.Hour)

		// Parse IP address
		parsedIP, err := netip.ParseAddr(ip)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid IP address format")
		}

		timeline, err := queries.GetSourceIPTimeline(c.Context(), database.GetSourceIPTimelineParams{
			UserID:   database.ToPgUUID(userID),
			Column2:  parsedIP,
			Bucket:   database.ToPgTimestamptz(start),
			Bucket_2: database.ToPgTimestamptz(end),
		})
		if err != nil {
			log.Printf("[API] GetSourceIPTimeline error: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to get IP timeline")
		}

		return c.JSON(fiber.Map{
			"ip":   ip,
			"data": timeline,
		})
	}
}

// HandleGetSourceIPBlockTimes returns the timestamps when a specific IP was blocked
func HandleGetSourceIPBlockTimes(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := c.Locals("user_id").(string)
		ip := c.Query("ip")
		startDate := c.Query("start_date")
		endDate := c.Query("end_date")

		if ip == "" {
			return fiber.NewError(fiber.StatusBadRequest, "IP address is required")
		}

		if startDate == "" {
			startDate = time.Now().AddDate(0, 0, -1).Format("2006-01-02")
		}
		if endDate == "" {
			endDate = time.Now().Format("2006-01-02")
		}

		start, err := time.Parse("2006-01-02", startDate)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid start_date format")
		}
		end, err := time.Parse("2006-01-02", endDate)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid end_date format")
		}
		end = end.Add(24 * time.Hour)

		parsedIP, err := netip.ParseAddr(ip)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid IP address format")
		}

		times, err := queries.GetSourceIPBlockTimes(c.Context(), database.GetSourceIPBlockTimesParams{
			UserID:      database.ToPgUUID(userID),
			Column2:     parsedIP,
			BlockedAt:   database.ToPgTimestamptz(start),
			BlockedAt_2: database.ToPgTimestamptz(end),
		})
		if err != nil {
			log.Printf("[API] GetSourceIPBlockTimes error: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to get IP block times")
		}

		// Convert to plain ISO strings for the frontend
		result := make([]string, 0, len(times))
		for _, t := range times {
			if t.Valid {
				result = append(result, t.Time.UTC().Format(time.RFC3339))
			}
		}

		return c.JSON(fiber.Map{
			"ip":   ip,
			"data": result,
		})
	}
}

// HandleGetTopIPsTimeline returns timeline data for the top N IPs ranked by hits or score
func HandleGetTopIPsTimeline(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := c.Locals("user_id").(string)
		sortBy := c.Query("sort_by", "hits") // "hits" | "score"
		startDate := c.Query("start_date")
		endDate := c.Query("end_date")
		limit := int32(5)
		if l := c.QueryInt("limit"); l > 0 {
			limit = int32(l)
		}

		if startDate == "" {
			startDate = time.Now().AddDate(0, 0, -1).Format("2006-01-02")
		}
		if endDate == "" {
			endDate = time.Now().Format("2006-01-02")
		}

		start, err := time.Parse("2006-01-02", startDate)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid start_date format")
		}
		end, err := time.Parse("2006-01-02", endDate)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid end_date format")
		}
		end = end.Add(24 * time.Hour)

		type timelineRow struct {
			Ip         string `json:"ip"`
			TimeBucket string `json:"time_bucket"`
			Count      int32  `json:"count"`
		}

		var rows []timelineRow
		topIPs := map[string]bool{}

		if sortBy == "score" {
			result, err := queries.GetTopIPsTimelineByScore(c.Context(), database.GetTopIPsTimelineByScoreParams{
				UserID:   database.ToPgUUID(userID),
				Bucket:   database.ToPgTimestamptz(start),
				Bucket_2: database.ToPgTimestamptz(end),
				Limit:    limit,
			})
			if err != nil {
				log.Printf("[API] GetTopIPsTimelineByScore error: %v", err)
				return fiber.NewError(fiber.StatusInternalServerError, "Failed to get timeline")
			}
			for _, r := range result {
				bucket := ""
				if r.TimeBucket.Valid {
					bucket = r.TimeBucket.Time.UTC().Format(time.RFC3339)
				}
				rows = append(rows, timelineRow{Ip: r.Ip, TimeBucket: bucket, Count: r.Count})
				topIPs[r.Ip] = true
			}
		} else {
			result, err := queries.GetTopIPsTimelineByHits(c.Context(), database.GetTopIPsTimelineByHitsParams{
				UserID:   database.ToPgUUID(userID),
				Bucket:   database.ToPgTimestamptz(start),
				Bucket_2: database.ToPgTimestamptz(end),
				Limit:    limit,
			})
			if err != nil {
				log.Printf("[API] GetTopIPsTimelineByHits error: %v", err)
				return fiber.NewError(fiber.StatusInternalServerError, "Failed to get timeline")
			}
			for _, r := range result {
				bucket := ""
				if r.TimeBucket.Valid {
					bucket = r.TimeBucket.Time.UTC().Format(time.RFC3339)
				}
				rows = append(rows, timelineRow{Ip: r.Ip, TimeBucket: bucket, Count: r.Count})
				topIPs[r.Ip] = true
			}
		}

		ips := make([]string, 0, len(topIPs))
		for ip := range topIPs {
			ips = append(ips, ip)
		}

		return c.JSON(fiber.Map{
			"data":    rows,
			"top_ips": ips,
		})
	}
}

func HandleGetThreatTrends(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := c.Locals("user_id").(string)

		// Parse date range
		startDate := c.Query("start_date")
		endDate := c.Query("end_date")

		// Default to last 7 days
		if startDate == "" {
			startDate = time.Now().AddDate(0, 0, -7).Format("2006-01-02")
		}
		if endDate == "" {
			endDate = time.Now().Format("2006-01-02")
		}

		start, err := time.Parse("2006-01-02", startDate)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid start_date format")
		}
		end, err := time.Parse("2006-01-02", endDate)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid end_date format")
		}
		end = end.Add(24 * time.Hour)

		trends, err := queries.GetThreatTrends(c.Context(), database.GetThreatTrendsParams{
			UserID:      database.ToPgUUID(userID),
			CreatedAt:   database.ToPgTimestamptz(start),
			CreatedAt_2: database.ToPgTimestamptz(end),
		})
		if err != nil {
			log.Printf("[API] GetThreatTrends error: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to get threat trends")
		}

		return c.JSON(fiber.Map{
			"data": trends,
		})
	}
}
