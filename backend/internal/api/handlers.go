package api

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/kerneleye/backend/internal/database"
	"github.com/kerneleye/backend/internal/geoip"
)

// sanitizeLikePattern escapes ILIKE metacharacters (%, _) in user input
// to prevent wildcard injection in LIKE/ILIKE queries.
func sanitizeLikePattern(input string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(input)
}

// ServerWithLocation extends a Server row with GeoIP-derived location fields.
type ServerWithLocation struct {
	database.Server
	CountryCode string  `json:"country_code"`
	CountryName string  `json:"country_name"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
}

// HandleListServers returns all servers for a user, enriched with GeoIP location data.
func HandleListServers(queries *database.Queries, geoIP *geoip.Service) fiber.Handler {
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

		if geoIP == nil {
			return c.JSON(servers)
		}

		enriched := make([]ServerWithLocation, 0, len(servers))
		for _, s := range servers {
			row := ServerWithLocation{Server: s}
			if s.IpAddress != nil {
				country, countryCode, city, _, lat, lng, _, _, _ := geoIP.LookupDetailed(s.IpAddress.String())
				row.CountryCode = countryCode
				row.CountryName = country
				row.City = city
				row.Latitude = lat
				row.Longitude = lng
			}
			enriched = append(enriched, row)
		}
		return c.JSON(enriched)
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
		search := sanitizeLikePattern(c.Query("search"))
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

		// Build query params - use pgtype.Text for nullable text params
		params := database.ListTrafficEventsByServerParams{
			ServerID: database.ToPgUUID(serverID),
			Limit:    int32(pageSize),
			Offset:   int32(offset),
			Column8:  sortBy,
		}

		// Apply search filter (empty string means no filter)
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

// PortTrafficResponse represents aggregated traffic data per port/protocol
type PortTrafficResponse struct {
	Port           int32          `json:"port"`
	Protocol       string         `json:"protocol"`
	ServiceName    string         `json:"service_name"`
	UniqueIps      int32          `json:"unique_ips"`
	TotalBytesIn   int64          `json:"total_bytes_in"`
	TotalBytesOut  int64          `json:"total_bytes_out"`
	TotalHits      int32          `json:"total_hits"`
	TotalSyn       int32          `json:"total_syn"`
	TotalAck       int32          `json:"total_ack"`
	TotalIcmpIn    int64          `json:"total_icmp_in"`
	TotalIcmpOut   int64          `json:"total_icmp_out"`
	MaxThreatScore int32          `json:"max_threat_score"`
	MaxThreatLevel string         `json:"max_threat_level"`
	LastSeen       time.Time      `json:"last_seen"`
	Sources        []PortSourceIP `json:"sources"`
}

// PortSourceIP represents a source IP in port traffic
type PortSourceIP struct {
	SourceIP             string           `json:"source_ip"`
	DestinationPort      int32            `json:"destination_port,omitempty"`
	DestinationIP        *string          `json:"destination_ip,omitempty"`
	BytesIn              int64            `json:"bytes_in"`
	BytesOut             int64            `json:"bytes_out"`
	SynCount             int32            `json:"syn_count"`
	AckCount             int32            `json:"ack_count"`
	HitCount             int32            `json:"hit_count"`
	ThreatScore          int32            `json:"threat_score"`
	ThreatLevel          string           `json:"threat_level"`
	Country              *string          `json:"country,omitempty"`
	City                 *string          `json:"city,omitempty"`
	ISP                  *string          `json:"isp,omitempty"`
	LastSeen             time.Time        `json:"last_seen"`
	Direction            string           `json:"direction,omitempty"`
	IcmpPacketsIn        int64            `json:"icmp_packets_in,omitempty"`
	IcmpPacketsOut       int64            `json:"icmp_packets_out,omitempty"`
	ConnectionDurationMs int64            `json:"connection_duration_ms,omitempty"`
	PortBytesIn          map[string]int64 `json:"port_bytes_in,omitempty"`
	PortBytesOut         map[string]int64 `json:"port_bytes_out,omitempty"`
}

// ProtocolTrafficResponse represents aggregated traffic data per protocol
type ProtocolTrafficResponse struct {
	Protocol       string         `json:"protocol"`
	UniqueIps      int32          `json:"unique_ips"`
	UniquePorts    int32          `json:"unique_ports"`
	TotalBytesIn   int64          `json:"total_bytes_in"`
	TotalBytesOut  int64          `json:"total_bytes_out"`
	TotalHits      int32          `json:"total_hits"`
	TotalSyn       int32          `json:"total_syn"`
	TotalAck       int32          `json:"total_ack"`
	MaxThreatScore int32          `json:"max_threat_score"`
	MaxThreatLevel string         `json:"max_threat_level"`
	LastSeen       time.Time      `json:"last_seen"`
	Sources        []PortSourceIP `json:"sources"`
}

// HandleServerPortTraffic returns aggregated port traffic with source IPs for a specific server
func HandleServerPortTraffic(queries *database.Queries) fiber.Handler {
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
		search := sanitizeLikePattern(c.Query("search"))
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
		params := database.ListPortTrafficByServerParams{
			ServerID: database.ToPgUUID(serverID),
			Limit:    int32(pageSize),
			Offset:   int32(offset),
			Column6:  sortBy,
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
		countParams := database.CountPortTrafficByServerParams{
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

		totalCount, err := queries.CountPortTrafficByServer(c.Context(), countParams)
		if err != nil {
			log.Printf("[HandleServerPortTraffic] Count error: %v", err)
			totalCount = 0
		}

		rows, err := queries.ListPortTrafficByServer(c.Context(), params)
		if err != nil {
			log.Printf("[HandleServerPortTraffic] Error: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to fetch port traffic")
		}

		// Convert to response format
		items := make([]PortTrafficResponse, 0, len(rows))
		for _, row := range rows {
			// Parse sources JSON
			sources := make([]PortSourceIP, 0)
			if row.Sources != nil {
				var rawSources []map[string]interface{}
				sourcesBytes, _ := json.Marshal(row.Sources)
				if err := json.Unmarshal(sourcesBytes, &rawSources); err == nil {
					for _, raw := range rawSources {
						source := PortSourceIP{
							SourceIP:    getString(raw, "source_ip"),
							BytesIn:     getInt64(raw, "bytes_in"),
							BytesOut:    getInt64(raw, "bytes_out"),
							SynCount:    getInt32(raw, "syn_count"),
							AckCount:    getInt32(raw, "ack_count"),
							HitCount:    getInt32(raw, "hit_count"),
							ThreatScore: getInt32(raw, "threat_score"),
							ThreatLevel: getString(raw, "threat_level"),
							Direction:   getString(raw, "direction"),
						}
						if country, ok := raw["country"].(string); ok && country != "" {
							source.Country = &country
						}
						if city, ok := raw["city"].(string); ok && city != "" {
							source.City = &city
						}
						if isp, ok := raw["isp"].(string); ok && isp != "" {
							source.ISP = &isp
						}
						if lastSeen, ok := raw["last_seen"].(string); ok {
							if t, err := time.Parse(time.RFC3339, lastSeen); err == nil {
								source.LastSeen = t
							}
						}
						sources = append(sources, source)
					}
				}
			}

			// Handle interface{} types from SQL
			var maxThreatScore int32
			if score, ok := row.MaxThreatScore.(int32); ok {
				maxThreatScore = score
			} else if score, ok := row.MaxThreatScore.(int64); ok {
				maxThreatScore = int32(score)
			} else if score, ok := row.MaxThreatScore.(float64); ok {
				maxThreatScore = int32(score)
			}

			var maxThreatLevel string
			if level, ok := row.MaxThreatLevel.(string); ok {
				maxThreatLevel = level
			}

			var lastSeen time.Time
			if ts, ok := row.LastSeen.(time.Time); ok {
				lastSeen = ts
			}

			items = append(items, PortTrafficResponse{
				Port:           row.DestinationPort,
				Protocol:       row.Protocol,
				ServiceName:    row.ServiceName,
				UniqueIps:      int32(row.UniqueIps),
				TotalBytesIn:   row.TotalBytesIn,
				TotalBytesOut:  row.TotalBytesOut,
				TotalHits:      row.TotalHits,
				TotalSyn:       row.TotalSyn,
				TotalAck:       row.TotalAck,
				TotalIcmpIn:    row.TotalIcmpIn,
				TotalIcmpOut:   row.TotalIcmpOut,
				MaxThreatScore: maxThreatScore,
				MaxThreatLevel: maxThreatLevel,
				LastSeen:       lastSeen,
				Sources:        sources,
			})
		}

		// Return with pagination metadata
		totalPages := int(math.Ceil(float64(totalCount) / float64(pageSize)))
		return c.JSON(fiber.Map{
			"data": items,
			"pagination": fiber.Map{
				"page":        page,
				"page_size":   pageSize,
				"total_count": totalCount,
				"total_pages": totalPages,
			},
		})
	}
}

// HandleServerPortSources returns paginated source IPs for a specific port/protocol combination
func HandleServerPortSources(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		serverID := c.Params("id")
		port := c.Params("port")
		userID := c.Locals("user_id")

		// Verify ownership
		server, err := queries.GetServerByID(c.Context(), database.ToPgUUID(serverID))
		if err != nil {
			return fiber.NewError(fiber.StatusNotFound, "Server not found")
		}
		if database.FromPgUUID(server.UserID) != userID.(string) {
			return fiber.NewError(fiber.StatusForbidden, "Access denied")
		}

		// Parse port number
		portNum, err := strconv.Atoi(port)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid port number")
		}

		// Parse query parameters
		protocol := c.Query("protocol")
		if protocol == "" {
			return fiber.NewError(fiber.StatusBadRequest, "Protocol is required")
		}

		page := c.QueryInt("page", 1)
		if page < 1 {
			page = 1
		}

		pageSize := c.QueryInt("page_size", 25)
		if pageSize > 100 {
			pageSize = 100
		}
		if pageSize < 1 {
			pageSize = 1
		}

		offset := (page - 1) * pageSize

		// Optional filters
		search := sanitizeLikePattern(c.Query("search"))
		sortBy := c.Query("sort_by", "last_seen")
		sortOrder := c.Query("sort_order", "desc")

		// Build query params
		params := database.ListPortSourcesByServerParams{
			ServerID:        database.ToPgUUID(serverID),
			DestinationPort: int32(portNum),
			Protocol:        protocol,
			Limit:           int32(pageSize),
			Offset:          int32(offset),
			Column5:         sortBy,
			Column6:         sortOrder,
		}

		// Apply search filter
		if search != "" {
			params.Column4 = search
		}

		// Get total count for pagination
		countParams := database.CountPortSourcesByServerParams{
			ServerID:        database.ToPgUUID(serverID),
			DestinationPort: int32(portNum),
			Protocol:        protocol,
		}
		if search != "" {
			countParams.Column4 = search
		}

		totalCount, err := queries.CountPortSourcesByServer(c.Context(), countParams)
		if err != nil {
			log.Printf("[HandleServerPortSources] Count error: %v", err)
			totalCount = 0
		}

		rows, err := queries.ListPortSourcesByServer(c.Context(), params)
		if err != nil {
			log.Printf("[HandleServerPortSources] Error: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to fetch port sources")
		}

		// Convert to response format
		items := make([]PortSourceIP, 0, len(rows))
		for _, row := range rows {
			var country, city, isp, destIP *string
			if row.Country.Valid {
				country = &row.Country.String
			}
			if row.City.Valid {
				city = &row.City.String
			}
			if row.Isp.Valid {
				isp = &row.Isp.String
			}
			if row.DestinationIp != nil {
				s := row.DestinationIp.String()
				destIP = &s
			}

			lastSeen := row.LastSeen.Time

			items = append(items, PortSourceIP{
				SourceIP:             row.SourceIp.String(),
				DestinationPort:      int32(portNum),
				DestinationIP:        destIP,
				BytesIn:              row.BytesIn,
				BytesOut:             row.BytesOut,
				SynCount:             row.SynCount,
				AckCount:             row.AckCount,
				HitCount:             row.HitCount,
				ThreatScore:          row.ThreatScore,
				ThreatLevel:          row.ThreatLevel,
				Country:              country,
				City:                 city,
				ISP:                  isp,
				LastSeen:             lastSeen,
				Direction:            row.Direction,
				IcmpPacketsIn:        row.IcmpPacketsIn,
				IcmpPacketsOut:       row.IcmpPacketsOut,
				ConnectionDurationMs: row.ConnectionDurationMs,
				PortBytesIn:          unmarshalPortBytesMap(row.PortBytesIn),
				PortBytesOut:         unmarshalPortBytesMap(row.PortBytesOut),
			})
		}

		// Return with pagination metadata
		totalPages := int(math.Ceil(float64(totalCount) / float64(pageSize)))
		return c.JSON(fiber.Map{
			"data": items,
			"pagination": fiber.Map{
				"page":        page,
				"page_size":   pageSize,
				"total_count": totalCount,
				"total_pages": totalPages,
			},
		})
	}
}

// HandleServerProtocolTraffic returns aggregated protocol traffic with source IPs for a specific server
func HandleServerProtocolTraffic(queries *database.Queries) fiber.Handler {
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
		search := sanitizeLikePattern(c.Query("search"))
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
		params := database.ListProtocolTrafficByServerParams{
			ServerID: database.ToPgUUID(serverID),
			Limit:    int32(pageSize),
			Offset:   int32(offset),
			Column6:  sortBy,
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
		countParams := database.CountProtocolTrafficByServerParams{
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

		totalCount, err := queries.CountProtocolTrafficByServer(c.Context(), countParams)
		if err != nil {
			log.Printf("[HandleServerProtocolTraffic] Count error: %v", err)
			totalCount = 0
		}

		rows, err := queries.ListProtocolTrafficByServer(c.Context(), params)
		if err != nil {
			log.Printf("[HandleServerProtocolTraffic] Error: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to fetch protocol traffic")
		}

		// Convert to response format
		items := make([]ProtocolTrafficResponse, 0, len(rows))
		for _, row := range rows {
			// Parse sources JSON
			sources := make([]PortSourceIP, 0)
			if row.Sources != nil {
				var rawSources []map[string]interface{}
				sourcesBytes, _ := json.Marshal(row.Sources)
				if err := json.Unmarshal(sourcesBytes, &rawSources); err == nil {
					for _, raw := range rawSources {
						source := PortSourceIP{
							SourceIP:        getString(raw, "source_ip"),
							DestinationPort: int32(getInt64(raw, "destination_port")),
							BytesIn:         getInt64(raw, "bytes_in"),
							BytesOut:        getInt64(raw, "bytes_out"),
							SynCount:        getInt32(raw, "syn_count"),
							AckCount:        getInt32(raw, "ack_count"),
							HitCount:        getInt32(raw, "hit_count"),
							ThreatScore:     getInt32(raw, "threat_score"),
							ThreatLevel:     getString(raw, "threat_level"),
							Direction:       getString(raw, "direction"),
						}
						if destIP, ok := raw["destination_ip"].(string); ok && destIP != "" {
							source.DestinationIP = &destIP
						}
						if country, ok := raw["country"].(string); ok && country != "" {
							source.Country = &country
						}
						if city, ok := raw["city"].(string); ok && city != "" {
							source.City = &city
						}
						if isp, ok := raw["isp"].(string); ok && isp != "" {
							source.ISP = &isp
						}
						if lastSeen, ok := raw["last_seen"].(string); ok {
							if t, err := time.Parse(time.RFC3339, lastSeen); err == nil {
								source.LastSeen = t
							}
						}
						sources = append(sources, source)
					}
				}
			}

			// Handle interface{} types from SQL
			var maxThreatScore int32
			if score, ok := row.MaxThreatScore.(int32); ok {
				maxThreatScore = score
			} else if score, ok := row.MaxThreatScore.(int64); ok {
				maxThreatScore = int32(score)
			} else if score, ok := row.MaxThreatScore.(float64); ok {
				maxThreatScore = int32(score)
			}

			var maxThreatLevel string
			if level, ok := row.MaxThreatLevel.(string); ok {
				maxThreatLevel = level
			}

			var lastSeen time.Time
			if ts, ok := row.LastSeen.(time.Time); ok {
				lastSeen = ts
			}

			items = append(items, ProtocolTrafficResponse{
				Protocol:       row.Protocol,
				UniqueIps:      int32(row.UniqueIps),
				UniquePorts:    int32(row.UniquePorts),
				TotalBytesIn:   row.TotalBytesIn,
				TotalBytesOut:  row.TotalBytesOut,
				TotalHits:      row.TotalHits,
				TotalSyn:       row.TotalSyn,
				TotalAck:       row.TotalAck,
				MaxThreatScore: maxThreatScore,
				MaxThreatLevel: maxThreatLevel,
				LastSeen:       lastSeen,
				Sources:        sources,
			})
		}

		// Return with pagination metadata
		totalPages := int(math.Ceil(float64(totalCount) / float64(pageSize)))
		return c.JSON(fiber.Map{
			"data": items,
			"pagination": fiber.Map{
				"page":        page,
				"page_size":   pageSize,
				"total_count": totalCount,
				"total_pages": totalPages,
			},
		})
	}
}

// Helper functions for JSON parsing
// unmarshalPortBytesMap deserializes a JSONB port-bytes map from the DB ([]byte)
// into map[string]int64 suitable for the REST response. Returns nil on empty or error.
func unmarshalPortBytesMap(data []byte) map[string]int64 {
	if len(data) == 0 || string(data) == "{}" || string(data) == "null" {
		return nil
	}
	var m map[string]int64
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getInt64(m map[string]interface{}, key string) int64 {
	switch v := m[key].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	}
	return 0
}

func getInt32(m map[string]interface{}, key string) int32 {
	switch v := m[key].(type) {
	case float64:
		return int32(v)
	case int32:
		return v
	case int:
		return int32(v)
	}
	return 0
}

// ThreatWithBlockStatus extends TrafficEvent with block status
type ThreatWithBlockStatus struct {
	database.TrafficEvent
	IsBlocked bool `json:"is_blocked"`
}

// HandleListThreats returns detected threats with block status
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

		userUUID := database.ToPgUUID(userID.(string))
		threats, err := queries.ListThreats(c.Context(), database.ListThreatsParams{
			UserID: userUUID,
			Limit:  int32(limit),
		})
		if err != nil {
			log.Printf("[HandleListThreats] Error fetching threats for user %s: %v", userID, err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to fetch threats")
		}

		// Check block status for each threat
		threatsWithStatus := make([]ThreatWithBlockStatus, 0, len(threats))
		for _, threat := range threats {
			isBlocked, _ := queries.IsIPBlocked(c.Context(), database.IsIPBlockedParams{
				UserID:    userUUID,
				IpAddress: threat.SourceIp,
			})
			threatsWithStatus = append(threatsWithStatus, ThreatWithBlockStatus{
				TrafficEvent: threat,
				IsBlocked:    isBlocked,
			})
		}

		return c.JSON(threatsWithStatus)
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

		// Check if user has an active subscription, trial, or cancel-at-period-end access
		now := time.Now()
		isTrialing := user.TrialEndsAt.Valid && user.TrialEndsAt.Time.After(now)
		hasActiveSub := hasSubscriptionEntitlement(user, now)

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
		server, err := queries.GetServerByID(c.Context(), database.ToPgUUID(serverID))
		if err != nil {
			log.Printf("[HandleDeleteServer] Server not found: %v", err)
			return fiber.NewError(fiber.StatusNotFound, "Server not found")
		}

		// Verify ownership: server must belong to the authenticated user
		if database.FromPgUUID(server.UserID) != userID.(string) {
			log.Printf("[HandleDeleteServer] Ownership mismatch: user %s tried to delete server %s owned by %s",
				userID, serverID, database.FromPgUUID(server.UserID))
			return fiber.NewError(fiber.StatusForbidden, "You do not own this server")
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
