package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/kerneleye/backend/internal/database"
)

// DeploymentMode represents a deployment option
type DeploymentMode struct {
	Key           string `json:"key"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	Requirements  string `json:"requirements"`
	Performance   string `json:"performance"`
	Compatibility string `json:"compatibility"`
}

// HandleGetDeploymentModes returns available modes for frontend
func HandleGetDeploymentModes(c *fiber.Ctx) error {
	modes := []DeploymentMode{
		{
			Key:           "monitor",
			Name:          "Monitor Only",
			Description:   "Collect traffic data without blocking. Alerts only.",
			Requirements:  "None - works on any Linux system",
			Performance:   "Minimal overhead (<1% CPU)",
			Compatibility: "Universal - all Linux kernels",
		},
		{
			Key:           "block_ipset",
			Name:          "IPSet Blocking",
			Description:   "Block threats using iptables + ipset. Reliable and compatible.",
			Requirements:  "Root privileges, ipset package",
			Performance:   "~10μs per packet, handles 100k PPS",
			Compatibility: "Works on all Linux systems, VMs, containers",
		},
		{
			Key:           "block_xdp",
			Name:          "XDP Blocking (High Performance)",
			Description:   "Kernel-level packet filtering at NIC driver. Ultra-fast.",
			Requirements:  "Root, kernel 4.8+, XDP-supported NIC, BTF",
			Performance:   "~50ns per packet, handles 10M+ PPS",
			Compatibility: "Bare metal, some VMs. Not in containers.",
		},
		{
			Key:           "block_hybrid",
			Name:          "Hybrid (Recommended)",
			Description:   "XDP for speed + IPSet for compatibility and persistence.",
			Requirements:  "Same as XDP mode",
			Performance:   "XDP speed with IPSet fallback",
			Compatibility: "Best of both - XDP if available, else IPSet",
		},
	}

	return c.JSON(modes)
}

// FeatureInfo represents a configurable feature
type FeatureInfo struct {
	Key          string   `json:"key"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Flag         string   `json:"flag"`
	EnvVar       string   `json:"env_var"`
	DefaultValue bool     `json:"default_value"`
	AvailableIn  []string `json:"available_in"`
	Details      string   `json:"details"`
	Example      string   `json:"example"`
	Benefits     []string `json:"benefits"`
	Risks        []string `json:"risks,omitempty"`
}

// HandleGetAgentFeatures returns available features with explanations
func HandleGetAgentFeatures(c *fiber.Ctx) error {
	features := []FeatureInfo{
		{
			Key:          "auto_block",
			Name:         "Auto-Blocking",
			Description:  "Automatically block IPs that exceed threat threshold",
			Flag:         "--auto-block",
			EnvVar:       "KERNELEYE_AUTO_BLOCK",
			DefaultValue: false,
			AvailableIn:  []string{"block_ipset", "block_xdp", "block_hybrid"},
			Details:      "When enabled, the agent will automatically add IPs to the blocklist when their threat score exceeds the threshold.",
			Example:      "KERNELEYE_AUTO_BLOCK=true",
			Benefits: []string{
				"Immediate response to attacks (seconds, not minutes)",
				"Works 24/7 without human intervention",
				"Escalates duration for repeat offenders",
			},
			Risks: []string{
				"Potential false positives (mitigated by confidence scoring)",
				"Could block legitimate users during attacks",
			},
		},
		{
			Key:          "geoip_enrich",
			Name:         "GeoIP Enrichment",
			Description:  "Add country/city data to traffic logs",
			Flag:         "--geoip",
			EnvVar:       "KERNELEYE_GEOIP",
			DefaultValue: true,
			AvailableIn:  []string{"monitor", "block_ipset", "block_xdp", "block_hybrid"},
			Details:      "Requires MaxMind GeoIP database. Adds country, city, ASN to events.",
			Example:      "KERNELEYE_GEOIP=true",
			Benefits: []string{
				"See where attacks come from",
				"Block by country if needed",
				"Detect unusual geo patterns",
			},
		},
	}

	return c.JSON(features)
}

// GenerateAPIKeyRequest with configuration options
type GenerateAPIKeyRequest struct {
	ServerName string `json:"server_name" validate:"required"`
}

// CommandBuilder generates the agent run command
type CommandBuilder struct {
	APIKey     string
	ServerHost string
	Mode       string
}

// HandleGenerateAPIKeyWithConfig generates API key with subscription validation
func HandleGenerateAPIKeyWithConfig(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := c.Locals("user_id").(string)

		var req GenerateAPIKeyRequest
		if err := c.BodyParser(&req); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid request")
		}

		// Validate user has active subscription
		user, err := queries.GetUserByID(c.Context(), database.ToPgUUID(userID))
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "failed to verify user")
		}

		// Check subscription status - accepts active, trialing, or valid trial end date
		isTrialing := user.TrialEndsAt.Valid && user.TrialEndsAt.Time.After(time.Now())
		hasActiveSub := user.SubscriptionStatus.String == "active" || 
		                user.SubscriptionStatus.String == "trialing" || 
		                isTrialing
		
		if !hasActiveSub {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":   "No active subscription",
				"message": "You need an active subscription or trial to add servers.",
				"code":    "NO_SUBSCRIPTION",
			})
		}

		// Check server limit
		serverCount, err := queries.CountServersByUser(c.Context(), database.ToPgUUID(userID))
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "failed to check server limit")
		}

		if serverCount >= user.MaxServers {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":       "Server limit reached",
				"message":     fmt.Sprintf("Your plan allows up to %d servers", user.MaxServers),
				"code":        "SERVER_LIMIT_REACHED",
				"current":     serverCount,
				"max":         user.MaxServers,
				"upgrade_url": "/subscription",
			})
		}

		// Generate client token first (for identification before full registration)
		clientToken := uuid.New().String()
		
		// Create server in pending state
		server, err := queries.CreateServerWithAPIKey(c.Context(), database.CreateServerWithAPIKeyParams{
			UserID:      database.ToPgUUID(userID),
			Hostname:    req.ServerName,
			ApiKey:      database.ToPgText("pending"), // Will be set after registration
			ClientToken: database.ToPgText(clientToken),
			IpAddress:   nil,
		})
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "failed to create server")
		}

		// Generate proper API key with HMAC signature
		apiKey := GenerateAPIKey(userID, database.FromPgUUID(server.ID))
		
		// Update server with actual API key
		err = queries.UpdateServerAPIKey(c.Context(), database.UpdateServerAPIKeyParams{
			ID:     server.ID,
			ApiKey: database.ToPgText(apiKey),
		})
		if err != nil {
			// Rollback: delete the server we just created
			_ = queries.DeleteServer(c.Context(), server.ID)
			return fiber.NewError(fiber.StatusInternalServerError, "failed to set API key")
		}

		// Build installation command
		builder := CommandBuilder{
			APIKey:     apiKey,
			ServerHost: getServerHost(),
			Mode:       "block_hybrid",
		}

		response := map[string]interface{}{
			"api_key":      apiKey,
			"client_token": clientToken,
			"server_id":    server.ID.String(),
			"status":       "pending",
			"commands": map[string]string{
				"docker":   builder.DockerCommand(),
				"systemd":  builder.SystemdCommand(),
				"binary":   builder.BinaryCommand(),
				"download": "curl -sSL https://install.kerneleye.cloud | bash",
			},
			"environment": builder.EnvironmentVariables(),
		}

		return c.JSON(response)
	}
}

// DockerCommand generates Docker run command
func (cb *CommandBuilder) DockerCommand() string {
	env := cb.buildEnvVars()

	cmd := fmt.Sprintf("docker run -d \\\n  --name kerneleye-agent \\\n  --privileged \\\n  --net=host \\\n  -v /sys/kernel/debug:/sys/kernel/debug \\\n%s \\\n  kerneleye/agent:latest", env)

	return cmd
}

// SystemdCommand generates systemd service setup
func (cb *CommandBuilder) SystemdCommand() string {
	env := cb.buildEnvVars()

	return fmt.Sprintf(`# Download and install
sudo curl -o /usr/local/bin/kerneleye-agent \
  https://releases.kerneleye.cloud/agent/latest/kerneleye-agent
sudo chmod +x /usr/local/bin/kerneleye-agent

# Create environment file
sudo mkdir -p /etc/kerneleye
cat << 'EOF' | sudo tee /etc/kerneleye/agent.env
%sEOF

# Create systemd service
sudo kerneleye-agent install
sudo systemctl enable --now kerneleye-agent

# Check status
sudo systemctl status kerneleye-agent`, env)
}

// BinaryCommand generates direct binary run command
func (cb *CommandBuilder) BinaryCommand() string {
	env := cb.buildEnvVarsInline()

	cmd := fmt.Sprintf("sudo %s kerneleye-agent -server \"%s\" -apikey \"%s\"",
		env, cb.ServerHost, cb.APIKey)

	return cmd
}

// buildEnvVars generates environment variable exports
func (cb *CommandBuilder) buildEnvVars() string {
	var vars string

	vars += fmt.Sprintf("  -e KERNELEYE_API_KEY=%s \\\n", cb.APIKey)
	vars += fmt.Sprintf("  -e KERNELEYE_SERVER=%s \\\n", cb.ServerHost)

	switch cb.Mode {
	case "block_xdp":
		vars += "  -e KERNELEYE_XDP=true \\\n"
	case "block_hybrid":
		vars += "  -e KERNELEYE_XDP=true \\\n"
		vars += "  -e KERNELEYE_HYBRID=true \\\n"
	}

	return vars
}

// buildEnvVarsInline generates inline env vars for binary command
func (cb *CommandBuilder) buildEnvVarsInline() string {
	var vars string

	vars += fmt.Sprintf("KERNELEYE_API_KEY=%s ", cb.APIKey)
	vars += fmt.Sprintf("KERNELEYE_SERVER=%s ", cb.ServerHost)

	switch cb.Mode {
	case "block_xdp":
		vars += "KERNELEYE_XDP=true "
	case "block_hybrid":
		vars += "KERNELEYE_XDP=true KERNELEYE_HYBRID=true "
	}

	return vars
}

// EnvironmentVariables returns a map of env vars
func (cb *CommandBuilder) EnvironmentVariables() map[string]string {
	vars := map[string]string{
		"KERNELEYE_API_KEY": cb.APIKey,
		"KERNELEYE_SERVER":  cb.ServerHost,
	}

	switch cb.Mode {
	case "block_xdp", "block_hybrid":
		vars["KERNELEYE_XDP"] = "true"
	}

	if cb.Mode == "block_hybrid" {
		vars["KERNELEYE_HYBRID"] = "true"
	}

	return vars
}

func getServerHost() string {
	return "api.kerneleye.cloud:443"
}

func toEnvVar(s string) string {
	return strings.ToUpper(strings.ReplaceAll(s, "-", "_"))
}

// ============================================
// Server Configuration Handlers
// ============================================

// AgentConfig represents the agent configuration
type AgentConfig struct {
	Mode      string          `json:"mode"`
	Features  map[string]bool `json:"features"`
	Threshold int             `json:"threshold"`
	Duration  string          `json:"duration"`
}

// CreateServerWithConfigRequest represents the request to create a server with config
type CreateServerWithConfigRequest struct {
	ServerName string      `json:"server_name"`
	Config     AgentConfig `json:"config"`
}

// HandleCreateServerWithConfig creates a new server with configuration
func HandleCreateServerWithConfig(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := c.Locals("user_id")
		if userID == nil {
			return fiber.NewError(fiber.StatusUnauthorized, "User not authenticated")
		}

		var req CreateServerWithConfigRequest
		if err := c.BodyParser(&req); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
		}

		if req.ServerName == "" {
			return fiber.NewError(fiber.StatusBadRequest, "Server name is required")
		}

		userIDStr := userID.(string)

		// Validate user has active subscription
		user, err := queries.GetUserByID(c.Context(), database.ToPgUUID(userIDStr))
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "failed to verify user")
		}

		// Check subscription status
		isTrialing := user.TrialEndsAt.Valid && user.TrialEndsAt.Time.After(time.Now())
		hasActiveSub := user.SubscriptionStatus.String == "active" || isTrialing

		if !hasActiveSub {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":         "No active subscription",
				"message":       "You need an active subscription or trial to add servers.",
				"code":          "NO_SUBSCRIPTION",
				"subscribe_url": "/subscription",
			})
		}

		// Check server limit
		serverCount, err := queries.CountServersByUser(c.Context(), database.ToPgUUID(userIDStr))
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "failed to check server limit")
		}

		if int32(serverCount) >= user.MaxServers {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":       "Server limit reached",
				"message":     fmt.Sprintf("Your plan allows up to %d servers", user.MaxServers),
				"code":        "SERVER_LIMIT_REACHED",
				"current":     serverCount,
				"max":         user.MaxServers,
				"upgrade_url": "/subscription",
			})
		}

		// Generate client token and API key
		clientToken := uuid.New().String()
		serverID := uuid.New()
		apiKey := GenerateAPIKey(userIDStr, serverID.String())

		// Create server with API key
		server, err := queries.CreateServerWithAPIKey(c.Context(), database.CreateServerWithAPIKeyParams{
			UserID:      database.ToPgUUID(userIDStr),
			Hostname:    req.ServerName,
			ApiKey:      database.ToPgText(apiKey),
			ClientToken: database.ToPgText(clientToken),
			IpAddress:   nil,
		})
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "failed to create server")
		}

		// Store config in database
		featuresJSON, _ := json.Marshal(req.Config.Features)
		_, err = queries.CreateAgentConfig(c.Context(), database.CreateAgentConfigParams{
			ServerID:  server.ID,
			Mode:      req.Config.Mode,
			Features:  featuresJSON,
			Threshold: int32(req.Config.Threshold),
			Duration:  req.Config.Duration,
		})
		if err != nil {
			// Log error but don't fail - config can be recreated later
			fmt.Printf("Failed to create agent config: %v\n", err)
		}

		// Build installation commands
		builder := CommandBuilder{
			APIKey:     apiKey,
			ServerHost: getServerHost(),
			Mode:       req.Config.Mode,
		}

		response := map[string]interface{}{
			"api_key":      apiKey,
			"client_token": clientToken,
			"server_id":    server.ID.String(),
			"status":       "pending",
			"commands": map[string]string{
				"docker":   builder.DockerCommand(),
				"systemd":  builder.SystemdCommand(),
				"binary":   builder.BinaryCommand() + " -daemon",
				"download": "curl -sSL https://install.kerneleye.cloud | bash",
			},
			"environment": builder.EnvironmentVariables(),
		}

		return c.JSON(response)
	}
}

// HandleGetServerConfig returns the configuration for a server
func HandleGetServerConfig(queries *database.Queries) fiber.Handler {
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

		config, err := queries.GetAgentConfigByServerID(c.Context(), database.ToPgUUID(serverID))
		if err != nil {
			// Return default config if none exists
			return c.JSON(AgentConfig{
				Mode:      "block_hybrid",
				Features:  map[string]bool{"auto_block": true, "geoip_enrich": true, "bandwidth_tracking": true},
				Threshold: 80,
				Duration:  "1h",
			})
		}

		var features map[string]bool
		json.Unmarshal(config.Features, &features)

		return c.JSON(AgentConfig{
			Mode:      config.Mode,
			Features:  features,
			Threshold: int(config.Threshold),
			Duration:  config.Duration,
		})
	}
}

// HandleUpdateServerConfig updates the configuration for a server
func HandleUpdateServerConfig(queries *database.Queries, hub *Hub) fiber.Handler {
	return func(c *fiber.Ctx) error {
		serverID := c.Params("id")
		userID := c.Locals("user_id")

		var req AgentConfig
		if err := c.BodyParser(&req); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
		}

		// Verify ownership
		server, err := queries.GetServerByID(c.Context(), database.ToPgUUID(serverID))
		if err != nil {
			return fiber.NewError(fiber.StatusNotFound, "Server not found")
		}
		if database.FromPgUUID(server.UserID) != userID.(string) {
			return fiber.NewError(fiber.StatusForbidden, "Access denied")
		}

		featuresJSON, _ := json.Marshal(req.Features)
		err = queries.UpdateAgentConfig(c.Context(), database.UpdateAgentConfigParams{
			ServerID:  database.ToPgUUID(serverID),
			Mode:      req.Mode,
			Features:  featuresJSON,
			Threshold: int32(req.Threshold),
			Duration:  req.Duration,
		})
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to update configuration")
		}

		// Notify via WebSocket
		hub.Broadcast(userID.(string), "config_updated", map[string]interface{}{
			"server_id": serverID,
			"config":    req,
		})

		return c.JSON(fiber.Map{
			"success": true,
			"config":  req,
		})
	}
}
