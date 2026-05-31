package api

import (
	"fmt"
	"net/url"
	"os"
	"strings"

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
	ServerName string      `json:"server_name" validate:"required"`
	Config     AgentConfig `json:"config"`
}

// CommandBuilder generates the agent run command
type CommandBuilder struct {
	APIKey     string
	ServerHost string
	GRPCURL    string
	Mode       string
	Systemd    bool
	Threshold  int
	Duration   string
	Features   map[string]bool
}

// HandleGenerateAPIKeyWithConfig generates API key with agent configuration.
func HandleGenerateAPIKeyWithConfig(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := c.Locals("user_id").(string)

		var req GenerateAPIKeyRequest
		if err := c.BodyParser(&req); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid request")
		}

		// Generate API key package only.
		// The server row will be created when the remote agent calls Register.
		serverID := uuid.New().String()
		apiKey := GenerateAPIKey(userID, serverID)

		// Use config from request or defaults
		mode := req.Config.Mode
		if mode == "" {
			mode = "block_hybrid"
		}
		threshold := req.Config.Threshold
		if threshold == 0 {
			threshold = 80
		}
		duration := req.Config.Duration
		if duration == "" {
			duration = "1h"
		}
		daemonize := false
		if req.Config.Daemon != nil {
			daemonize = *req.Config.Daemon
		}

		serverHost := getServerHost()
		grpcURL := getGRPCURL(serverHost)

		// Build installation command
		builder := CommandBuilder{
			APIKey:     apiKey,
			ServerHost: serverHost,
			GRPCURL:    grpcURL,
			Mode:       mode,
			Systemd:    daemonize,
			Threshold:  threshold,
			Duration:   duration,
			Features:   req.Config.Features,
		}

		response := map[string]interface{}{
			"api_key":      apiKey,
			"client_token": "",
			"server_id":    serverID,
			"status":       "awaiting_agent_connection",
			"commands": map[string]string{
				"binary":   builder.BinaryCommand(),
				"download": fmt.Sprintf("curl -sSL %s | bash", getInstallScriptURL()),
			},
			"environment": builder.EnvironmentVariables(),
		}

		return c.JSON(response)
	}
}

// BinaryCommand generates one-line curl install command
func (cb *CommandBuilder) BinaryCommand() string {
	args := cb.buildInstallerArgs()
	return fmt.Sprintf("curl -sSL %s | sudo API_KEY=\"%s\" bash -s -- %s",
		getInstallScriptURL(), cb.APIKey, args)
}

// buildInstallerArgs generates arguments for install.sh.
// `--daemon` here means "install/run via systemd service" in the installer.
func (cb *CommandBuilder) buildInstallerArgs() string {
	mode := cb.Mode
	if mode == "" {
		mode = "block_hybrid"
	}

	systemdFlag := ""
	if cb.Systemd {
		systemdFlag = " --daemon"
	}
	if mode == "monitor" {
		return fmt.Sprintf("--server %s --grpc-url %s%s", cb.ServerHost, cb.GRPCURL, systemdFlag)
	}
	return fmt.Sprintf("--mode %s --server %s --grpc-url %s%s", mode, cb.ServerHost, cb.GRPCURL, systemdFlag)
}

// EnvironmentVariables returns a map of env vars for the API response
func (cb *CommandBuilder) EnvironmentVariables() map[string]string {
	// The agent reads API key, server, and optional gRPC target from env.
	// Mode settings are passed via command-line flags
	return map[string]string{
		"KERNELEYE_API_KEY":  cb.APIKey,
		"KERNELEYE_SERVER":   cb.ServerHost,
		"KERNELEYE_GRPC_URL": cb.GRPCURL,
	}
}

func getServerHost() string {
	server := strings.TrimSpace(os.Getenv("KERNELEYE_SERVER"))
	if server == "" {
		return "api.kerneleye.net:9091"
	}

	// Accept either host:port or full URL in env.
	// Examples:
	// - localhost:8080
	// - https://api.example.com/api/v1  -> api.example.com:9091
	if strings.HasPrefix(server, "http://") || strings.HasPrefix(server, "https://") {
		parsed, err := url.Parse(server)
		if err != nil || parsed.Hostname() == "" {
			return "api.kerneleye.net:9091"
		}
		if parsed.Port() != "" {
			return fmt.Sprintf("%s:%s", parsed.Hostname(), parsed.Port())
		}
		if parsed.Scheme == "https" {
			return parsed.Hostname() + ":9091"
		}
		return parsed.Hostname() + ":80"
	}

	return server
}

func getGRPCURL(serverHost string) string {
	// Check for explicit gRPC host first (recommended approach)
	grpcHost := strings.TrimSpace(os.Getenv("KERNELEYE_GRPC_HOST"))
	if grpcHost != "" {
		return grpcHost
	}

	// Fallback: check full gRPC URL
	grpcURL := strings.TrimSpace(os.Getenv("KERNELEYE_GRPC_URL"))
	if grpcURL != "" {
		return grpcURL
	}

	// Derive from server host (without port, agent will append 9091)
	host := strings.Replace(serverHost, ":443", "", 1)
	host = strings.Replace(host, ":8080", "", 1)
	return host
}

func getInstallScriptURL() string {
	installDomain := os.Getenv("INSTALL_DOMAIN")
	if installDomain == "" {
		installDomain = "app.kerneleye.net"
	}
	return fmt.Sprintf("https://%s/install.sh", installDomain)
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
	Daemon    *bool           `json:"daemon,omitempty"`
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

		// Generate API key package only.
		// The server row will be created when the remote agent calls Register.
		serverID := uuid.New().String()
		apiKey := GenerateAPIKey(userIDStr, serverID)

		serverHost := getServerHost()
		grpcURL := getGRPCURL(serverHost)

		// Build installation commands
		daemonize := false
		if req.Config.Daemon != nil {
			daemonize = *req.Config.Daemon
		}
		builder := CommandBuilder{
			APIKey:     apiKey,
			ServerHost: serverHost,
			GRPCURL:    grpcURL,
			Mode:       req.Config.Mode,
			Systemd:    daemonize,
		}

		response := map[string]interface{}{
			"api_key":      apiKey,
			"client_token": "",
			"server_id":    serverID,
			"status":       "awaiting_agent_connection",
			"commands": map[string]string{
				"binary":   builder.BinaryCommand(),
				"download": fmt.Sprintf("curl -sSL %s | bash", getInstallScriptURL()),
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

		// Return default config (agent_configs table was removed)
		// Configuration is now handled via agent flags
		return c.JSON(AgentConfig{
			Mode:      "block_hybrid",
			Features:  map[string]bool{"auto_block": true, "geoip_enrich": true, "bandwidth_tracking": true},
			Threshold: 80,
			Duration:  "1h",
		})
	}
}

// HandleUpdateServerConfig updates the configuration for a server
// Note: Configuration is now managed via agent flags, not stored in database
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

		// Configuration is now handled via agent flags
		// Notify via WebSocket that config change was requested
		hub.Broadcast(userID.(string), "config_updated", map[string]interface{}{
			"server_id": serverID,
			"config":    req,
			"message":   "Configuration is managed via agent flags. Please restart the agent with new flags.",
		})

		return c.JSON(fiber.Map{
			"success": true,
			"message": "Configuration is managed via agent flags. Please restart the agent with new flags.",
			"config":  req,
		})
	}
}
