package api

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/kerneleye/backend/internal/database"
)

// AgentMode represents the agent deployment mode
type AgentMode string

const (
	ModeMonitorOnly AgentMode = "monitor"
	ModeBlockIPSet  AgentMode = "block_ipset"
	ModeBlockXDP    AgentMode = "block_xdp"
	ModeBlockHybrid AgentMode = "block_hybrid"
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
			Key:           string(ModeMonitorOnly),
			Name:          "Monitor Only",
			Description:   "Collect traffic data without blocking. Alerts only.",
			Requirements:  "None - works on any Linux system",
			Performance:   "Minimal overhead (<1% CPU)",
			Compatibility: "Universal - all Linux kernels",
		},
		{
			Key:           string(ModeBlockIPSet),
			Name:          "IPSet Blocking",
			Description:   "Block threats using iptables + ipset. Reliable and compatible.",
			Requirements:  "Root privileges, ipset package",
			Performance:   "~10μs per packet, handles 100k PPS",
			Compatibility: "Works on all Linux systems, VMs, containers",
		},
		{
			Key:           string(ModeBlockXDP),
			Name:          "XDP Blocking (High Performance)",
			Description:   "Kernel-level packet filtering at NIC driver. Ultra-fast.",
			Requirements:  "Root, kernel 4.8+, XDP-supported NIC, BTF",
			Performance:   "~50ns per packet, handles 10M+ PPS",
			Compatibility: "Bare metal, some VMs. Not in containers.",
		},
		{
			Key:           string(ModeBlockHybrid),
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

// HandleGenerateAPIKeyWithConfig generates API key with configuration options
func HandleGenerateAPIKeyWithConfig(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := c.Locals("user_id").(string)

		var req GenerateAPIKeyRequest
		if err := c.BodyParser(&req); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid request")
		}

		// Generate API key
		apiKey := "ke_" + uuid.New().String()
		clientToken := uuid.New().String()

		// Create server in pending state
		server, err := queries.CreateServerWithAPIKey(c.Context(), database.CreateServerWithAPIKeyParams{
			UserID:      database.ToPgUUID(userID),
			Hostname:    req.ServerName,
			ApiKey:      database.ToPgText(apiKey),
			ClientToken: database.ToPgText(clientToken),
			IpAddress:   nil,
		})
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "failed to create server")
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
