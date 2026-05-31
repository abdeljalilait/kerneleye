package main

import (
	"flag"
	"os"

	"github.com/joho/godotenv"
	"github.com/kerneleye/agent/remediation"
)

// AgentConfig holds all agent configuration
type AgentConfig struct {
	APIKey            string
	ServerHost        string
	GRPCURL           string // gRPC server URL (overrides ServerHost if set)
	EnableRemediation bool   // Enables both remediation AND auto-blocking
	EnableXDP         bool
	AutoBlockConfig   remediation.AutoBlockerConfig
	InterfaceName     string
	LogFile           string // Path to log file (empty = stdout only)
	ListBlocked       bool   // Print current ipset blocklist and exit
	ClearData         bool   // Delete all local data stores and exit
	FlushBlocklists   bool   // Flush all ipset and XDP blocklists and exit
	ReadOnly          bool   // Disable all remediation actions (monitor + report only)

	// TLS configuration for agent-to-backend communication
	TLSInsecure  bool   // Disable TLS entirely (dev only — loud warning logged)
	TLSCAFile    string // Custom CA certificate PEM file for backend verification
	TLSCertFile  string // Agent client certificate PEM file (for mTLS)
	TLSKeyFile   string // Agent client private key PEM file (for mTLS)
	TLSServerName string // Override TLS server name for hostname verification
}

// DefaultEnvFile is the path to the environment file
const DefaultEnvFile = "/etc/kerneleye/agent.env"

// ToTLSTransportConfig converts AgentConfig TLS fields to a TLSTransportConfig.
func (cfg AgentConfig) ToTLSTransportConfig() *TLSTransportConfig {
	return &TLSTransportConfig{
		Insecure:   cfg.TLSInsecure,
		CAFile:     cfg.TLSCAFile,
		CertFile:   cfg.TLSCertFile,
		KeyFile:    cfg.TLSKeyFile,
		ServerName: cfg.TLSServerName,
	}
}

func parseConfig() AgentConfig {
	// Load environment file if it exists (before parsing flags)
	// This allows flags to override env file settings
	if _, err := os.Stat(DefaultEnvFile); err == nil {
		if err := godotenv.Load(DefaultEnvFile); err != nil {
			if Logger != nil {
				Logger.Warnf("Failed to load %s: %v", DefaultEnvFile, err)
			}
		}
	}

	serverFlag := flag.String("server", "", "Backend server address")
	grpcURLFlag := flag.String("grpc-url", "", "gRPC server URL (overrides server address)")
	enableRemediation := flag.Bool("enable-remediation", false, "Enable active remediation with auto-blocking (requires root and iptables)")
	enableXDP := flag.Bool("xdp", false, "Enable XDP fast-path blocking (requires root, kernel 5.4+)")
	interfaceName := flag.String("interface", "", "Network interface for XDP attachment (e.g., eth0)")
	logFile := flag.String("log", os.Getenv("KERNELEYE_LOG_FILE"), "Log file path (default: stdout)")
	listBlocked := flag.Bool("list-blocked", false, "Print IPs currently in kernel_eye ipsets and exit")
	clearData := flag.Bool("clear-data", false, "Delete all local data stores (history.db, pending.db) and exit")
	flushBlocklists := flag.Bool("flush-blocklists", false, "Flush all ipset and XDP blocklists (kernel structures) and exit")
	readOnly := flag.Bool("read-only", false, "Disable all remediation actions (agent monitors and reports only, never blocks)")

	// TLS flags
	insecure := flag.Bool("insecure", false, "Disable TLS entirely — NEVER use in production")
	tlsCAFile := flag.String("tls-ca-file", os.Getenv("KERNELEYE_TLS_CA_FILE"), "Custom CA certificate PEM file for backend verification")
	tlsCertFile := flag.String("tls-cert-file", os.Getenv("KERNELEYE_TLS_CERT_FILE"), "Agent client certificate PEM file for mTLS")
	tlsKeyFile := flag.String("tls-key-file", os.Getenv("KERNELEYE_TLS_KEY_FILE"), "Agent client private key PEM file for mTLS")
	tlsServerName := flag.String("tls-server-name", os.Getenv("KERNELEYE_TLS_SERVER_NAME"), "Override TLS server name for hostname verification")

	flag.Parse()

	autoBlockConfig := remediation.DefaultAutoBlockerConfig()
	autoBlockConfig.Enabled = *enableRemediation

	cfg := AgentConfig{
		APIKey:            os.Getenv("KERNELEYE_API_KEY"),
		ServerHost:        os.Getenv("KERNELEYE_SERVER"),
		GRPCURL:           os.Getenv("KERNELEYE_GRPC_URL"),
		EnableRemediation: *enableRemediation,
		EnableXDP:         *enableXDP,
		AutoBlockConfig:   autoBlockConfig,
		InterfaceName:     *interfaceName,
		LogFile:           *logFile,
		ListBlocked:       *listBlocked,
		ClearData:         *clearData,
		FlushBlocklists:   *flushBlocklists,
		ReadOnly:          *readOnly,
		TLSInsecure:       *insecure,
		TLSCAFile:         *tlsCAFile,
		TLSCertFile:       *tlsCertFile,
		TLSKeyFile:        *tlsKeyFile,
		TLSServerName:     *tlsServerName,
	}

	if *serverFlag != "" {
		cfg.ServerHost = *serverFlag
	}
	if *grpcURLFlag != "" {
		cfg.GRPCURL = *grpcURLFlag
	}
	if cfg.ServerHost == "" {
		if Logger != nil {
			Logger.Fatal("KERNELEYE_SERVER is required. Set via -server flag or KERNELEYE_SERVER environment variable.")
		}
		os.Exit(1)
	}

	// XDP requires an interface
	if cfg.EnableXDP && cfg.InterfaceName == "" {
		cfg.InterfaceName = detectDefaultInterface()
	}

	return cfg
}

// detectDefaultInterface attempts to find the default network interface
func detectDefaultInterface() string {
	candidates := []string{"eth0", "ens3", "ens18", "enp0s3", "enp1s0"}
	for _, name := range candidates {
		if _, err := os.Stat("/sys/class/net/" + name); err == nil {
			return name
		}
	}
	return "eth0"
}

func printBanner(cfg AgentConfig) {
	Logger.Info("╔════════════════════════════════════════╗")
	Logger.Infof("║   KernelEye Agent v%-19s ║", Version)
	Logger.Info("╚════════════════════════════════════════╝")
	Logger.Infof("API Key: %s...%s", cfg.APIKey[:4], cfg.APIKey[len(cfg.APIKey)-4:])
	Logger.Infof("Server: %s", cfg.ServerHost)
	if cfg.GRPCURL != "" {
		Logger.Infof("gRPC URL: %s", cfg.GRPCURL)
	}
	if cfg.TLSInsecure {
		Logger.Warn("⚠️  TLS DISABLED (--insecure) — all traffic is plaintext")
	}
	if cfg.TLSCertFile != "" {
		Logger.Infof("mTLS: Enabled (cert: %s)", cfg.TLSCertFile)
	}
	if cfg.ReadOnly {
		Logger.Info("🛡️  Read-only mode: agent will not perform any blocking")
	}
	Logger.Info("Monitoring: TCP connections (IPv4)")
	if byteCounterMap != nil {
		Logger.Info("Monitoring: Bandwidth tracking (IPv4)")
	}
	if cfg.EnableXDP {
		Logger.Infof("XDP: Enabled on %s", cfg.InterfaceName)
	}
	if cfg.EnableRemediation {
		Logger.Infof("Auto-Block: Enabled (threshold: %d)", cfg.AutoBlockConfig.BlockThreshold)
	}
}
