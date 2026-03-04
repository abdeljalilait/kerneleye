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
}

// DefaultEnvFile is the path to the environment file
const DefaultEnvFile = "/etc/kerneleye/agent.env"

func parseConfig() AgentConfig {
	// Load environment file if it exists (before parsing flags)
	// This allows flags to override env file settings
	if _, err := os.Stat(DefaultEnvFile); err == nil {
		if err := godotenv.Load(DefaultEnvFile); err != nil {
			Logger.Warnf("Failed to load %s: %v", DefaultEnvFile, err)
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
	flag.Parse()

	autoBlockConfig := remediation.DefaultAutoBlockerConfig()
	autoBlockConfig.Enabled = *enableRemediation // Auto-block is enabled when remediation is enabled

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
	}

	if *serverFlag != "" {
		cfg.ServerHost = *serverFlag
	}
	// gRPC URL from env, overridden by flag when present
	if *grpcURLFlag != "" {
		cfg.GRPCURL = *grpcURLFlag
	}
	if cfg.ServerHost == "" {
		Logger.Fatal("KERNELEYE_SERVER is required. Set via -server flag or KERNELEYE_SERVER environment variable.")
	}

	// XDP requires an interface
	if cfg.EnableXDP && cfg.InterfaceName == "" {
		cfg.InterfaceName = detectDefaultInterface()
	}

	return cfg
}

// detectDefaultInterface attempts to find the default network interface
func detectDefaultInterface() string {
	// Common default interface names
	candidates := []string{"eth0", "ens3", "ens18", "enp0s3", "enp1s0"}
	for _, name := range candidates {
		if _, err := os.Stat("/sys/class/net/" + name); err == nil {
			return name
		}
	}
	return "eth0" // Fallback
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
