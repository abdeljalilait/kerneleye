package main

import (
	"flag"
	"log"
	"os"
)

// AgentConfig holds all agent configuration
type AgentConfig struct {
	APIKey            string
	ServerHost        string
	GRPCURL           string // gRPC server URL (overrides ServerHost if set)
	EnableRemediation bool
	EnableXDP         bool
	InterfaceName     string
	LogFile           string // Path to log file (empty = stdout only)
}

func parseConfig() AgentConfig {
	serverFlag := flag.String("server", "", "Backend server address")
	apiKeyFlag := flag.String("apikey", "", "API key")
	grpcURLFlag := flag.String("grpc-url", "", "gRPC server URL (overrides server address)")
	enableRemediation := flag.Bool("enable-remediation", false, "Enable active remediation (requires root and iptables)")
	enableXDP := flag.Bool("xdp", false, "Enable XDP fast-path blocking (requires root, kernel 5.4+)")
	interfaceName := flag.String("interface", "", "Network interface for XDP attachment (e.g., eth0)")
	logFile := flag.String("log", os.Getenv("KERNELEYE_LOG_FILE"), "Log file path (default: stdout)")
	flag.Parse()

	cfg := AgentConfig{
		APIKey:            os.Getenv("KERNELEYE_API_KEY"),
		ServerHost:        os.Getenv("KERNELEYE_SERVER"),
		GRPCURL:           os.Getenv("KERNELEYE_GRPC_URL"),
		EnableRemediation: *enableRemediation,
		EnableXDP:         *enableXDP,
		InterfaceName:     *interfaceName,
		LogFile:           *logFile,
	}

	if *apiKeyFlag != "" {
		cfg.APIKey = *apiKeyFlag
	}
	if *serverFlag != "" {
		cfg.ServerHost = *serverFlag
	}
	if *grpcURLFlag != "" {
		cfg.GRPCURL = *grpcURLFlag
	}
	// Fall back to build-time default if env var not set
	if cfg.GRPCURL == "" && DefaultGRPCURL != "" {
		cfg.GRPCURL = DefaultGRPCURL
	}
	if cfg.ServerHost == "" {
		log.Fatal("KERNELEYE_SERVER is required. Set via -server flag or KERNELEYE_SERVER environment variable.")
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
	log.Println("╔════════════════════════════════════════╗")
	log.Printf("║   KernelEye Agent v%-19s ║\n", Version)
	log.Println("╚════════════════════════════════════════╝")
	log.Printf("API Key: %s...%s\n", cfg.APIKey[:4], cfg.APIKey[len(cfg.APIKey)-4:])
	log.Printf("Server: %s\n", cfg.ServerHost)
	if cfg.GRPCURL != "" {
		log.Printf("gRPC URL: %s\n", cfg.GRPCURL)
	}
	log.Println("Monitoring: TCP connections (IPv4)")
	if byteCounterMap != nil {
		log.Println("Monitoring: Bandwidth tracking (IPv4)")
	}
	if cfg.EnableXDP {
		log.Printf("XDP: Enabled on %s\n", cfg.InterfaceName)
	}
}
