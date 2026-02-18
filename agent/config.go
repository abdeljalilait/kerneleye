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
	EnableRemediation bool
	EnableXDP         bool
	InterfaceName     string
}

func parseConfig() AgentConfig {
	serverFlag := flag.String("server", "", "Backend server address")
	apiKeyFlag := flag.String("apikey", "", "API key")
	enableRemediation := flag.Bool("enable-remediation", false, "Enable active remediation (requires root and iptables)")
	enableXDP := flag.Bool("xdp", false, "Enable XDP fast-path blocking (requires root, kernel 5.4+)")
	interfaceName := flag.String("interface", "", "Network interface for XDP attachment (e.g., eth0)")
	flag.Parse()

	cfg := AgentConfig{
		APIKey:            os.Getenv("KERNELEYE_API_KEY"),
		ServerHost:        os.Getenv("KERNELEYE_SERVER"),
		EnableRemediation: *enableRemediation,
		EnableXDP:         *enableXDP,
		InterfaceName:     *interfaceName,
	}

	if *apiKeyFlag != "" {
		cfg.APIKey = *apiKeyFlag
	}
	if *serverFlag != "" {
		cfg.ServerHost = *serverFlag
	}
	if cfg.ServerHost == "" {
		cfg.ServerHost = "api.kerneleye.io:443"
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
	log.Println("Monitoring: TCP connections (IPv4)")
	if byteCounterMap != nil {
		log.Println("Monitoring: Bandwidth tracking (IPv4)")
	}
	if cfg.EnableXDP {
		log.Printf("XDP: Enabled on %s\n", cfg.InterfaceName)
	}
}
