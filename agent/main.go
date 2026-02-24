package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/kerneleye/agent/remediation"
	"github.com/kerneleye/shared/scoring"
)

// Version information - injected at build time via ldflags
var (
	Version   = "dev"
	GitCommit = "unknown"
	GitBranch = "unknown"
	BuildDate = "unknown"
	BuildUser = "unknown"
	BuildHost = "unknown"
	GoVersion = "unknown"
)

// Default gRPC URL - can be overridden at build time via ldflags
// or at runtime via KERNELEYE_GRPC_URL environment variable
var DefaultGRPCURL = ""

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 bpf ebpf/traffic_probe.c -- -I/usr/include/bpf

func main() {
	// Check for version flag manually (before main flag parsing)
	for _, arg := range os.Args[1:] {
		if arg == "-version" || arg == "--version" {
			printVersion()
			os.Exit(0)
		}
	}

	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	cfg := parseConfig()

	// Print banner immediately to show version on startup
	printBanner(cfg)

	// Logging setup (agent runs in foreground; systemd manages background lifecycle)
	if cfg.LogFile != "" {
		// Ensure log directory exists
		logDir := filepath.Dir(cfg.LogFile)
		if logDir != "" && logDir != "." {
			if err := os.MkdirAll(logDir, 0755); err != nil {
				log.Printf("⚠️  Failed to create log directory %s: %v", logDir, err)
			}
		}

		logFile, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("⚠️  Failed to open log file %s: %v. Using stdout.", cfg.LogFile, err)
		} else {
			// Write to both stdout and file
			log.SetOutput(io.MultiWriter(os.Stdout, logFile))
		}
	} else {
		log.SetOutput(os.Stdout)
	}

	if cfg.APIKey == "" {
		log.Fatal("KERNELEYE_API_KEY is required.")
	}
	log.Println("Registering agent with server...")
	if err := registerAndWaitForApproval(cfg.APIKey, cfg.ServerHost, cfg.GRPCURL); err != nil {
		log.Fatalf("Registration failed: %v", err)
	}
	log.Println("✅ Agent approved! Starting monitoring...")
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("⚠️  Failed to remove memlock: %v", err)
	}
	ebpfRes, err := LoadAndAttacheBPF()
	if err != nil {
		log.Printf("Failed to load eBPF objects: %v", err)
		log.Println("\n⚠️  eBPF loading failed. Possible causes:")
		log.Println("  1. Not running as root (try: sudo)")
		log.Println("  2. Missing kernel capabilities (need: CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN, CAP_SYS_RESOURCE)")
		log.Println("  3. eBPF disabled in kernel (check: /proc/sys/kernel/unprivileged_bpf_disabled)")
		log.Println("\nTo check eBPF status:")
		log.Println("  cat /proc/sys/kernel/unprivileged_bpf_disabled")
		log.Println("\nTo enable eBPF (as root):")
		log.Println("  echo 0 | sudo tee /proc/sys/kernel/unprivileged_bpf_disabled")
		log.Fatal("\nAgent cannot run without eBPF support.")
	}
	defer ebpfRes.Close()
	SetupBandwidthTracking(ebpfRes)
	printBanner(cfg)
	rd, err := ringbuf.NewReader(ebpfRes.Objects.Events)
	if err != nil {
		log.Fatalf("Failed to open ringbuf: %v", err)
	}
	defer rd.Close()

	// Initialize remediation (hybrid: XDP + iptables)
	var remediator *remediation.HybridRemediator
	if cfg.EnableRemediation {
		remediator = remediation.NewHybridRemediator(remediation.HybridConfig{
			EnableXDP:     cfg.EnableXDP,
			InterfaceName: cfg.InterfaceName,
		})
		if err := remediator.Setup(); err != nil {
			log.Printf("❌ Remediation setup failed: %v", err)
			log.Println("\nTo install required dependencies:")
			log.Println("  Debian/Ubuntu: sudo apt-get install ipset iptables")
			log.Println("  RHEL/CentOS:   sudo yum install ipset iptables")
			log.Println("\nOr run without remediation:")
			log.Printf("  sudo kerneleye-agent -server \"%s\" -apikey \"...\"", cfg.ServerHost)
			os.Exit(1)
		}
		defer remediator.Teardown()
		if remediator.IsXDPEnabled() {
			log.Printf("🛡️  Remediation enabled: XDP (%s) + iptables", remediator.XDPMode())
		} else {
			log.Println("🛡️  Remediation enabled: iptables only")
		}
	} else {
		log.Println("ℹ️  Remediation disabled (use -enable-remediation to enable)")
	}

	// Initialize scoring engine
	scorer := scoring.NewThreatScorer()

	// Initialize auto-blocker (enabled when remediation is enabled)
	var autoBlocker *remediation.AutoBlocker
	if cfg.EnableRemediation && remediator != nil {
		var err error
		autoBlocker, err = remediation.NewAutoBlocker(cfg.AutoBlockConfig, scorer, remediator.GetIPSetRemediator())
		if err != nil {
			log.Printf("❌ Auto-blocker setup failed: %v", err)
			os.Exit(1)
		}
		log.Printf("🎯 Auto-blocker enabled (threshold: %d)", cfg.AutoBlockConfig.BlockThreshold)
	}

	analyzer := remediation.NewAnalyzer(remediation.DefaultAnalyzerConfig())
	// Start cleanup routine with a cancellable context for graceful shutdown
	analyzerCtx, analyzerCancel := context.WithCancel(context.Background())
	defer analyzerCancel()
	analyzer.CleanupRoutine(analyzerCtx, 5*time.Minute)

	aggregator, err := NewAggregator(cfg.APIKey, cfg.ServerHost, cfg.GRPCURL, remediator, analyzer, autoBlocker, scorer)
	if err != nil {
		log.Fatalf("Failed to create aggregator: %v", err)
	}
	defer aggregator.Close()

	// Wire the block callback to report blocked IPs via gRPC
	if remediator != nil {
		remediator.OnBlock = aggregator.ReportBlockedIP
	}

	// Initialize block command client to receive commands from backend
	// Pass the shared gRPC connection from aggregator
	blockCmdClient, err := NewBlockCommandClient(aggregator.GetGRPCConn(), cfg.APIKey, aggregator.ServerID(),
		// OnBlock callback - use remediator directly
		func(ip string, duration time.Duration, reason string) error {
			if remediator == nil {
				return nil
			}
			parsedIP := net.ParseIP(ip)
			if parsedIP == nil {
				return fmt.Errorf("invalid IP: %s", ip)
			}
			if err := remediator.Block(parsedIP, duration); err != nil {
				return fmt.Errorf("block failed: %w", err)
			}
			// Report to backend
			aggregator.ReportBlockedIP(parsedIP, remediation.ActionBlock, reason, duration)
			return nil
		},
		// OnUnblock callback
		func(ip string, reason string) error {
			if remediator == nil {
				return nil
			}
			parsedIP := net.ParseIP(ip)
			if parsedIP == nil {
				return fmt.Errorf("invalid IP: %s", ip)
			}
			return remediator.Unblock(parsedIP)
		},
	)
	if err != nil {
		log.Printf("⚠️  Block command client setup failed: %v (backend blocking will not be available)", err)
	} else {
		// Start receiving block commands from backend
		if err := blockCmdClient.Start(context.Background()); err != nil {
			log.Printf("⚠️  Failed to start block command client: %v", err)
		} else {
			aggregator.SetBlockCommandClient(blockCmdClient)
			log.Printf("📡 Block command client connected to backend")

			// Sync block list from backend for state reconciliation
			if err := blockCmdClient.SyncBlockList(context.Background()); err != nil {
				log.Printf("⚠️  Failed to sync block list: %v", err)
			}
		}
	}

	aggregator.StartFlushTimer(10 * time.Second)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go handleShutdown(sig, aggregator, rd, remediator, analyzerCancel)
	runEventLoop(rd, aggregator)
}

func handleShutdown(sig chan os.Signal, agg *Aggregator, rd *ringbuf.Reader, rem *remediation.HybridRemediator, cancelAnalyzer context.CancelFunc) {
	select {
	case <-sig:
		log.Println("\nShutdown signal, flushing...")
	case <-agg.stopChan:
		log.Println("\nServer deleted, shutting down...")
	}
	cancelAnalyzer() // Stop the analyzer cleanup goroutine
	agg.Close()      // This will flush and cleanup
	rd.Close()
	if rem != nil {
		rem.Teardown()
	}
	os.Exit(0)
}

func runEventLoop(rd *ringbuf.Reader, agg *Aggregator) {
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		var event Event
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			continue
		}

		if err := validateEvent(&event); err != nil {
			// log.Printf("Dropping malformed event: %v", err)
			continue
		}
		agg.ProcessEvent(event)
	}
}

func validateEvent(e *Event) error {
	if e.Saddr == 0 {
		return errors.New("missing source IP")
	}
	if e.Lport == 0 {
		return errors.New("missing port")
	}
	return nil
}

// printVersion displays version information
func printVersion() {
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║          KernelEye Agent - Version Information           ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
	fmt.Printf("  Version:    %s\n", Version)
	fmt.Printf("  Git Commit: %s\n", GitCommit)
	fmt.Printf("  Git Branch: %s\n", GitBranch)
	fmt.Printf("  Build Date: %s\n", BuildDate)
	fmt.Printf("  Built By:   %s@%s\n", BuildUser, BuildHost)
	fmt.Printf("  Go Version: %s\n", GoVersion)
}
