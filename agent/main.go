package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
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

	cfg := parseConfig()

	// Initialize zap logger BEFORE any logging
	debug := os.Getenv("KERNELEYE_DEBUG") == "true"
	if err := initLogger(debug); err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Failed to initialize logger: %v\n", err)
	}
	defer SyncLogger()

	// Print banner immediately to show version on startup
	printBanner(cfg)

	if cfg.APIKey == "" {
		Logger.Fatal("KERNELEYE_API_KEY is required.")
	}
	Logger.Info("Registering agent with server...")
	if err := registerAndWaitForApproval(cfg.APIKey, cfg.ServerHost, cfg.GRPCURL); err != nil {
		Logger.Fatalf("Registration failed: %v", err)
	}
	Logger.Info("✅ Agent approved! Starting monitoring...")
	if err := rlimit.RemoveMemlock(); err != nil {
		Logger.Warnf("⚠️  Failed to remove memlock: %v", err)
	}
	ebpfRes, err := LoadAndAttacheBPF()
	if err != nil {
		Logger.Errorf("Failed to load eBPF objects: %v", err)
		Logger.Info("\n⚠️  eBPF loading failed. Possible causes:")
		Logger.Info("  1. Not running as root (try: sudo)")
		Logger.Info("  2. Missing kernel capabilities (need: CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN, CAP_SYS_RESOURCE)")
		Logger.Info("  3. eBPF disabled in kernel (check: /proc/sys/kernel/unprivileged_bpf_disabled)")
		Logger.Info("\nTo check eBPF status:")
		Logger.Info("  cat /proc/sys/kernel/unprivileged_bpf_disabled")
		Logger.Info("\nTo enable eBPF (as root):")
		Logger.Info("  echo 0 | sudo tee /proc/sys/kernel/unprivileged_bpf_disabled")
		Logger.Fatal("\nAgent cannot run without eBPF support.")
	}
	defer ebpfRes.Close()
	SetupBandwidthTracking(ebpfRes)
	printBanner(cfg)
	rd, err := ringbuf.NewReader(ebpfRes.Objects.Events)
	if err != nil {
		Logger.Fatalf("Failed to open ringbuf: %v", err)
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
			Logger.Errorf("❌ Remediation setup failed: %v", err)
			Logger.Info("\nTo install required dependencies:")
			Logger.Info("  Debian/Ubuntu: sudo apt-get install ipset iptables")
			Logger.Info("  RHEL/CentOS:   sudo yum install ipset iptables")
			Logger.Info("\nOr run without remediation:")
			Logger.Infof("  sudo kerneleye-agent -server \"%s\" -apikey \"...\"", cfg.ServerHost)
			os.Exit(1)
		}
		defer remediator.Teardown()
		if remediator.IsXDPEnabled() {
			Logger.Infof("🛡️  Remediation enabled: XDP (%s) + iptables", remediator.XDPMode())
		} else {
			Logger.Info("🛡️  Remediation enabled: iptables only")
		}
	} else {
		Logger.Info("ℹ️  Remediation disabled (use -enable-remediation to enable)")
	}

	// Initialize scoring engine
	scorer := scoring.NewThreatScorer()

	// Initialize auto-blocker (enabled when remediation is enabled)
	var autoBlocker *remediation.AutoBlocker
	if cfg.EnableRemediation && remediator != nil {
		var err error
		autoBlocker, err = remediation.NewAutoBlocker(cfg.AutoBlockConfig, scorer, remediator.GetIPSetRemediator())
		if err != nil {
			Logger.Errorf("❌ Auto-blocker setup failed: %v", err)
			os.Exit(1)
		}
		Logger.Infof("🎯 Auto-blocker enabled (threshold: %d)", cfg.AutoBlockConfig.BlockThreshold)
	}

	analyzer := remediation.NewAnalyzer(remediation.DefaultAnalyzerConfig())
	// Start cleanup routine with a cancellable context for graceful shutdown
	analyzerCtx, analyzerCancel := context.WithCancel(context.Background())
	defer analyzerCancel()
	analyzer.CleanupRoutine(analyzerCtx, 5*time.Minute)

	aggregator, err := NewAggregator(cfg.APIKey, cfg.ServerHost, cfg.GRPCURL, remediator, analyzer, autoBlocker, scorer)
	if err != nil {
		Logger.Fatalf("Failed to create aggregator: %v", err)
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
		Logger.Warnf("⚠️  Block command client setup failed: %v (backend blocking will not be available)", err)
	} else {
		// Start receiving block commands from backend
		if err := blockCmdClient.Start(context.Background()); err != nil {
			Logger.Warnf("⚠️  Failed to start block command client: %v", err)
		} else {
			aggregator.SetBlockCommandClient(blockCmdClient)
			Logger.Info("📡 Block command client connected to backend")

			// Sync block list from backend for state reconciliation
			if err := blockCmdClient.SyncBlockList(context.Background()); err != nil {
				Logger.Warnf("⚠️  Failed to sync block list: %v", err)
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
		Logger.Info("\nShutdown signal, flushing...")
	case <-agg.stopChan:
		Logger.Info("\nServer deleted, shutting down...")
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
