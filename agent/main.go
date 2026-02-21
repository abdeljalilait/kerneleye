package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/kerneleye/agent/remediation"
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

	// Handle daemon stop request
	if cfg.StopDaemon {
		if err := CheckAndStopDaemon(cfg.PIDFile); err != nil {
			log.Fatalf("Failed to stop daemon: %v", err)
		}
		log.Println("Daemon stopped")
		os.Exit(0)
	}

	// When daemon mode is requested without explicit log file, use default
	if cfg.Daemon && cfg.LogFile == "" {
		cfg.LogFile = DefaultLogFile
	}

	// Daemonize if requested (must happen before any resource setup)
	if cfg.Daemon {
		isChild, err := Daemonize(cfg.LogFile)
		if err != nil {
			log.Fatalf("Failed to daemonize: %v", err)
		}
		if !isChild {
			// Parent exits cleanly
			fmt.Printf("Daemon started (PID file: %s, log: %s)\n", cfg.PIDFile, cfg.LogFile)
			os.Exit(0)
		}
		// Child process continues as daemon
		if err := WritePIDFile(cfg.PIDFile); err != nil {
			log.Fatalf("Failed to write PID file: %v", err)
		}
		defer RemovePIDFile(cfg.PIDFile)
		// Log output is already redirected by Daemonize(), setup log package
		log.SetOutput(os.Stdout) // This will go to the redirected file
	} else {
		// Non-daemon mode: setup logging to file if specified
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
		log.Fatalf("Failed to remove memlock: %v", err)
	}
	ebpfRes, err := LoadAndAttacheBPF()
	if err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
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

	analyzer := remediation.NewAnalyzer(remediation.DefaultAnalyzerConfig())
	// Start cleanup routine with a cancellable context for graceful shutdown
	analyzerCtx, analyzerCancel := context.WithCancel(context.Background())
	defer analyzerCancel()
	analyzer.CleanupRoutine(analyzerCtx, 5*time.Minute)

	aggregator, err := NewAggregator(cfg.APIKey, cfg.ServerHost, cfg.GRPCURL, remediator, analyzer)
	if err != nil {
		log.Fatalf("Failed to create aggregator: %v", err)
	}
	defer aggregator.Close()

	// Wire the block callback to report blocked IPs via gRPC
	if remediator != nil {
		remediator.OnBlock = aggregator.ReportBlockedIP
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
