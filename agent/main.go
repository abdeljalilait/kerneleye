package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
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

	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	cfg := parseConfig()
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
			log.Printf("⚠️  Failed to setup remediation: %v", err)
			remediator = nil
		} else {
			defer remediator.Teardown()
			if remediator.IsXDPEnabled() {
				log.Printf("🛡️  Remediation enabled: XDP (%s) + iptables", remediator.XDPMode())
			} else {
				log.Println("🛡️  Remediation enabled: iptables only")
			}
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
