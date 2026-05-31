// SPDX-License-Identifier: AGPL-3.0-only

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

	// -list-blocked: print current ipset state and exit (no backend connection needed)
	if cfg.ListBlocked {
		listBlockedAndExit()
	}

	// -clear-data: wipe all local SQLite stores and exit
	if cfg.ClearData {
		clearDataAndExit()
	}

	// -flush-blocklists: flush ipset and XDP kernel structures and exit
	if cfg.FlushBlocklists {
		flushBlocklistsAndExit()
	}

	// Print banner immediately to show version on startup
	printBanner(cfg)

	if cfg.APIKey == "" {
		Logger.Fatal("KERNELEYE_API_KEY is required.")
	}
	tlsCfg := cfg.ToTLSTransportConfig()

	// Read-only mode: override remediation to disable all blocking.
	// The agent still monitors and reports, but never modifies kernel state.
	if cfg.ReadOnly {
		cfg.EnableRemediation = false
		cfg.EnableXDP = false
		Logger.Info("🛡️  Read-only mode: agent will monitor and report, but never block")
	}

	// Enforce command signing when remediation is enabled.
	// Unsigned block/unblock/rate-limit commands are a critical security gap.
	if cfg.EnableRemediation {
		if os.Getenv("CMD_SIGNING_KEY") == "" {
			Logger.Fatal("CMD_SIGNING_KEY must be set when remediation is enabled. " +
				"Generate one with: openssl rand -base64 32. " +
				"Set the same key on both agent and backend.")
		}
	}

	// Enforce TLS verification when not in insecure mode.
	// Plaintext gRPC exposes all telemetry metadata to network sniffing.
	if cfg.TLSInsecure && cfg.TLSCAFile == "" {
		Logger.Warn("⚠️  INSECURE MODE: gRPC traffic is plaintext and unauthenticated. " +
			"Telemetry metadata (IPs, ports, processes) is visible to anyone on the network. " +
			"Set KERNELEYE_TLS_CA_FILE to verify the backend certificate.")
	}

	Logger.Info("Registering agent with server...")
	if err := registerAndWaitForApproval(cfg.APIKey, cfg.ServerHost, cfg.GRPCURL, tlsCfg); err != nil {
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

		// Register XDP map snapshots for periodic integrity verification
		if xdpRem := remediator.GetXDPRemediator(); xdpRem != nil {
			RegisterMapSnapshots(xdpRem.GetMapSnapshots())
		}

		if cfg.EnableRemediation {
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

	aggregator, err := NewAggregator(cfg.APIKey, cfg.ServerHost, cfg.GRPCURL, Version, tlsCfg, remediator, analyzer, autoBlocker, scorer)
	if err != nil {
		Logger.Fatalf("Failed to create aggregator: %v", err)
	}
	// NOTE: aggregator.Close() is intentionally NOT deferred here.
	// handleShutdown is the single authoritative shutdown path and calls agg.Close().
	// A deferred close would race with handleShutdown after rd.Close() unblocks runEventLoop,
	// causing a double-close with double-flush and a second call to remediator.Teardown().

	// Context for block command client lifetime.
	// Cancelled at the very start of shutdown so gRPC streams terminate immediately,
	// preventing grpcConn.Close() from waiting on orphaned stream.Recv() goroutines.
	blockCtx, cancelBlock := context.WithCancel(context.Background())

	// Wire the block callback to report blocked IPs via gRPC
	if remediator != nil {
		remediator.OnBlock = func(ip net.IP, action remediation.Action, reason string, duration time.Duration) {
			// Look up the primary targeted port for this IP from live stats.
			// This gives "Service Targeted" / port context in the blocked-IPs table.
			port, proto, procName := aggregator.GetPrimaryPortForIP(ip.String())
			if port > 0 {
				svcName := resolveAgentService(procName, port, proto)
				aggregator.ReportBlockedIPWithContext(ip, action, reason, duration, port, proto, svcName)
			} else {
				aggregator.ReportBlockedIP(ip, action, reason, duration)
			}
		}

		// Wire the blocked packet callback to report XDP blocked packets via gRPC
		remediator.OnBlockedPacket = aggregator.ReportBlockedPacket

		// Start the XDP blocked packet reader if XDP is enabled
		if remediator.IsXDPEnabled() {
			if err := remediator.StartBlockedPacketReader(); err != nil {
				Logger.Warnf("⚠️  Failed to start XDP blocked packet reader: %v", err)
			} else {
				Logger.Info("📡 XDP blocked packet reader started")
			}
		}
	}

	if remediator != nil {
		// Initialize block command client to receive commands from backend.
		// Only enable this stream when remediation is active.
		blockCmdClient, err := NewBlockCommandClient(aggregator.GetGRPCConn(), cfg.APIKey, aggregator.ServerID(),
			// OnBlock callback - use remediator directly
			func(ip string, duration time.Duration, reason string) error {
				if reason == "whitelist_removed" {
					aggregator.SetWhitelistIP(ip, false)
					return nil
				}
				if aggregator.IsWhitelistedIPString(ip) {
					return nil
				}
				parsedIP := net.ParseIP(ip)
				if parsedIP == nil {
					return fmt.Errorf("invalid IP: %s", ip)
				}
				// Check if already blocked to avoid duplicate reporting
				if remediator.IsBlocked(parsedIP) {
					return nil
				}
				if err := remediator.Block(parsedIP, duration); err != nil {
					return fmt.Errorf("block failed: %w", err)
				}
				// Reporting is handled by remediator.OnBlock callback above
				return nil
			},
			// OnUnblock callback
			func(ip string, blockType remediation.BlockType, reason string) error {
				switch reason {
				case "whitelisted":
					aggregator.SetWhitelistIP(ip, true)
				case "whitelist_removed":
					aggregator.SetWhitelistIP(ip, false)
				}
				parsedIP := net.ParseIP(ip)
				if parsedIP == nil {
					return fmt.Errorf("invalid IP: %s", ip)
				}
				return remediator.Unblock(parsedIP, blockType)
			},
		)
		if err != nil {
			Logger.Warnf("⚠️  Block command client setup failed: %v (backend blocking will not be available)", err)
		} else {
			// Wire rate-limit callback so RATE_LIMIT commands route to the kernel
			// ipset rate-limit set rather than the hard blocklist.
			blockCmdClient.SetOnRateLimit(func(ip string, duration time.Duration, reason string) error {
				if reason == "whitelist_removed" {
					aggregator.SetWhitelistIP(ip, false)
					return nil
				}
				if aggregator.IsWhitelistedIPString(ip) {
					return nil
				}
				parsedIP := net.ParseIP(ip)
				if parsedIP == nil {
					return fmt.Errorf("invalid IP: %s", ip)
				}
				if err := remediator.RateLimit(parsedIP, duration); err != nil {
					return fmt.Errorf("rate-limit failed: %w", err)
				}
				return nil
			})

			// Start receiving block commands from backend
			if err := blockCmdClient.Start(blockCtx); err != nil {
				Logger.Warnf("⚠️  Failed to start block command client: %v", err)
			} else {
				aggregator.SetBlockCommandClient(blockCmdClient)
				Logger.Info("📡 Block command client connected to backend")

				// Sync block list from backend for state reconciliation
				if err := blockCmdClient.SyncBlockList(blockCtx); err != nil {
					Logger.Warnf("⚠️  Failed to sync block list: %v", err)
				}

				// Report any IPs already in ipset/XDP (from previous run) to the backend
				// so the dashboard reflects actual kernel-level state immediately.
				// Both sources are deduplicated in a single pass (XDP preferred).
				go aggregator.SyncBlocklistsToBackend(remediator.GetIPSetRemediator(), remediator.GetXDPRemediator())

				// Start periodic reconcile every 1 minute.
				// The goroutine exits when blockCtx is cancelled (at shutdown start).
				go func() {
					ticker := time.NewTicker(1 * time.Minute)
					defer ticker.Stop()
					for {
						select {
						case <-blockCtx.Done():
							return
						case <-ticker.C:
							if blockCmdClient.IsConnected() {
								if err := blockCmdClient.Reconcile(blockCtx); err != nil && blockCtx.Err() == nil {
									Logger.Warnf("⚠️  Failed to reconcile block list: %v", err)
								}
							}
						}
					}
				}()
			}
		}
	} else {
		Logger.Info("ℹ️  Block command stream disabled because remediation is not enabled")
	}

	aggregator.StartFlushTimer(10 * time.Second)

	// Start periodic eBPF map integrity verification and attestation (Phase 3-4)
	go func() {
		// Run an initial check after startup
		time.Sleep(15 * time.Second)
		verifyMapIntegrity()

		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-blockCtx.Done():
				return
			case <-ticker.C:
				verifyMapIntegrity()
				// Send integrity report to backend
				conn := aggregator.GetGRPCConn()
				if conn != nil {
					if err := sendIntegrityReport(conn, cfg.APIKey, aggregator.ServerID(), Version); err != nil {
						Logger.Debugf("[Integrity] Failed to send integrity report: %v", err)
					}
				}
			}
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go handleShutdown(sig, aggregator, rd, remediator, analyzerCancel, cancelBlock)
	runEventLoop(rd, aggregator)
}

func handleShutdown(sig chan os.Signal, agg *Aggregator, rd *ringbuf.Reader, rem *remediation.HybridRemediator, cancelAnalyzer context.CancelFunc, cancelBlock context.CancelFunc) {
	select {
	case <-sig:
		Logger.Info("\nShutdown signal, flushing...")
	case <-agg.stopChan:
		Logger.Info("\nServer deleted, shutting down...")
	}
	// Cancel the block client context first — this immediately terminates any
	// in-flight gRPC streams (stream.Recv goroutines) and stops the reconcile
	// goroutine, so grpcConn.Close() inside agg.Close() is not delayed.
	cancelBlock()
	cancelAnalyzer() // Stop the analyzer cleanup goroutine
	Logger.Debug("[Shutdown] Contexts cancelled")

	agg.Close() // This will flush and cleanup
	Logger.Debug("[Shutdown] Aggregator closed")

	rd.Close()
	Logger.Debug("[Shutdown] Ringbuf reader closed")

	if rem != nil {
		Logger.Debug("[Shutdown] Tearing down remediator...")
		rem.Teardown()
		Logger.Debug("[Shutdown] Remediator torn down")
	}

	CloseAuditLog()
	Logger.Info("[Shutdown] Complete, exiting...")
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
			Logger.Debugf("Dropping malformed event: %v", err)
			continue
		}

		// Debug: log all events with their flags
		Logger.Debugf("Event received: saddr=%v, family=%d, protocol=%d, flags=0x%02x, dir=%d, lport=%d, rport=%d",
			event.Saddr[:4], event.Family, event.Protocol, event.Flags, event.Direction, event.Lport, event.Rport)

		agg.ProcessEvent(event)
	}
}

func validateEvent(e *Event) error {
	// Protocol: only TCP(6), UDP(17), and ICMP(1) are valid
	if e.Protocol != 6 && e.Protocol != 17 && e.Protocol != 1 {
		return errors.New("invalid protocol")
	}
	// Family: only AF_INET(2) and AF_INET6(10)
	if e.Family != 2 && e.Family != 10 {
		return errors.New("invalid address family")
	}
	// Direction: 0=inbound, 1=outbound
	if e.Direction > 1 {
		return errors.New("invalid direction")
	}
	// Source IP must be non-zero (first 4 bytes for IPv4)
	if e.Saddr[0] == 0 && e.Saddr[1] == 0 && e.Saddr[2] == 0 && e.Saddr[3] == 0 {
		return errors.New("missing source IP")
	}
	// At least one port must be non-zero
	if e.Lport == 0 && e.Rport == 0 {
		return errors.New("missing ports")
	}
	// Timestamp sanity: not zero and not more than 1 hour into the future
	if e.Timestamp == 0 {
		return errors.New("missing timestamp")
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

// flushBlocklistsAndExit tears down all ipset and XDP blocklists (kernel
// structures), prints a summary, then exits. Does NOT touch SQLite stores.
// Safe to run while the agent is stopped.
func flushBlocklistsAndExit() {
	ipsetOK := true
	xdpOK := true

	// --- ipset ---
	ipsetRem := remediation.NewIPSetRemediator()
	if err := ipsetRem.Teardown(); err != nil {
		fmt.Fprintf(os.Stderr, "❌  ipset flush failed: %v\n", err)
		ipsetOK = false
	} else {
		fmt.Println("✅  Flushed ipset blocklists (kernel_eye_block, kernel_eye_ratelimit, CIDR sets, iptables chain)")
	}

	// --- XDP BPF maps ---
	xdpRem := remediation.NewXDPRemediator("")
	if err := xdpRem.FlushBlocklistMaps(); err != nil {
		fmt.Fprintf(os.Stderr, "❌  XDP flush failed: %v\n", err)
		xdpOK = false
	} else {
		fmt.Println("✅  Flushed XDP blocklists (xdp_blocklist, xdp_blocklist_v6 BPF maps)")
	}

	if !ipsetOK || !xdpOK {
		os.Exit(1)
	}
	os.Exit(0)
}

// clearDataAndExit deletes all local data stores used by the agent, prints a
// summary of what was removed, then exits. Safe to run while the agent is stopped.
func clearDataAndExit() {
	stores := []struct {
		label string
		path  string
	}{
		{"history DB (default)", defaultHistoryDBPath},
		{"history DB (fallback)", fallbackHistoryDBPath},
		{"pending DB (default)", defaultDBPath},
		{"pending DB (fallback)", fallbackDBPath},
	}

	removed := 0
	for _, s := range stores {
		if _, err := os.Stat(s.path); os.IsNotExist(err) {
			continue
		}
		if err := os.Remove(s.path); err != nil {
			fmt.Fprintf(os.Stderr, "❌  Failed to remove %s (%s): %v\n", s.label, s.path, err)
		} else {
			fmt.Printf("🗑️   Removed %s: %s\n", s.label, s.path)
			removed++
		}
		// Also remove WAL and SHM sidecar files if present
		for _, suf := range []string{"-wal", "-shm"} {
			_ = os.Remove(s.path + suf)
		}
	}

	if removed == 0 {
		fmt.Println("No local data stores found.")
	} else {
		fmt.Printf("✅  Cleared %d data store(s).\n", removed)
	}
	os.Exit(0)
}

// listBlockedAndExit reads the kernel_eye ipsets and (if available) the XDP BPF
// maps directly, prints a summary, then exits. No backend connection needed.
func listBlockedAndExit() {
	// --- ipset ---
	ipsetRem := remediation.NewIPSetRemediator()
	ipsetEntries, ipsetErr := ipsetRem.ListCurrentlyBlocked()
	if ipsetErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not read ipset: %v\n", ipsetErr)
	}

	// --- XDP BPF maps (pinned at /sys/fs/bpf/kerneleye) ---
	xdpRem := remediation.NewXDPRemediator("")
	xdpEntries, xdpErr := xdpRem.ListCurrentlyBlocked()
	if xdpErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not read XDP maps (not loaded?): %v\n", xdpErr)
	}

	total := len(ipsetEntries) + len(xdpEntries)
	if total == 0 {
		fmt.Println("No IPs currently blocked (ipset empty, XDP maps empty or not loaded).")
		os.Exit(0)
	}

	fmt.Printf("KernelEye blocked IPs (%d total)\n", total)
	fmt.Println("══════════════════════════════════════")

	// ipset section
	var blocked, ratelimited []string
	for _, e := range ipsetEntries {
		if e.BlockType == remediation.BlockTypeRateLimit {
			ratelimited = append(ratelimited, e.IP.String())
		} else {
			blocked = append(blocked, e.IP.String())
		}
	}
	if len(blocked) > 0 {
		fmt.Printf("\n🚫 ipset blocked (%d) — kernel_eye_block / kernel_eye_block_v6:\n", len(blocked))
		for _, ip := range blocked {
			fmt.Printf("   %s\n", ip)
		}
	}
	if len(ratelimited) > 0 {
		fmt.Printf("\n⏱  ipset rate-limited (%d) — kernel_eye_ratelimit / kernel_eye_ratelimit_v6:\n", len(ratelimited))
		for _, ip := range ratelimited {
			fmt.Printf("   %s\n", ip)
		}
	}

	// XDP section
	if len(xdpEntries) > 0 {
		fmt.Printf("\n⚡ XDP blocked (%d) — xdp_blocklist / xdp_blocklist_v6:\n", len(xdpEntries))
		for _, e := range xdpEntries {
			fmt.Printf("   %s\n", e.IP.String())
		}
	}

	os.Exit(0)
}
