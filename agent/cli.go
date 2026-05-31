package main

import (
	"fmt"
	"os"

	"github.com/kerneleye/agent/remediation"
)

// CLI-only operations that print information and exit.
// These do not start the agent daemon or load eBPF programs.

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
		// Clean WAL/SHM sidecars regardless of main DB file presence
		for _, suf := range []string{"-wal", "-shm"} {
			_ = os.Remove(s.path + suf)
		}

		if _, err := os.Stat(s.path); os.IsNotExist(err) {
			continue
		}
		if err := os.Remove(s.path); err != nil {
			fmt.Fprintf(os.Stderr, "❌  Failed to remove %s (%s): %v\n", s.label, s.path, err)
		} else {
			fmt.Printf("🗑️   Removed %s: %s\n", s.label, s.path)
			removed++
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
