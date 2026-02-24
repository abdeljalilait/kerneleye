package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"time"
)

// getBootTime reads the system boot time from /proc/stat.
// eBPF's bpf_ktime_get_ns() returns nanoseconds since boot (monotonic clock).
// To convert to wall clock: bootTime + time.Duration(ebpfTimestamp).
// Falls back to time.Now() on error (timestamps will be approximate).
func getBootTime() time.Time {
	f, err := os.Open("/proc/stat")
	if err != nil {
		Logger.Warnf("⚠️  Cannot read /proc/stat for boot time: %v (timestamps will be approximate)", err)
		return time.Now()
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "btime ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				btime, err := strconv.ParseInt(fields[1], 10, 64)
				if err == nil {
					return time.Unix(btime, 0)
				}
			}
		}
	}

	Logger.Warn("⚠️  Could not find btime in /proc/stat (timestamps will be approximate)")
	return time.Now()
}
