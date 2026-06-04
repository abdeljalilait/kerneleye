package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	pb "github.com/kerneleye/proto/kerneleye/v1"
	"github.com/kerneleye/agent/remediation"
	"google.golang.org/grpc"
)

// verifyMapIntegrity checks pinned BPF maps against their load-time snapshots
// using real kernel BPF state (map IDs, content hashes, frozen status).
// Returns warnings detected during verification for inclusion in the integrity report.
func verifyMapIntegrity() []string {
	var warnings []string
	maps := remediation.ClassifyMaps()

	for _, cls := range maps {
		// Only check maps with high trust level and pinned paths
		if cls.TrustLevel < remediation.TrustLevelHigh {
			continue
		}

		snap, ok := mapStateSnapshots[cls.Name]
		if !ok {
			continue
		}

		w := remediation.VerifyMapSnapshot(snap.Name, snap)
		for _, w := range w {
			Logger.Warnf("[Integrity] %s", w)
		}
		warnings = append(warnings, w...)
	}
	return warnings
}

// mapStateSnapshots is populated by the XDP remediator and traffic probe loader
// at startup. Keyed by map name.
var mapStateSnapshots = make(map[string]*remediation.MapStateSnapshot)

// RegisterMapSnapshots registers XDP map snapshots for integrity verification.
func RegisterMapSnapshots(snapshots map[string]*remediation.MapStateSnapshot) {
	for name, snap := range snapshots {
		mapStateSnapshots[name] = snap
	}
	Logger.Infof("[Integrity] Registered %d map snapshots for integrity verification", len(snapshots))
}

// captureProbeMapSnapshots records load-time identity for traffic-probe maps.
// These maps are dynamic telemetry maps, so we only capture ID and pinned-path
// (no content hash) — they change legitimately during normal operation.
func captureProbeMapSnapshots(objects *bpfObjects) map[string]*remediation.MapStateSnapshot {
	pinPath := probeMapPinPath
	snapshots := make(map[string]*remediation.MapStateSnapshot)

	maps := []struct {
		m    *ebpf.Map
		name string
	}{
		{objects.DebugCounters, "debug_counters"},
		{objects.Events, "events"},
		{objects.GlobalRateLimiter, "global_rate_limiter"},
		{objects.IcmpCounters, "icmp_counters"},
		{objects.IpByteCounters, "ip_byte_counters"},
		{objects.IpByteCountersV6, "ip_byte_counters_v6"},
		{objects.IpPortBytes, "ip_port_bytes"},
		{objects.RateLimiter, "rate_limiter"},
		{objects.TcpSynTracker, "tcp_syn_tracker"},
		{objects.TcpSynTrackerV6, "tcp_syn_tracker_v6"},
	}

	for _, entry := range maps {
		if entry.m == nil {
			continue
		}
		info, err := entry.m.Info()
		if err != nil {
			Logger.Warnf("[Integrity] Failed to get map info for %s: %v", entry.name, err)
			continue
		}

		cls, _ := remediation.MapClassificationByName(entry.name)
		mapID, hasID := info.ID()
		if !hasID {
			mapID = 0
		}
		snap := &remediation.MapStateSnapshot{
			Name:       entry.name,
			MapID:      mapID,
			PinnedPath: filepath.Join(pinPath, entry.name),
			Frozen:     info.Frozen(),
			TrustLevel: cls.TrustLevel,
			CapturedAt: time.Now(),
		}
		snapshots[entry.name] = snap
		Logger.Debugf("[Integrity] Probe map snapshot: %s id=%d frozen=%v trust=%s",
			snap.Name, snap.MapID, snap.Frozen, snap.TrustLevel)
	}

	return snapshots
}

// computeAgentBinaryHash returns the SHA-256 hash of the agent's own binary.
func computeAgentBinaryHash() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h)
}

// mapTrustLevelToProto converts remediation.MapTrustLevel to pb.TrustLevel.
func mapTrustLevelToProto(level remediation.MapTrustLevel) pb.TrustLevel {
	switch level {
	case remediation.TrustLevelLow:
		return pb.TrustLevel_TRUST_LEVEL_LOW
	case remediation.TrustLevelMedium:
		return pb.TrustLevel_TRUST_LEVEL_MEDIUM
	case remediation.TrustLevelHigh:
		return pb.TrustLevel_TRUST_LEVEL_HIGH
	case remediation.TrustLevelVeryHigh:
		return pb.TrustLevel_TRUST_LEVEL_VERY_HIGH
	default:
		return pb.TrustLevel_TRUST_LEVEL_LOW
	}
}

// buildIntegrityReport constructs a pb.IntegrityReport from current state,
// populated with real BPF map info from loaded snapshots and runtime
// verification findings.
func buildIntegrityReport(agentID, agentVersion string, findings []string) *pb.IntegrityReport {
	healthy := true
	report := &pb.IntegrityReport{
		ApiKey:          "",
		AgentId:         agentID,
		AgentVersion:    agentVersion,
		AgentBinaryHash: computeAgentBinaryHash(),
		Timestamp:       time.Now().UnixNano(),
		Status: &pb.IntegrityStatus{
			Healthy:  true,
			Warnings: nil,
			Errors:   nil,
		},
	}

	// Fold runtime verification findings into the report
	if len(findings) > 0 {
		healthy = false
		report.Status.Warnings = append(report.Status.Warnings, findings...)
	}

	// Populate maps from load-time snapshots with kernel-verified data
	for name, snap := range mapStateSnapshots {
		cls, _ := remediation.MapClassificationByName(name)

		lm := &pb.LoadedMap{
			Name:       snap.Name,
			Id:         uint32(snap.MapID),
			PinnedPath: snap.PinnedPath,
			Frozen:     snap.Frozen,
			TrustLevel: mapTrustLevelToProto(snap.TrustLevel),
		}

		// Check if pinned file is still present at expected path
		if _, err := os.Stat(snap.PinnedPath); err != nil {
			lm.PinnedPathChanged = true
			report.Status.Warnings = append(report.Status.Warnings,
				fmt.Sprintf("map %s: pinned path %s not found", snap.Name, snap.PinnedPath))
		}

		// Verify frozen state for maps classified as frozen
		if cls.Frozen && !snap.Frozen {
			lm.ConfigHashChanged = true
			report.Status.Warnings = append(report.Status.Warnings,
				fmt.Sprintf("map %s: classified frozen but freeze not applied", snap.Name))
		}

		report.Maps = append(report.Maps, lm)
	}

	if len(report.Status.Errors) > 0 || !healthy {
		report.Status.Healthy = false
	}

	return report
}

// sendIntegrityReport sends the integrity report to the backend via gRPC.
func sendIntegrityReport(conn *grpc.ClientConn, apiKey, agentID, agentVersion string, findings []string) error {
	if conn == nil {
		return fmt.Errorf("no gRPC connection")
	}

	report := buildIntegrityReport(agentID, agentVersion, findings)
	report.ApiKey = apiKey
	report.Timestamp = time.Now().UnixNano()

	client := pb.NewIngestServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.ReportIntegrity(ctx, report)
	if err != nil {
		return fmt.Errorf("integrity report failed: %w", err)
	}

	if !resp.Acknowledged {
		Logger.Warnf("[Integrity] Backend did not acknowledge integrity report: %s", resp.Message)
	}

	Logger.Debugf("[Integrity] Report sent: healthy=%v maps=%d",
		report.Status.Healthy, len(report.Maps))
	return nil
}
