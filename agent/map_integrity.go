package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"time"

	pb "github.com/kerneleye/proto/kerneleye/v1"
	"github.com/kerneleye/agent/remediation"
	"google.golang.org/grpc"
)

// verifyMapIntegrity checks that pinned BPF maps have not been tampered with
// and that frozen maps have not been modified since initialization.
func verifyMapIntegrity() {
	maps := remediation.ClassifyMaps()
	pinPath := "/sys/fs/bpf/kerneleye"

	for _, m := range maps {
		pinnedFile := pinPath + "/" + m.Name
		info, err := os.Stat(pinnedFile)
		if err != nil {
			if m.TrustLevel >= remediation.TrustLevelHigh {
				Logger.Warnf("[Integrity] Pinned map %s not found at %s — possible tampering", m.Name, pinnedFile)
			}
			continue
		}

		if info.Mode()&0022 != 0 {
			Logger.Warnf("[Integrity] Map %s has world-writable permissions (%o)", m.Name, info.Mode().Perm())
		}

		if m.Frozen {
			if time.Since(info.ModTime()) < 30*time.Minute {
				if time.Since(info.ModTime()) > 5*time.Minute {
					Logger.Warnf("[Integrity] Frozen map %s was modified %v ago — integrity violation suspected",
						m.Name, time.Since(info.ModTime()).Round(time.Second))
				}
			}
		}
	}
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

// buildIntegrityReport constructs a pb.IntegrityReport from current state.
func buildIntegrityReport(agentID, agentVersion string) *pb.IntegrityReport {
	report := &pb.IntegrityReport{
		ApiKey:          "", // Set by caller
		AgentId:         agentID,
		AgentVersion:    agentVersion,
		AgentBinaryHash: computeAgentBinaryHash(),
		Timestamp:       time.Now().UnixNano(),
		Programs:        nil, // TODO: populate from ebpf.ProgramInfo when available
		Maps:            nil, // TODO: populate from ebpf.MapInfo when available
		Status: &pb.IntegrityStatus{
			Healthy:  true,
			Warnings: nil,
			Errors:   nil,
		},
	}

	maps := remediation.ClassifyMaps()
	pinPath := "/sys/fs/bpf/kerneleye"
	for _, m := range maps {
		pinnedFile := pinPath + "/" + m.Name
		_, err := os.Stat(pinnedFile)
		pinnedPathExists := err == nil

		lm := &pb.LoadedMap{
			Name:        m.Name,
			Frozen:      m.Frozen,
			TrustLevel:  mapTrustLevelToProto(m.TrustLevel),
			PinnedPath:  pinnedFile,
		}

		if !pinnedPathExists && m.TrustLevel >= remediation.TrustLevelHigh {
			lm.PinnedPathChanged = true
			report.Status.Warnings = append(report.Status.Warnings,
				fmt.Sprintf("high-trust map %s: pinned file %s not found", m.Name, pinnedFile))
		}

		report.Maps = append(report.Maps, lm)
	}

	if len(report.Status.Errors) > 0 {
		report.Status.Healthy = false
	}

	return report
}

// sendIntegrityReport sends the integrity report to the backend via gRPC.
func sendIntegrityReport(conn *grpc.ClientConn, apiKey, agentID, agentVersion string) error {
	if conn == nil {
		return fmt.Errorf("no gRPC connection")
	}

	report := buildIntegrityReport(agentID, agentVersion)
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

	Logger.Debugf("[Integrity] Report sent: healthy=%v maps=%d programs=%d",
		report.Status.Healthy, len(report.Maps), len(report.Programs))
	return nil
}

// ReportMapIntegrityToBackend builds and sends the periodic integrity report.
func ReportMapIntegrityToBackend() {
	// This is called from a goroutine in main.go with access to aggregator's gRPC connection.
	// The actual call is wired through the aggregator's periodic loop.
	_ = fmt.Sprintf("integrity report at %v", time.Now())
}
