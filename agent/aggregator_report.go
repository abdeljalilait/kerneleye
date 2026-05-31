package main

import (
	"context"
	"net"
	"time"

	"github.com/kerneleye/agent/remediation"
	pb "github.com/kerneleye/proto/kerneleye/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Block reporting and block-list synchronization for the Aggregator.
// Handles agent-to-backend reporting of blocked IPs, blocked packets,
// and startup synchronization of local block state.

func (a *Aggregator) ReportBlockedPacket(ip string, port uint16, protocol uint8, reason uint8) {
	// Map protocol number to protobuf enum
	var proto pb.Protocol
	switch protocol {
	case 6:
		proto = pb.Protocol_PROTOCOL_TCP
	case 17:
		proto = pb.Protocol_PROTOCOL_UDP
	case 1:
		proto = pb.Protocol_PROTOCOL_ICMP
	default:
		proto = pb.Protocol_PROTOCOL_UNKNOWN
	}

	// Map reason to protobuf enum
	var blockReason pb.BlockReason
	switch reason {
	case 1:
		blockReason = pb.BlockReason_BLOCK_REASON_BLOCKLIST
	case 2:
		blockReason = pb.BlockReason_BLOCK_REASON_CIDR
	case 3:
		blockReason = pb.BlockReason_BLOCK_REASON_RATE_LIMIT
	default:
		blockReason = pb.BlockReason_BLOCK_REASON_UNKNOWN
	}

	req := &pb.BlockedPacketEvent{
		ApiKey:          a.apiKey,
		ServerId:        a.serverID,
		SourceIp:        ip,
		DestinationPort: uint32(port),
		Protocol:        proto,
		Reason:          blockReason,
		Timestamp:       timestamppb.New(time.Now()),
	}

	// Send asynchronously to avoid blocking the ring buffer reader
	go func() {
		a.grpcMu.RLock()
		client := a.grpcClient
		if client == nil {
			a.grpcMu.RUnlock()
			Logger.Warn("⚠️  gRPC client not initialized, cannot report blocked packet")
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := client.ReportBlockedPacket(ctx, req)
		a.grpcMu.RUnlock()
		cancel()

		if err != nil {
			Logger.Warnf("⚠️  Failed to report blocked packet from %s: %v", ip, err)
		} else {
			Logger.Debugf("📡 Reported blocked packet from %s:%d (reason: %d) to backend", ip, port, reason)
		}
	}()
}

// ReportBlockedIP sends a blocked IP event to the backend via gRPC
func (a *Aggregator) ReportBlockedIP(ip net.IP, action remediation.Action, reason string, duration time.Duration) {
	var blockAction pb.BlockAction
	switch action {
	case remediation.ActionBlock:
		blockAction = pb.BlockAction_BLOCK_ACTION_BLOCK
	case remediation.ActionRateLimit:
		blockAction = pb.BlockAction_BLOCK_ACTION_RATE_LIMIT
	default:
		blockAction = pb.BlockAction_BLOCK_ACTION_ALLOW
	}

	req := &pb.BlockedIPEvent{
		ApiKey:          a.apiKey,
		ServerId:        a.serverID,
		IpAddress:       ip.String(),
		Action:          blockAction,
		DurationSeconds: uint32(duration.Seconds()),
		Reason:          reason,
		AgentVersion:    a.agentVersion,
	}

	// Retry up to 3 times with exponential backoff
	var err error
	for attempt := range 3 {
		a.grpcMu.RLock()
		client := a.grpcClient
		if client == nil {
			a.grpcMu.RUnlock()
			Logger.Warn("⚠️  gRPC client not initialized, cannot report blocked IP")
			a.scheduleReconnect()
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err = client.ReportBlockedIP(ctx, req)
		a.grpcMu.RUnlock()
		cancel()
		if err == nil {
			Logger.Infof("📡 Reported blocked IP %s (%s) to backend", ip, action)
			return
		}
		Logger.Warnf("⚠️  Attempt %d/3 failed to report blocked IP %s: %v", attempt+1, ip, err)
		if attempt < 2 {
			time.Sleep(time.Duration(1<<attempt) * time.Second) // 1s, 2s backoff
		}
	}
	a.scheduleReconnect()
	Logger.Errorf("❌ Failed to report blocked IP %s after 3 attempts: %v", ip, err)
}

// SyncBlocklistsToBackend reports all currently-blocked IPs (ipset + XDP) to the
// backend exactly once per IP, deduplicating across both sources. XDP entries are
// preferred when an IP appears in both (XDP is the active enforcement layer).
// Called once on startup so IPs that survived a restart appear in the dashboard
// immediately without waiting for a new block event.
func (a *Aggregator) SyncBlocklistsToBackend(ipsetRem *remediation.IPSetRemediator, xdpRem *remediation.XDPRemediator) {
	reported := make(map[string]bool)
	now := time.Now()

	// --- XDP first (preferred source when active) ---
	if xdpRem != nil {
		entries, err := xdpRem.ListCurrentlyBlocked()
		if err != nil {
			Logger.Warnf("⚠️  SyncBlocklistsToBackend: failed to read XDP maps: %v", err)
		} else if len(entries) > 0 {
			Logger.Infof("📋 SyncBlocklistsToBackend: %d XDP-blocked IPs", len(entries))
			for _, e := range entries {
				ipStr := e.IP.String()
				if reported[ipStr] {
					continue
				}
				reported[ipStr] = true
				port, proto, procName := a.history.GetContext(ipStr, 0, now)
				if port > 0 {
					svcName := resolveAgentService(procName, port, proto)
					a.ReportBlockedIPWithContext(e.IP, remediation.ActionBlock, "xdp_block", 0, port, proto, svcName)
				} else {
					a.ReportBlockedIP(e.IP, remediation.ActionBlock, "xdp_block", 0)
				}
			}
		}
	}

	// --- ipset second (skip IPs already reported from XDP) ---
	if ipsetRem != nil {
		entries, err := ipsetRem.ListCurrentlyBlocked()
		if err != nil {
			Logger.Warnf("⚠️  SyncBlocklistsToBackend: failed to read ipset: %v", err)
		} else if len(entries) > 0 {
			Logger.Infof("📋 SyncBlocklistsToBackend: %d ipset-blocked IPs", len(entries))
			for _, e := range entries {
				ipStr := e.IP.String()
				if reported[ipStr] {
					continue
				}
				reported[ipStr] = true
				action := remediation.ActionBlock
				reason := "ipset_block"
				if e.BlockType == remediation.BlockTypeRateLimit {
					action = remediation.ActionRateLimit
					reason = "ipset_ratelimit"
				}
				port, proto, procName := a.history.GetContext(ipStr, 0, now)
				if port > 0 {
					svcName := resolveAgentService(procName, port, proto)
					a.ReportBlockedIPWithContext(e.IP, action, reason, 0, port, proto, svcName)
				} else {
					a.ReportBlockedIP(e.IP, action, reason, 0)
				}
			}
		}
	}

	Logger.Infof("✅ SyncBlocklistsToBackend: reported %d unique blocked IPs", len(reported))
}

// ReportBlockedIPWithContext sends a blocked IP event with port/protocol/service context
func (a *Aggregator) ReportBlockedIPWithContext(ip net.IP, action remediation.Action, reason string, duration time.Duration, targetPort uint16, protocol uint8, serviceName string) {
	var blockAction pb.BlockAction
	switch action {
	case remediation.ActionBlock:
		blockAction = pb.BlockAction_BLOCK_ACTION_BLOCK
	case remediation.ActionRateLimit:
		blockAction = pb.BlockAction_BLOCK_ACTION_RATE_LIMIT
	default:
		blockAction = pb.BlockAction_BLOCK_ACTION_ALLOW
	}

	// Convert protocol number to Protocol enum
	var proto pb.Protocol
	switch protocol {
	case 6:
		proto = pb.Protocol_PROTOCOL_TCP
	case 17:
		proto = pb.Protocol_PROTOCOL_UDP
	case 1:
		proto = pb.Protocol_PROTOCOL_ICMP
	default:
		proto = pb.Protocol_PROTOCOL_UNKNOWN
	}

	req := &pb.BlockedIPEvent{
		ApiKey:          a.apiKey,
		ServerId:        a.serverID,
		IpAddress:       ip.String(),
		Action:          blockAction,
		DurationSeconds: uint32(duration.Seconds()),
		Reason:          reason,
		TargetPort:      uint32(targetPort),
		Protocol:        proto,
		ServiceName:     serviceName,
		AgentVersion:    a.agentVersion,
	}

	// Retry up to 3 times with exponential backoff
	var err error
	for attempt := range 3 {
		a.grpcMu.RLock()
		client := a.grpcClient
		if client == nil {
			a.grpcMu.RUnlock()
			Logger.Warn("⚠️  gRPC client not initialized, cannot report blocked IP")
			a.scheduleReconnect()
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err = client.ReportBlockedIP(ctx, req)
		a.grpcMu.RUnlock()
		cancel()
		if err == nil {
			Logger.Infof("📡 Reported blocked IP %s (%s) to backend", ip, action)
			return
		}
		Logger.Warnf("⚠️  Attempt %d/3 failed to report blocked IP %s: %v", attempt+1, ip, err)
		if attempt < 2 {
			time.Sleep(time.Duration(1<<attempt) * time.Second) // 1s, 2s backoff
		}
	}
	a.scheduleReconnect()
	Logger.Errorf("❌ Failed to report blocked IP %s after 3 attempts: %v", ip, err)
}
