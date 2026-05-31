package main

import (
	"fmt"
	"time"

	"github.com/kerneleye/agent/remediation"
	pb "github.com/kerneleye/proto/kerneleye/v1"
	"github.com/kerneleye/shared/cmdsigning"
)

// Command verification and processing for the BlockCommandClient.
// verifyCommand checks HMAC signature, nonce freshness, and timestamp window.
// processCommand dispatches verified commands to the appropriate handler.

func (b *BlockCommandClient) verifyCommand(cmd *pb.BlockCommand) error {
	key := cmdsigning.Key()
	if key == "" {
		return fmt.Errorf("CMD_SIGNING_KEY is not configured — unsigned commands are rejected. " +
			"Set CMD_SIGNING_KEY env var on both agent and backend to enable command authentication")
	}

	if cmd.Nonce <= 0 || len(cmd.Signature) == 0 {
		return fmt.Errorf("unsigned command rejected (CMD_SIGNING_KEY is configured, but command has no signature)")
	}

	if !b.nonceTracker.Check(cmd.Nonce) {
		return fmt.Errorf("replayed command nonce %d (last seen: %d)", cmd.Nonce, b.nonceTracker.Last())
	}

	const maxCommandAge = 5 * time.Minute
	if cmd.IssuedAt != nil {
		age := time.Since(cmd.IssuedAt.AsTime())
		if age > maxCommandAge {
			return fmt.Errorf("command expired: issued %v ago (max %v)", age.Round(time.Second), maxCommandAge)
		}
		if age < -maxCommandAge {
			return fmt.Errorf("command issued in the future: %v ahead (max clock skew %v)", (-age).Round(time.Second), maxCommandAge)
		}
	}

	actionCode := int32(cmd.Action)
	issuedAtNano := int64(0)
	if cmd.IssuedAt != nil {
		issuedAtNano = cmd.IssuedAt.AsTime().UnixNano()
	}
	payload := cmdsigning.BuildCanonicalPayload(
		actionCode,
		cmd.IpAddress,
		cmd.DurationSeconds,
		cmd.Reason,
		cmd.BlockId,
		int32(cmd.BlockType),
		issuedAtNano,
	)

	if err := cmdsigning.Verify(key, cmd.Nonce, payload, cmd.Signature); err != nil {
		return fmt.Errorf("command signature verification failed: %w", err)
	}

	b.nonceTracker.Record(cmd.Nonce)
	b.persistNonce(cmd.Nonce)
	return nil
}

// processCommand handles a single block command
func (b *BlockCommandClient) processCommand(cmd *pb.BlockCommand) {
	Logger.Infof("[BlockCommandClient] Received command: action=%s ip=%s duration=%ds reason=%s nonce=%d",
		cmd.Action.String(), cmd.IpAddress, cmd.DurationSeconds, cmd.Reason, cmd.Nonce)

	// Verify command authenticity before execution
	if err := b.verifyCommand(cmd); err != nil {
		Logger.Errorf("[BlockCommandClient] Command verification FAILED: %v — refusing to execute", err)
		AuditLogCommandRejected(cmd.Action.String(), cmd.IpAddress, cmd.Reason, err)
		return
	}

	AuditLogCommandAccepted(cmd.Action.String(), cmd.IpAddress, cmd.Reason, cmd.DurationSeconds)

	switch cmd.Action {
	case pb.BlockCommand_BLOCK:
		if b.onBlock != nil {
			var duration time.Duration
			// duration = 0 means permanent block (no expiry)
			// Only convert to duration if DurationSeconds > 0
			if cmd.DurationSeconds > 0 {
				duration = time.Duration(cmd.DurationSeconds) * time.Second
			}
			ip := cmd.IpAddress
			reason := cmd.Reason
			onBlock := b.onBlock
			go func() {
				if err := onBlock(ip, duration, reason); err != nil {
					Logger.Errorf("[BlockCommandClient] Failed to block %s: %v", ip, err)
				} else {
					if duration > 0 {
						Logger.Infof("[BlockCommandClient] Blocked %s for %v", ip, duration)
					} else {
						Logger.Infof("[BlockCommandClient] Blocked %s permanently", ip)
					}
				}
			}()
		}

	case pb.BlockCommand_UNBLOCK:
		if b.onUnblock != nil {
			ip := cmd.IpAddress
			reason := cmd.Reason
			blockType := remediation.BlockTypeBlocklist // default

			// Convert proto BlockType to remediation.BlockType
			switch cmd.BlockType {
			case pb.BlockListEntry_BLOCK_TYPE_RATE_LIMIT:
				blockType = remediation.BlockTypeRateLimit
			case pb.BlockListEntry_BLOCK_TYPE_CIDR:
				blockType = remediation.BlockTypeCIDR
			case pb.BlockListEntry_BLOCK_TYPE_BLOCKLIST:
				blockType = remediation.BlockTypeBlocklist
			}

			onUnblock := b.onUnblock
			go func() {
				if err := onUnblock(ip, blockType, reason); err != nil {
					Logger.Errorf("[BlockCommandClient] Failed to unblock %s: %v", ip, err)
				} else {
					Logger.Infof("[BlockCommandClient] Unblocked %s from %s", ip, blockType)
				}
			}()
		}

	case pb.BlockCommand_RATE_LIMIT:
		b.mu.RLock()
		onRateLimit := b.onRateLimit
		b.mu.RUnlock()
		if onRateLimit != nil {
			var duration time.Duration
			if cmd.DurationSeconds > 0 {
				duration = time.Duration(cmd.DurationSeconds) * time.Second
			}
			ip := cmd.IpAddress
			reason := cmd.Reason
			go func() {
				if err := onRateLimit(ip, duration, reason); err != nil {
					Logger.Errorf("[BlockCommandClient] Failed to rate-limit %s: %v", ip, err)
				} else {
					Logger.Infof("[BlockCommandClient] Rate-limited %s for %v", ip, duration)
				}
			}()
		} else {
			Logger.Warnf("[BlockCommandClient] No onRateLimit handler set, falling back to block for %s", cmd.IpAddress)
			if b.onBlock != nil {
				var duration time.Duration
				if cmd.DurationSeconds > 0 {
					duration = time.Duration(cmd.DurationSeconds) * time.Second
				}
				ipCopy, reasonCopy := cmd.IpAddress, cmd.Reason
				go func() { _ = b.onBlock(ipCopy, duration, reasonCopy) }()
			}
		}

	default:
		Logger.Warnf("[BlockCommandClient] Unknown command action: %v", cmd.Action)
	}
}

// IsConnected returns the connection state
