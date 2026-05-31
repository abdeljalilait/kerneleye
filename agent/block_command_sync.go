package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	pb "github.com/kerneleye/proto/kerneleye/v1"
	"github.com/kerneleye/shared/cmdsigning"
)

// Block list reconciliation and synchronization.
// Reconcile and SyncBlockList pull the current block list from the backend,
// verify the response signature, and apply blocks locally.
// Nonce persistence across restarts is also handled here.

func (b *BlockCommandClient) loadNonce() {
	data, err := os.ReadFile(b.noncePath)
	if err != nil {
		return
	}
	last, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return
	}
	b.nonceTracker.Record(last)
	Logger.Debugf("[BlockCommandClient] Restored nonce: %d", last)
}

// persistNonce saves the last seen nonce to disk.
func (b *BlockCommandClient) persistNonce(nonce int64) {
	if b.noncePath == "" {
		return
	}
	data := []byte(strconv.FormatInt(nonce, 10))
	if err := os.WriteFile(b.noncePath, data, 0600); err != nil {
		Logger.Debugf("[BlockCommandClient] Failed to persist nonce: %v", err)
	}
}

// Start begins receiving block commands from the backend
func (b *BlockCommandClient) Start(ctx context.Context) error {
	b.mu.Lock()
	if b.running {
		b.mu.Unlock()
		return nil
	}
	b.running = true
	b.mu.Unlock()

	b.wg.Add(1)
	go b.receiveLoop(ctx)

	Logger.Info("[BlockCommandClient] Started streaming block commands")
	return nil
}

// Reconcile performs a full reconciliation between backend blocks and local state.
// Returns an error if the block list response signature is invalid (tampered response).
func (b *BlockCommandClient) Reconcile(ctx context.Context) error {
	resp, err := b.fetchBlockList(ctx)
	if err != nil {
		return err
	}

	// Build a map of backend blocks for quick lookup
	backendBlocks := make(map[string]pb.BlockListEntry_BlockType)
	for _, block := range resp.Blocks {
		if block.ExpiresAt > 0 {
			expiresAt := time.Unix(block.ExpiresAt, 0)
			if time.Now().After(expiresAt) {
				continue
			}
		}
		backendBlocks[block.IpAddress] = block.BlockType
	}

	Logger.Debugf("[BlockCommandClient] Backend has %d active blocks", len(backendBlocks))

	for ip := range backendBlocks {
		var duration time.Duration
		for _, block := range resp.Blocks {
			if block.IpAddress == ip {
				if block.DurationSeconds > 0 {
					duration = time.Duration(block.DurationSeconds) * time.Second
				}
				break
			}
		}

		b.mu.RLock()
		onBlock := b.onBlock
		b.mu.RUnlock()
		if onBlock != nil {
			if err := onBlock(ip, duration, "reconcile"); err != nil {
				Logger.Warnf("[BlockCommandClient] Failed to reconcile block %s: %v", ip, err)
			}
		}
	}

	Logger.Infof("[BlockCommandClient] Reconciliation complete: %d blocks from backend", len(backendBlocks))
	return nil
}

// fetchBlockList gets the block list from backend and verifies the response signature.
func (b *BlockCommandClient) fetchBlockList(ctx context.Context) (*pb.GetBlockListResponse, error) {
	b.mu.RLock()
	client := b.client
	apiKey := b.apiKey
	serverID := b.serverID
	b.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("client not initialized")
	}

	resp, err := client.GetBlockList(ctx, &pb.GetBlockListRequest{
		ApiKey:      apiKey,
		ClientToken: serverID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get block list: %w", err)
	}

	// Verify response signature if CMD_SIGNING_KEY is configured
	key := cmdsigning.Key()
	if key != "" {
		if len(resp.Signature) == 0 || resp.Nonce <= 0 {
			return nil, fmt.Errorf("block list response is unsigned — rejecting (CMD_SIGNING_KEY is configured)")
		}
		entries := make([]cmdsigning.BlockListEntry, 0, len(resp.Blocks))
		for _, b := range resp.Blocks {
			entries = append(entries, cmdsigning.BlockListEntry{
				IPAddress:       b.IpAddress,
				DurationSeconds: b.DurationSeconds,
				Reason:          b.Reason,
				BlockType:       int32(b.BlockType),
			})
		}
		payload := cmdsigning.BuildBlockListPayload(entries)
		if err := cmdsigning.Verify(key, resp.Nonce, payload, resp.Signature); err != nil {
			return nil, fmt.Errorf("block list signature verification failed: %w", err)
		}
	}

	return resp, nil
}

// Stop stops the block command client
func (b *BlockCommandClient) SyncBlockList(ctx context.Context) error {
	resp, err := b.fetchBlockList(ctx)
	if err != nil {
		return fmt.Errorf("failed to get block list: %w", err)
	}

	Logger.Infof("[BlockCommandClient] Synced %d blocks from backend", len(resp.Blocks))

	// Apply each block locally
	for _, block := range resp.Blocks {
		if block.ExpiresAt > 0 {
			expiresAt := time.Unix(block.ExpiresAt, 0)
			if time.Now().After(expiresAt) {
				Logger.Warnf("[BlockCommandClient] Skipping expired block: %s (expired %v ago)", block.IpAddress, time.Since(expiresAt))
				continue
			}
		}

		var duration time.Duration
		if block.DurationSeconds > 0 {
			duration = time.Duration(block.DurationSeconds) * time.Second
		}

		if block.BlockType == pb.BlockListEntry_BLOCK_TYPE_RATE_LIMIT {
			b.mu.RLock()
			onRateLimit := b.onRateLimit
			b.mu.RUnlock()
			if onRateLimit != nil {
				if err := onRateLimit(block.IpAddress, duration, block.Reason); err != nil {
					Logger.Errorf("[BlockCommandClient] Failed to apply rate-limit %s: %v", block.IpAddress, err)
				} else {
					Logger.Debugf("[BlockCommandClient] Applied rate-limit %s for %v", block.IpAddress, duration)
				}
			}
		} else if b.onBlock != nil {
			if err := b.onBlock(block.IpAddress, duration, block.Reason); err != nil {
				Logger.Errorf("[BlockCommandClient] Failed to apply block %s: %v", block.IpAddress, err)
			} else {
				if duration > 0 {
					Logger.Debugf("[BlockCommandClient] Applied block %s for %v", block.IpAddress, duration)
				} else {
					Logger.Debugf("[BlockCommandClient] Applied permanent block %s", block.IpAddress)
				}
			}
		}
	}

	return nil
}
