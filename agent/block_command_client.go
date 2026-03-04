package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/kerneleye/agent/remediation"
	pb "github.com/kerneleye/proto/kerneleye/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

// BlockCommandClient handles receiving block/unblock commands from backend
type BlockCommandClient struct {
	conn     *grpc.ClientConn
	client   pb.BlockServiceClient
	apiKey   string
	serverID string

	mu       sync.RWMutex
	stream   pb.BlockService_StreamBlockCommandsClient
	running  bool
	stopChan chan struct{}
	wg       sync.WaitGroup

	onBlock     func(ip string, duration time.Duration, reason string) error
	onRateLimit func(ip string, duration time.Duration, reason string) error
	onUnblock   func(ip string, blockType remediation.BlockType, reason string) error

	reconnectMu       sync.Mutex
	reconnectCount    int
	maxReconnectDelay time.Duration
	reconnecting      bool
}

// SetOnRateLimit sets the callback invoked when the backend sends a RATE_LIMIT command.
// Must be called before Start().
func (b *BlockCommandClient) SetOnRateLimit(fn func(ip string, duration time.Duration, reason string) error) {
	b.mu.Lock()
	b.onRateLimit = fn
	b.mu.Unlock()
}

// NewBlockCommandClient creates a new block command client
// If conn is provided, it will use that connection instead of creating a new one
func NewBlockCommandClient(conn *grpc.ClientConn, apiKey, serverID string, onBlock func(ip string, duration time.Duration, reason string) error, onUnblock func(ip string, blockType remediation.BlockType, reason string) error) (*BlockCommandClient, error) {
	var client pb.BlockServiceClient
	if conn != nil {
		client = pb.NewBlockServiceClient(conn)
	} else {
		return nil, fmt.Errorf("connection is required")
	}
	if client == nil {
		return nil, fmt.Errorf("failed to create block service client")
	}

	return &BlockCommandClient{
		conn:              conn,
		client:            client,
		apiKey:            apiKey,
		serverID:          serverID,
		stopChan:          make(chan struct{}),
		onBlock:           onBlock,
		onUnblock:         onUnblock,
		maxReconnectDelay: 5 * time.Minute,
	}, nil
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

// Reconcile performs a full reconciliation between backend blocks and local state
// It removes IPs that are no longer in the backend and adds IPs that are missing locally
func (b *BlockCommandClient) Reconcile(ctx context.Context) error {
	b.mu.RLock()
	client := b.client
	apiKey := b.apiKey
	serverID := b.serverID
	onBlock := b.onBlock
	b.mu.RUnlock()

	if client == nil {
		return fmt.Errorf("client not initialized")
	}

	// Get blocks from backend
	resp, err := client.GetBlockList(ctx, &pb.GetBlockListRequest{
		ApiKey:      apiKey,
		ClientToken: serverID,
	})
	if err != nil {
		return fmt.Errorf("failed to get block list: %w", err)
	}

	// Build a map of backend blocks for quick lookup
	backendBlocks := make(map[string]pb.BlockListEntry_BlockType)
	for _, block := range resp.Blocks {
		if block.ExpiresAt > 0 {
			expiresAt := time.Unix(block.ExpiresAt, 0)
			if time.Now().After(expiresAt) {
				continue // Skip expired blocks
			}
		}
		backendBlocks[block.IpAddress] = block.BlockType
	}

	Logger.Debugf("[BlockCommandClient] Backend has %d active blocks", len(backendBlocks))

	// Note: To properly reconcile, we would need to query the local state (XDP/ipset)
	// and compare with backend. For now, we just log the reconciliation attempt.
	// Full implementation would require:
	// 1. Query local ipset/XDP for current blocked IPs
	// 2. Find IPs in backend but not locally -> add
	// 3. Find IPs locally but not in backend -> remove

	// For now, just re-apply all backend blocks (handles reconnection scenarios)
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

		if onBlock != nil {
			if err := onBlock(ip, duration, "reconcile"); err != nil {
				Logger.Warnf("[BlockCommandClient] Failed to reconcile block %s: %v", ip, err)
			}
		}
	}

	Logger.Infof("[BlockCommandClient] Reconciliation complete: %d blocks from backend", len(backendBlocks))
	return nil
}

// Stop stops the block command client
func (b *BlockCommandClient) Stop() {
	b.mu.Lock()
	if !b.running {
		b.mu.Unlock()
		return
	}
	b.running = false
	b.mu.Unlock()

	close(b.stopChan)
	b.wg.Wait()

	Logger.Info("[BlockCommandClient] Stopped")
}

// receiveLoop continuously receives and processes block commands
func (b *BlockCommandClient) receiveLoop(ctx context.Context) {
	defer b.wg.Done()

	for {
		select {
		case <-b.stopChan:
			return
		case <-ctx.Done():
			return
		default:
			if err := b.connectAndStream(ctx); err != nil {
				// Don't retry if we're shutting down
				if ctx.Err() != nil {
					Logger.Info("[BlockCommandClient] Stopping: context cancelled")
					return
				}
				select {
				case <-b.stopChan:
					return
				case <-ctx.Done():
					Logger.Info("[BlockCommandClient] Stopping: context cancelled during reconnect")
					return
				default:
					Logger.Warnf("[BlockCommandClient] Stream error: %v", err)
					delay := b.getReconnectDelay()
					select {
					case <-b.stopChan:
						return
					case <-ctx.Done():
						Logger.Info("[BlockCommandClient] Stopping: context cancelled during reconnect delay")
						return
					case <-time.After(delay):
						// Retry after delay
					}
				}
			}
		}
	}
}

func (b *BlockCommandClient) getReconnectDelay() time.Duration {
	b.reconnectMu.Lock()
	defer b.reconnectMu.Unlock()

	delay := time.Duration(1<<uint(b.reconnectCount)) * time.Second
	if delay > b.maxReconnectDelay {
		delay = b.maxReconnectDelay
	}
	b.reconnectCount++
	return delay
}

func (b *BlockCommandClient) resetReconnectDelay() {
	b.reconnectMu.Lock()
	b.reconnectCount = 0
	b.reconnectMu.Unlock()
}

// connectAndStream connects to the backend and streams block commands
func (b *BlockCommandClient) connectAndStream(ctx context.Context) error {
	// Check if context is already cancelled before starting
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.stopChan:
		return nil
	default:
	}

	b.mu.RLock()
	client := b.client
	conn := b.conn
	b.mu.RUnlock()

	if client == nil || conn == nil {
		return fmt.Errorf("client not initialized")
	}

	b.resetReconnectDelay()

	stream, err := client.StreamBlockCommands(ctx, &pb.StreamBlockRequest{
		ApiKey:      b.apiKey,
		ClientToken: b.serverID,
	})
	if err != nil {
		// Check if this is a context cancellation
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("failed to start stream: %w", err)
	}

	Logger.Info("[BlockCommandClient] Connected to stream")

	// Sync block list on reconnection for state reconciliation
	if err := b.SyncBlockList(ctx); err != nil {
		Logger.Warnf("[BlockCommandClient] Warning: failed to sync block list: %v", err)
	}

	for {
		select {
		case <-b.stopChan:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Use a goroutine to make stream.Recv() cancellable via stopChan
		// This prevents the receiveLoop from hanging indefinitely during shutdown
		recvChan := make(chan *pb.BlockCommand, 1)
		recvErrChan := make(chan error, 1)
		go func() {
			cmd, err := stream.Recv()
			if err != nil {
				recvErrChan <- err
			} else {
				recvChan <- cmd
			}
		}()

		select {
		case <-b.stopChan:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case err := <-recvErrChan:
			return fmt.Errorf("failed to receive command: %w", err)
		case cmd := <-recvChan:
			b.processCommand(cmd)
		}
	}
}

// UpdateClient updates the gRPC client (called when Aggregator reconnects)
func (b *BlockCommandClient) UpdateClient(conn *grpc.ClientConn) {
	b.mu.Lock()
	b.conn = conn
	b.client = pb.NewBlockServiceClient(conn)
	b.mu.Unlock()
	Logger.Info("[BlockCommandClient] Client updated with new connection")
}

// processCommand handles a single block command
func (b *BlockCommandClient) processCommand(cmd *pb.BlockCommand) {
	Logger.Infof("[BlockCommandClient] Received command: action=%s ip=%s duration=%ds reason=%s",
		cmd.Action.String(), cmd.IpAddress, cmd.DurationSeconds, cmd.Reason)

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
func (b *BlockCommandClient) IsConnected() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.conn == nil {
		return false
	}

	state := b.conn.GetState()
	return state == connectivity.Ready
}

// SyncBlockList fetches current block list from backend and applies locally
// Called on reconnection to reconcile state
func (b *BlockCommandClient) SyncBlockList(ctx context.Context) error {
	b.mu.RLock()
	client := b.client
	b.mu.RUnlock()

	if client == nil {
		return fmt.Errorf("client not initialized")
	}

	resp, err := client.GetBlockList(ctx, &pb.GetBlockListRequest{
		ApiKey:      b.apiKey,
		ClientToken: b.serverID,
	})
	if err != nil {
		return fmt.Errorf("failed to get block list: %w", err)
	}

	Logger.Infof("[BlockCommandClient] Synced %d blocks from backend", len(resp.Blocks))

	// Apply each block locally
	for _, block := range resp.Blocks {
		// Check if already expired
		if block.ExpiresAt > 0 {
			expiresAt := time.Unix(block.ExpiresAt, 0)
			if time.Now().After(expiresAt) {
				Logger.Warnf("[BlockCommandClient] Skipping expired block: %s (expired %v ago)", block.IpAddress, time.Since(expiresAt))
				continue
			}
		}

		var duration time.Duration
		// duration = 0 means permanent block
		if block.DurationSeconds > 0 {
			duration = time.Duration(block.DurationSeconds) * time.Second
		}

		if block.BlockType == pb.BlockListEntry_BLOCK_TYPE_RATE_LIMIT {
			// Route ratelimit entries to onRateLimit handler
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
