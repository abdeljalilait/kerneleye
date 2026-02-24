package main

import (
	"context"
	"fmt"
	"sync"
	"time"

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

	onBlock   func(ip string, duration time.Duration, reason string) error
	onUnblock func(ip string, reason string) error

	reconnectMu       sync.Mutex
	reconnectCount    int
	maxReconnectDelay time.Duration
	reconnecting      bool
}

// NewBlockCommandClient creates a new block command client
// If conn is provided, it will use that connection instead of creating a new one
func NewBlockCommandClient(conn *grpc.ClientConn, apiKey, serverID string, onBlock func(ip string, duration time.Duration, reason string) error, onUnblock func(ip string, reason string) error) (*BlockCommandClient, error) {
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
				Logger.Warnf("[BlockCommandClient] Stream error: %v", err)
				delay := b.getReconnectDelay()
				select {
				case <-b.stopChan:
					return
				case <-time.After(delay):
					// Retry after delay
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

		cmd, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("failed to receive command: %w", err)
		}

		b.processCommand(cmd)
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
			duration := time.Duration(cmd.DurationSeconds) * time.Second
			if duration == 0 {
				duration = 1 * time.Hour // Default to 1 hour
			}
			ip := cmd.IpAddress
			reason := cmd.Reason
			onBlock := b.onBlock
			go func() {
				if err := onBlock(ip, duration, reason); err != nil {
					Logger.Errorf("[BlockCommandClient] Failed to block %s: %v", ip, err)
				} else {
					Logger.Infof("[BlockCommandClient] Blocked %s for %v", ip, duration)
				}
			}()
		}

	case pb.BlockCommand_UNBLOCK:
		if b.onUnblock != nil {
			ip := cmd.IpAddress
			reason := cmd.Reason
			onUnblock := b.onUnblock
			go func() {
				if err := onUnblock(ip, reason); err != nil {
					Logger.Errorf("[BlockCommandClient] Failed to unblock %s: %v", ip, err)
				} else {
					Logger.Infof("[BlockCommandClient] Unblocked %s", ip)
				}
			}()
		}

	case pb.BlockCommand_RATE_LIMIT:
		Logger.Warnf("[BlockCommandClient] Rate limit command not yet implemented for %s", cmd.IpAddress)

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
		if b.onBlock != nil {
			duration := time.Duration(block.DurationSeconds) * time.Second
			if duration == 0 {
				duration = 1 * time.Hour
			}
			// Check if already expired
			if block.ExpiresAt > 0 {
				expiresAt := time.Unix(block.ExpiresAt, 0)
				if time.Now().After(expiresAt) {
					Logger.Warnf("[BlockCommandClient] Skipping expired block: %s (expired %v ago)", block.IpAddress, time.Since(expiresAt))
					continue
				}
			}
			if err := b.onBlock(block.IpAddress, duration, block.Reason); err != nil {
				Logger.Errorf("[BlockCommandClient] Failed to apply block %s: %v", block.IpAddress, err)
			}
		}
	}

	return nil
}
