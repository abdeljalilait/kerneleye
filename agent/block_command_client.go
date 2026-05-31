package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kerneleye/agent/remediation"
	pb "github.com/kerneleye/proto/kerneleye/v1"
	"github.com/kerneleye/shared/cmdsigning"
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

	nonceTracker cmdsigning.NonceTracker // Prevents replay attacks
	noncePath    string                  // File path for persisting nonce across restarts
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

	b := &BlockCommandClient{
		conn:              conn,
		client:            client,
		apiKey:            apiKey,
		serverID:          serverID,
		stopChan:          make(chan struct{}),
		onBlock:           onBlock,
		onUnblock:         onUnblock,
		maxReconnectDelay: 5 * time.Minute,
	}

	// Persist nonce across restart — default to /var/lib/kerneleye/
	nonceDir := "/var/lib/kerneleye"
	if _, err := os.Stat(nonceDir); os.IsNotExist(err) {
		nonceDir = os.TempDir()
	}
	b.noncePath = filepath.Join(nonceDir, "cmd_nonce")
	b.loadNonce()

	return b, nil
}

// loadNonce restores the last seen nonce from disk.
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

// verifyCommand checks the HMAC signature and nonce of a command.
// When CMD_SIGNING_KEY is configured, unsigned commands are rejected.
// When CMD_SIGNING_KEY is not set, verification is skipped with a warning.
func (b *BlockCommandClient) IsConnected() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.conn == nil {
		return false
	}

	state := b.conn.GetState()
	return state == connectivity.Ready
}

