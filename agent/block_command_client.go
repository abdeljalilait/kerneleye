package main

import (
	"context"
	"fmt"
	"log"
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

	// Callback for executing commands
	onBlock   func(ip string, duration time.Duration, reason string) error
	onUnblock func(ip string, reason string) error
}

// NewBlockCommandClient creates a new block command client
func NewBlockCommandClient(grpcTarget, apiKey, serverID string, onBlock func(ip string, duration time.Duration, reason string) error, onUnblock func(ip string, reason string) error) (*BlockCommandClient, error) {
	conn, err := grpc.NewClient(grpcDialTargetPrefix+grpcTarget, buildGRPCOpts(grpcTarget)...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to gRPC server: %w", err)
	}

	client := pb.NewBlockServiceClient(conn)
	if client == nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create block service client")
	}

	return &BlockCommandClient{
		conn:      conn,
		client:    client,
		apiKey:    apiKey,
		serverID:  serverID,
		stopChan:  make(chan struct{}),
		onBlock:   onBlock,
		onUnblock: onUnblock,
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

	log.Printf("[BlockCommandClient] Started streaming block commands")
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

	if b.conn != nil {
		b.conn.Close()
	}

	log.Printf("[BlockCommandClient] Stopped")
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
				log.Printf("[BlockCommandClient] Stream error: %v", err)
				select {
				case <-b.stopChan:
					return
				case <-time.After(5 * time.Second):
					// Retry after delay
				}
			}
		}
	}
}

// connectAndStream connects to the backend and streams block commands
func (b *BlockCommandClient) connectAndStream(ctx context.Context) error {
	// Re-create client if connection was closed
	b.mu.RLock()
	client := b.client
	b.mu.RUnlock()

	if client == nil {
		return fmt.Errorf("client not initialized")
	}

	stream, err := client.StreamBlockCommands(ctx, &pb.StreamBlockRequest{
		ApiKey:      b.apiKey,
		ClientToken: b.serverID,
	})
	if err != nil {
		return fmt.Errorf("failed to start stream: %w", err)
	}

	log.Printf("[BlockCommandClient] Connected to stream")

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

// processCommand handles a single block command
func (b *BlockCommandClient) processCommand(cmd *pb.BlockCommand) {
	log.Printf("[BlockCommandClient] Received command: action=%s ip=%s duration=%ds reason=%s",
		cmd.Action.String(), cmd.IpAddress, cmd.DurationSeconds, cmd.Reason)

	switch cmd.Action {
	case pb.BlockCommand_BLOCK:
		if b.onBlock != nil {
			duration := time.Duration(cmd.DurationSeconds) * time.Second
			if duration == 0 {
				duration = 1 * time.Hour // Default to 1 hour
			}
			if err := b.onBlock(cmd.IpAddress, duration, cmd.Reason); err != nil {
				log.Printf("[BlockCommandClient] Failed to block %s: %v", cmd.IpAddress, err)
			} else {
				log.Printf("[BlockCommandClient] Blocked %s for %v", cmd.IpAddress, duration)
			}
		}

	case pb.BlockCommand_UNBLOCK:
		if b.onUnblock != nil {
			if err := b.onUnblock(cmd.IpAddress, cmd.Reason); err != nil {
				log.Printf("[BlockCommandClient] Failed to unblock %s: %v", cmd.IpAddress, err)
			} else {
				log.Printf("[BlockCommandClient] Unblocked %s", cmd.IpAddress)
			}
		}

	case pb.BlockCommand_RATE_LIMIT:
		log.Printf("[BlockCommandClient] Rate limit command not yet implemented for %s", cmd.IpAddress)

	default:
		log.Printf("[BlockCommandClient] Unknown command action: %v", cmd.Action)
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
