package main

import (
	"context"
	"os"
	"time"

	pb "github.com/kerneleye/proto/kerneleye/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

// gRPC connection lifecycle for the Aggregator.
// Manages connection monitoring, exponential-backoff reconnection,
// heartbeat sending, buffer maintenance, and the flush timer.

func (a *Aggregator) runBufferMaintenance() {
	defer a.wg.Done()
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if a.buffer == nil {
				continue
			}
			evicted, err := a.buffer.EvictExpired(24 * time.Hour)
			if err != nil {
				Logger.Warnf("⚠️  Buffer TTL eviction error: %v", err)
			} else if evicted > 0 {
				Logger.Infof("🗑️  Buffer maintenance: evicted %d expired batches (>24h old)", evicted)
			}
		case <-a.stopChan:
			return
		}
	}
}

// getServerIPs retrieves all local IP addresses for the server
func (a *Aggregator) StartFlushTimer(interval time.Duration) {
	if a.flushTicker != nil {
		return // Already running
	}

	a.flushTicker = time.NewTicker(interval)
	a.heartbeatTicker = time.NewTicker(30 * time.Second)

	a.wg.Go(func() {
		for {
			select {
			case <-a.flushTicker.C:
				a.FlushToAPI()
			case <-a.heartbeatTicker.C:
				a.SendHeartbeat()
			case <-a.stopChan:
				return
			}
		}
	})
}

// SendHeartbeat sends a heartbeat to the backend
func (a *Aggregator) SendHeartbeat() {
	hostname, _ := os.Hostname()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	a.grpcMu.RLock()
	client := a.grpcClient
	apiKey := a.apiKey
	publicIP := a.cachedPublicIP
	a.grpcMu.RUnlock()

	if client == nil {
		Logger.Warn("⚠️  gRPC client not initialized, skipping heartbeat")
		a.scheduleReconnect()
		return
	}
	resp, err := client.Heartbeat(ctx, &pb.HeartbeatRequest{
		ApiKey: apiKey, Hostname: hostname, AgentVersion: Version, IpAddress: publicIP,
	})
	if err != nil {
		Logger.Errorf("❌ gRPC heartbeat error: %v", err)
		a.scheduleReconnect()
		return
	}
	if !resp.Success {
		Logger.Warnf("⚠️  Server status: %s - Agent will exit", resp.Message)
		a.Stop()
	}
}

// monitorConnection monitors gRPC connection health and reconnects on failure
func (a *Aggregator) monitorConnection() {
	defer a.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			a.checkConnection()
		case <-a.stopChan:
			return
		}
	}
}

// checkConnection verifies connection is alive and reconnects if needed
func (a *Aggregator) checkConnection() {
	a.grpcMu.RLock()
	conn := a.grpcConn
	if conn == nil {
		a.grpcMu.RUnlock()
		a.scheduleReconnect()
		return
	}
	state := conn.GetState()
	a.grpcMu.RUnlock()
	if state == connectivity.TransientFailure || state == connectivity.Shutdown {
		Logger.Infof("🔄 gRPC connection state: %v - attempting reconnect", state)
		a.scheduleReconnect()
	}
}

// scheduleReconnect schedules a reconnection attempt with exponential backoff
func (a *Aggregator) scheduleReconnect() {
	a.reconnectMu.Lock()
	if a.reconnecting {
		a.reconnectMu.Unlock()
		return
	}

	// Calculate delay with exponential backoff
	delay := min(time.Duration(1<<uint(a.reconnectCount))*time.Second, a.maxReconnectDelay)

	a.reconnectCount++
	attempt := a.reconnectCount
	a.lastReconnect = time.Now()
	a.reconnecting = true
	a.reconnectMu.Unlock()

	Logger.Infof("⏳ Scheduling reconnection attempt %d in %v", attempt, delay)

	go func() {
		select {
		case <-time.After(delay):
			a.attemptReconnect(attempt)
		case <-a.stopChan:
			a.reconnectMu.Lock()
			a.reconnecting = false
			a.reconnectMu.Unlock()
			return
		}
	}()
}

// attemptReconnect tries to reconnect to the gRPC server
func (a *Aggregator) attemptReconnect(attempt int) {
	Logger.Infof("🔄 Attempting to reconnect to gRPC server %s (attempt %d)...", a.grpcURL, attempt)

	// Create new connection
	conn, err := grpc.NewClient(grpcDialTargetPrefix+buildGRPCDialTarget(a.grpcURL), buildGRPCOpts(a.tlsCfg)...)
	if err != nil {
		Logger.Errorf("❌ Failed to create new gRPC connection: %v", err)
		a.reconnectMu.Lock()
		a.reconnecting = false
		a.reconnectMu.Unlock()
		a.scheduleReconnect()
		return
	}

	// Test connection with a simple call
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	testClient := pb.NewIngestServiceClient(conn)
	_, err = testClient.Heartbeat(ctx, &pb.HeartbeatRequest{
		ApiKey: a.apiKey,
	})

	if err != nil {
		Logger.Errorf("❌ Reconnection test failed: %v", err)
		conn.Close()
		a.reconnectMu.Lock()
		a.reconnecting = false
		a.reconnectMu.Unlock()
		a.scheduleReconnect()
		return
	}

	// Success - update connection
	a.grpcMu.Lock()
	oldConn := a.grpcConn
	a.grpcConn = conn
	a.grpcClient = testClient
	if oldConn != nil {
		_ = oldConn.Close()
	}
	a.grpcMu.Unlock()

	// Update block command client if set
	if a.blockCmdClient != nil {
		a.blockCmdClient.UpdateClient(conn)
	}

	a.reconnectMu.Lock()
	a.reconnectCount = 0 // Reset counter on success
	a.reconnecting = false
	a.reconnectMu.Unlock()

	Logger.Info("✅ Successfully reconnected to gRPC server")
}

// Stop signals the aggregator to stop
