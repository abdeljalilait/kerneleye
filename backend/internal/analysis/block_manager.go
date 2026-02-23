package analysis

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/kerneleye/backend/internal/database"
)

type BlockManagerConfig struct {
	AutoBlockEnabled  bool
	BlockThreshold    int
	BaseBlockDuration time.Duration
	MaxBlockDuration  time.Duration
	CheckInterval     time.Duration
}

type BlockManager struct {
	config  BlockManagerConfig
	queries *database.Queries
	hub     interface {
		BroadcastToUser(userID string, eventType string, data interface{})
		SendCommandToAgent(clientID string, cmd map[string]interface{})
		RegisterAgent(clientID string, cmdChan chan map[string]interface{})
		UnregisterAgent(clientID string)
	}

	mu           sync.RWMutex
	activeBlocks map[string]*ActiveBlock // key: source_ip
	stopChan     chan struct{}
	wg           sync.WaitGroup
}

type ActiveBlock struct {
	IP         string
	ServerID   pgtype.UUID
	UserID     pgtype.UUID
	Score      int
	Reason     string
	Duration   time.Duration
	BlockedAt  time.Time
	ExpiresAt  time.Time
	AgentToken string
}

func NewBlockManager(cfg BlockManagerConfig, queries *database.Queries, hub interface {
	BroadcastToUser(userID string, eventType string, data interface{})
	SendCommandToAgent(clientID string, cmd map[string]interface{})
	RegisterAgent(clientID string, cmdChan chan map[string]interface{})
	UnregisterAgent(clientID string)
}) *BlockManager {
	return &BlockManager{
		config:       cfg,
		queries:      queries,
		hub:          hub,
		activeBlocks: make(map[string]*ActiveBlock),
		stopChan:     make(chan struct{}, 1),
	}
}

func (bm *BlockManager) Start(ctx context.Context) {
	if !bm.config.AutoBlockEnabled {
		log.Printf("[BlockManager] Disabled (auto-block not enabled)")
		return
	}

	bm.wg.Add(1)
	go bm.runLoop(ctx)

	log.Printf("[BlockManager] Started (threshold: %d, duration: %v)",
		bm.config.BlockThreshold, bm.config.BaseBlockDuration)
}

func (bm *BlockManager) Stop() {
	bm.stopChan <- struct{}{}
	bm.wg.Wait()
	log.Printf("[BlockManager] Stopped")
}

func (bm *BlockManager) runLoop(ctx context.Context) {
	defer bm.wg.Done()

	ticker := time.NewTicker(bm.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			bm.evaluateAndBlock(ctx)
		case <-ctx.Done():
			return
		case <-bm.stopChan:
			return
		}
	}
}

func (bm *BlockManager) evaluateAndBlock(ctx context.Context) {
	windowStart := time.Now().Add(-5 * time.Minute)

	blockable, err := bm.queries.GetBlockableIPs(ctx, database.GetBlockableIPsParams{
		LastSeen:    database.ToPgTimestamptz(windowStart),
		ThreatScore: int32(bm.config.BlockThreshold),
	})
	if err != nil {
		log.Printf("[BlockManager] Failed to get blockable IPs: %v", err)
		return
	}

	count := 0
	skippedWhitelist := 0
	for _, row := range blockable {
		ipStr := row.SourceIp.String()

		bm.mu.RLock()
		_, exists := bm.activeBlocks[ipStr]
		bm.mu.RUnlock()

		if exists {
			continue
		}

		// Check if IP is whitelisted
		isWhitelisted, err := bm.queries.IsIPWhitelisted(ctx, database.IsIPWhitelistedParams{
			UserID:    row.UserID,
			IpAddress: row.SourceIp,
		})
		if err == nil && isWhitelisted {
			skippedWhitelist++
			log.Printf("[BlockManager] Skipping whitelisted IP: %s", ipStr)
			continue
		}

		count++
		bm.createBlock(ctx, row)
	}

	if count > 0 {
		log.Printf("[BlockManager] Created %d new blocks, skipped %d whitelisted", count, skippedWhitelist)
	}
}

func (bm *BlockManager) createBlock(ctx context.Context, row database.GetBlockableIPsRow) {
	ipStr := row.SourceIp.String()
	duration := bm.config.BaseBlockDuration

	if row.ThreatScore > 80 {
		duration = duration * 2
	}
	if duration > bm.config.MaxBlockDuration {
		duration = bm.config.MaxBlockDuration
	}

	expiresAt := time.Now().Add(duration)

	reasons := []string{row.ThreatType}

	block, err := bm.queries.CreateBlock(ctx, database.CreateBlockParams{
		ServerID:        row.ServerID,
		UserID:          row.UserID,
		IpAddress:       row.SourceIp,
		IpVersion:       pgtype.Int4{Int32: 4, Valid: true},
		ThreatScore:     row.ThreatScore,
		ThreatLevel:     row.ThreatLevel,
		Reasons:         reasons,
		TargetPort:      pgtype.Int4{Int32: 0, Valid: false},
		ServiceName:     pgtype.Text{String: "", Valid: false},
		Protocol:        pgtype.Text{String: "", Valid: false},
		CountryCode:     row.Country,
		CountryName:     row.Country,
		City:            row.City,
		Region:          pgtype.Text{String: "", Valid: false},
		Latitude:        pgtype.Float8{Float64: 0, Valid: false},
		Longitude:       pgtype.Float8{Float64: 0, Valid: false},
		Asn:             pgtype.Int4{Int32: 0, Valid: false},
		AsnOrg:          row.Isp,
		IsVpn:           pgtype.Bool{Bool: false, Valid: true},
		IsTor:           pgtype.Bool{Bool: false, Valid: true},
		IsDatacenter:    pgtype.Bool{Bool: false, Valid: true},
		BlockedAt:       database.ToPgTimestamptz(time.Now()),
		ExpiresAt:       database.ToPgTimestamptz(expiresAt),
		DurationSeconds: int32(duration.Seconds()),
		IsAutoBlocked:   pgtype.Bool{Bool: true, Valid: true},
		AgentVersion:    pgtype.Text{String: "", Valid: false},
		RawMetrics:      nil,
	})
	if err != nil {
		log.Printf("[BlockManager] Failed to create block for %s: %v", ipStr, err)
		return
	}

	bm.mu.Lock()
	bm.activeBlocks[ipStr] = &ActiveBlock{
		IP:        ipStr,
		ServerID:  row.ServerID,
		UserID:    row.UserID,
		Score:     int(row.ThreatScore),
		Reason:    row.ThreatType,
		Duration:  duration,
		BlockedAt: time.Now(),
		ExpiresAt: expiresAt,
	}
	bm.mu.Unlock()

	bm.sendBlockCommand(ipStr, duration, row.ThreatType, block.ID.String())

	if bm.hub != nil && row.UserID.Valid {
		bm.hub.BroadcastToUser(database.FromPgUUID(row.UserID), "new_block", map[string]interface{}{
			"block_id":     block.ID.String(),
			"ip_address":   ipStr,
			"server_id":    row.ServerID.String(),
			"threat_score": row.ThreatScore,
			"threat_level": row.ThreatLevel,
			"threat_type":  row.ThreatType,
			"duration":     duration.Seconds(),
			"expires_at":   expiresAt,
		})
	}

	log.Printf("[BlockManager] Blocked %s (score: %d, duration: %v)",
		ipStr, row.ThreatScore, duration)
}

func (bm *BlockManager) sendBlockCommand(ip string, duration time.Duration, reason, blockID string) {
	if bm.hub == nil {
		return
	}

	bm.mu.RLock()
	block, exists := bm.activeBlocks[ip]
	bm.mu.RUnlock()

	if !exists {
		return
	}

	agentID := block.ServerID.String()

	bm.hub.SendCommandToAgent(agentID, map[string]interface{}{
		"action":   "block",
		"ip":       ip,
		"duration": int64(duration.Seconds()),
		"reason":   reason,
		"block_id": blockID,
	})
}

func (bm *BlockManager) Unblock(ctx context.Context, ip string, reason string) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	block, exists := bm.activeBlocks[ip]
	if !exists {
		return nil
	}

	agentID := block.ServerID.String()
	bm.hub.SendCommandToAgent(agentID, map[string]interface{}{
		"action": "unblock",
		"ip":     ip,
		"reason": reason,
	})

	delete(bm.activeBlocks, ip)
	return nil
}

func (bm *BlockManager) GetActiveBlocks() []*ActiveBlock {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	blocks := make([]*ActiveBlock, 0, len(bm.activeBlocks))
	for _, block := range bm.activeBlocks {
		blocks = append(blocks, block)
	}
	return blocks
}
