package analysis

import (
	"context"
	"log"
	"net/netip"
	"strings"
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
	IP          string
	ServerID    pgtype.UUID
	UserID      pgtype.UUID
	Score       int
	Reason      string
	Duration    time.Duration
	BlockedAt   time.Time
	ExpiresAt   time.Time
	IsPermanent bool
	AgentToken  string
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

	// Load active blocks from database for state recovery
	bm.loadActiveBlocks(ctx)

	bm.wg.Add(1)
	go bm.runLoop(ctx)

	log.Printf("[BlockManager] Started (threshold: %d, duration: %v)",
		bm.config.BlockThreshold, bm.config.BaseBlockDuration)
}

func (bm *BlockManager) loadActiveBlocks(ctx context.Context) {
	blocks, err := bm.queries.GetAllActiveBlocks(ctx)
	if err != nil {
		log.Printf("[BlockManager] Failed to load active blocks: %v", err)
		return
	}

	bm.mu.Lock()
	defer bm.mu.Unlock()

	for _, block := range blocks {
		ipStr := block.IpAddress.String()
		expiresAt, _ := block.ExpiresAt.Value()
		var expires time.Time
		isPermanent := false
		if t, ok := expiresAt.(time.Time); ok {
			expires = t
		} else {
			// No expiry = permanent block
			isPermanent = true
		}

		bm.activeBlocks[ipStr] = &ActiveBlock{
			IP:          ipStr,
			ServerID:    block.ServerID,
			UserID:      block.UserID,
			Score:       int(block.ThreatScore),
			Reason:      strings.Join(block.Reasons, ", "),
			Duration:    time.Duration(block.DurationSeconds) * time.Second,
			BlockedAt:   block.BlockedAt.Time,
			ExpiresAt:   expires,
			IsPermanent: isPermanent,
		}
	}

	log.Printf("[BlockManager] Loaded %d active blocks from database", len(blocks))
}

func (bm *BlockManager) Stop() {
	bm.stopChan <- struct{}{}
	bm.wg.Wait()
	log.Printf("[BlockManager] Stopped")
}

func (bm *BlockManager) runLoop(ctx context.Context) {
	defer bm.wg.Done()

	evalTicker := time.NewTicker(bm.config.CheckInterval)
	defer evalTicker.Stop()

	// Cleanup expired blocks every 5 minutes
	cleanupTicker := time.NewTicker(5 * time.Minute)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-evalTicker.C:
			bm.evaluateAndBlock(ctx)
		case <-cleanupTicker.C:
			bm.cleanupExpiredBlocks()
		case <-ctx.Done():
			return
		case <-bm.stopChan:
			return
		}
	}
}

// cleanupExpiredBlocks removes expired temporary blocks from the in-memory map
// This prevents stale entries from preventing re-blocks of IPs whose blocks have expired
func (bm *BlockManager) cleanupExpiredBlocks() {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	now := time.Now()
	removed := 0
	for ip, block := range bm.activeBlocks {
		// Skip permanent blocks
		if block.IsPermanent {
			continue
		}
		// Remove if expired
		if block.ExpiresAt.Before(now) {
			delete(bm.activeBlocks, ip)
			removed++
		}
	}

	if removed > 0 {
		log.Printf("[BlockManager] Cleaned up %d expired blocks from memory", removed)
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
	
	// Determine if this should be a permanent block based on threat level
	// malicious/critical = permanent block (no expiry)
	// suspicious/normal = temporary block with duration
	var duration time.Duration
	var expiresAt time.Time
	var expiresAtPg pgtype.Timestamptz
	
	threatLevel := strings.ToLower(row.ThreatLevel)
	if threatLevel == "malicious" || threatLevel == "critical" {
		// Permanent block - no expiration
		duration = 0
		expiresAtPg = pgtype.Timestamptz{Valid: false}
	} else {
		// Temporary block with duration based on score
		duration = bm.config.BaseBlockDuration
		if row.ThreatScore > 80 {
			duration = duration * 2
		}
		if duration > bm.config.MaxBlockDuration {
			duration = bm.config.MaxBlockDuration
		}
		expiresAt = time.Now().Add(duration)
		expiresAtPg = database.ToPgTimestamptz(expiresAt)
	}

	reasons := []string{row.ThreatType}

	// Determine IP version
	ipVersion := int32(4)
	if row.SourceIp.Is6() {
		ipVersion = 6
	}

	isPermanent := threatLevel == "malicious" || threatLevel == "critical"

	block, err := bm.queries.CreateBlock(ctx, database.CreateBlockParams{
		ServerID:        row.ServerID,
		UserID:          row.UserID,
		IpAddress:       row.SourceIp,
		IpVersion:       pgtype.Int4{Int32: ipVersion, Valid: true},
		ThreatScore:     row.ThreatScore,
		ThreatLevel:     row.ThreatLevel,
		Reasons:         reasons,
		TargetPort:      pgtype.Int4{Int32: 0, Valid: false},
		ServiceName:     pgtype.Text{String: "", Valid: false},
		Protocol:        pgtype.Text{String: "", Valid: false},
		CountryCode:     row.CountryCode,
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
		ExpiresAt:       expiresAtPg,
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
		IP:          ipStr,
		ServerID:    row.ServerID,
		UserID:      row.UserID,
		Score:       int(row.ThreatScore),
		Reason:      row.ThreatType,
		Duration:    duration,
		BlockedAt:   time.Now(),
		ExpiresAt:   expiresAt,
		IsPermanent: isPermanent,
	}
	agentID := row.ServerID.String()
	bm.mu.Unlock()

	// Create alert for this block
	severity := "medium"
	if row.ThreatScore >= 70 {
		severity = "critical"
	} else if row.ThreatScore >= 50 {
		severity = "high"
	}

	ipAddr, _ := netip.ParseAddr(ipStr)
	_, err = bm.queries.CreateAlert(ctx, database.CreateAlertParams{
		ServerID:    row.ServerID,
		SourceIp:    ipAddr,
		ThreatScore: row.ThreatScore,
		Reason:      "Auto-blocked: " + row.ThreatType,
		Severity:    severity,
		Status:      "active",
	})
	if err != nil {
		log.Printf("[BlockManager] Failed to create alert for %s: %v", ipStr, err)
	}

	// Determine block type: ratelimit for low scores (< 50), blocklist for higher scores
	blockType := "blocklist"
	if row.ThreatScore < 50 {
		blockType = "ratelimit"
	}

	bm.sendBlockCommand(agentID, ipStr, duration, row.ThreatType, blockType, block.ID.String())

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
			"block_type":   blockType,
		})
	}

	log.Printf("[BlockManager] Blocked %s (score: %d, duration: %v)",
		ipStr, row.ThreatScore, duration)
}

func (bm *BlockManager) sendBlockCommand(agentID, ip string, duration time.Duration, reason, blockType, blockID string) {
	if bm.hub == nil {
		return
	}

	bm.hub.SendCommandToAgent(agentID, map[string]interface{}{
		"action":     "block",
		"ip":         ip,
		"duration":   int64(duration.Seconds()),
		"reason":     reason,
		"block_id":   blockID,
		"block_type": blockType,
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
