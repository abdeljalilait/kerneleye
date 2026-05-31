package analysis

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/kerneleye/backend/internal/database"
	"github.com/kerneleye/backend/internal/services"
	"github.com/kerneleye/shared/cmdsigning"
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

// EnforcementType defines what action is taken against a threat IP.
type EnforcementType string

const (
	EnforcementRateLimit EnforcementType = "ratelimit"
	EnforcementBlock     EnforcementType = "block"
	EnforcementPermanent EnforcementType = "permanent"

	// Minimum score that should enter the escalation pipeline.
	// determineEnforcement() contains explicit 30-49 handling (rate-limit path),
	// so querying at BlockThreshold=60 made that branch unreachable.
	minEscalationScore = 30
)

// EnforcementDecision is the output of the escalation engine.
type EnforcementDecision struct {
	Type        EnforcementType
	Duration    time.Duration // 0 = permanent
	ThreatLevel string
	Escalation  string // human-readable reason for escalation, for logging
}

type ActiveBlock struct {
	IP              string
	ServerID        pgtype.UUID
	UserID          pgtype.UUID
	Score           int
	Reason          string
	EnforcementType EnforcementType
	Duration        time.Duration
	BlockedAt       time.Time
	ExpiresAt       time.Time
	IsPermanent     bool
	AgentToken      string
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

	log.Printf("[BlockManager] Started (threshold: %d, candidate_score: %d, duration: %v)",
		bm.config.BlockThreshold, bm.candidateScoreThreshold(), bm.config.BaseBlockDuration)
}

func (bm *BlockManager) candidateScoreThreshold() int32 {
	threshold := bm.config.BlockThreshold
	if threshold <= 0 {
		return minEscalationScore
	}
	if threshold > minEscalationScore {
		return minEscalationScore
	}
	return int32(threshold)
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
			IP:              ipStr,
			ServerID:        block.ServerID,
			UserID:          block.UserID,
			Score:           int(block.ThreatScore),
			Reason:          strings.Join(block.Reasons, ", "),
			EnforcementType: EnforcementType(block.EnforcementType),
			Duration:        time.Duration(block.DurationSeconds) * time.Second,
			BlockedAt:       block.BlockedAt.Time,
			ExpiresAt:       expires,
			IsPermanent:     isPermanent,
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
	candidateThreshold := bm.candidateScoreThreshold()

	blockable, err := bm.queries.GetBlockableIPs(ctx, database.GetBlockableIPsParams{
		LastSeen:    database.ToPgTimestamptz(windowStart),
		ThreatScore: candidateThreshold,
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
		if err != nil {
			log.Printf("[BlockManager] Failed whitelist check for %s: %v (skipping for safety)", ipStr, err)
			continue
		}
		if isWhitelisted {
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

// determineEnforcement queries the IP's full history and applies the escalation
// matrix to return a decisive enforcement action.
func (bm *BlockManager) determineEnforcement(ctx context.Context, row database.GetBlockableIPsRow) EnforcementDecision {
	score := int(row.ThreatScore)

	// Score 90-100: always permanent regardless of history
	if score >= 90 {
		return EnforcementDecision{
			Type:        EnforcementPermanent,
			Duration:    0,
			ThreatLevel: "malicious",
			Escalation:  "score >= 90 → permanent",
		}
	}

	// Look up prior enforcement history for this IP
	history, err := bm.queries.GetIPEnforcementHistory(ctx, database.GetIPEnforcementHistoryParams{
		UserID:    row.UserID,
		IpAddress: row.SourceIp,
	})
	if err != nil {
		// On DB error fall back to conservative block
		log.Printf("[BlockManager] Failed to fetch enforcement history for %s: %v — using conservative default", row.SourceIp.String(), err)
		return EnforcementDecision{
			Type:        EnforcementBlock,
			Duration:    bm.config.BaseBlockDuration,
			ThreatLevel: strings.ToLower(row.ThreatLevel),
			Escalation:  "history lookup failed",
		}
	}

	blockCount := int(history.BlockCount)
	ratelimitCount := int(history.RatelimitCount)
	permanentCount := int(history.PermanentCount)

	// Any recorded permanent or the IP was already promoted to malicious → stay permanent
	if permanentCount > 0 {
		return EnforcementDecision{
			Type:        EnforcementPermanent,
			Duration:    0,
			ThreatLevel: "malicious",
			Escalation:  fmt.Sprintf("previously permanent (%d records) → permanent", permanentCount),
		}
	}

	switch {
	// Score 70–89: fast escalation path
	case score >= 70:
		switch {
		case blockCount >= 2:
			return EnforcementDecision{Type: EnforcementPermanent, Duration: 0, ThreatLevel: "malicious",
				Escalation: fmt.Sprintf("score %d + %d prior blocks ≥ 2 → permanent", score, blockCount)}
		case blockCount == 1:
			return EnforcementDecision{Type: EnforcementBlock, Duration: 24 * time.Hour, ThreatLevel: "malicious",
				Escalation: fmt.Sprintf("score %d + 1 prior block → 24h block", score)}
		default:
			return EnforcementDecision{Type: EnforcementBlock, Duration: 6 * time.Hour, ThreatLevel: "malicious",
				Escalation: fmt.Sprintf("score %d, first offense → 6h block", score)}
		}

	// Score 50–69: moderate escalation path
	case score >= 50:
		switch {
		case blockCount >= 3:
			return EnforcementDecision{Type: EnforcementPermanent, Duration: 0, ThreatLevel: "malicious",
				Escalation: fmt.Sprintf("score %d + %d prior blocks ≥ 3 → permanent", score, blockCount)}
		case blockCount == 2:
			return EnforcementDecision{Type: EnforcementBlock, Duration: 24 * time.Hour, ThreatLevel: "malicious",
				Escalation: fmt.Sprintf("score %d + 2 prior blocks → 24h block", score)}
		case blockCount == 1:
			return EnforcementDecision{Type: EnforcementBlock, Duration: 6 * time.Hour, ThreatLevel: "suspicious",
				Escalation: fmt.Sprintf("score %d + 1 prior block → 6h block", score)}
		default:
			return EnforcementDecision{Type: EnforcementBlock, Duration: bm.config.BaseBlockDuration, ThreatLevel: "suspicious",
				Escalation: fmt.Sprintf("score %d, first offense → %v block", score, bm.config.BaseBlockDuration)}
		}

	// Score 30–49 (suspicious, below block threshold but still actionable)
	default:
		switch {
		case blockCount >= 1 || ratelimitCount >= 2:
			return EnforcementDecision{Type: EnforcementBlock, Duration: 2 * time.Hour, ThreatLevel: "suspicious",
				Escalation: fmt.Sprintf("score %d + history (blocks=%d rl=%d) → escalated to 2h block", score, blockCount, ratelimitCount)}
		case ratelimitCount == 1:
			return EnforcementDecision{Type: EnforcementRateLimit, Duration: time.Hour, ThreatLevel: "suspicious",
				Escalation: fmt.Sprintf("score %d + 1 prior ratelimit → 1h ratelimit", score)}
		default:
			return EnforcementDecision{Type: EnforcementRateLimit, Duration: 30 * time.Minute, ThreatLevel: "suspicious",
				Escalation: fmt.Sprintf("score %d, first offense → 30min ratelimit", score)}
		}
	}
}

func (bm *BlockManager) createBlock(ctx context.Context, row database.GetBlockableIPsRow) {
	ipStr := row.SourceIp.String()

	// Determine enforcement type, duration, and threat level via escalation matrix
	decision := bm.determineEnforcement(ctx, row)
	log.Printf("[BlockManager] Enforcement decision for %s (score=%d): %s — %s",
		ipStr, row.ThreatScore, decision.Type, decision.Escalation)

	var expiresAt time.Time
	var expiresAtPg pgtype.Timestamptz
	if decision.Duration > 0 {
		expiresAt = time.Now().Add(decision.Duration)
		expiresAtPg = database.ToPgTimestamptz(expiresAt)
	} // else Valid=false → permanent (NULL in DB)

	// Build detailed reasons
	reasons := bm.buildBlockReasons(row)
	if decision.Escalation != "" {
		reasons = append(reasons, "Escalation: "+decision.Escalation)
	}

	// Determine IP version
	ipVersion := int32(4)
	if row.SourceIp.Is6() {
		ipVersion = 6
	}

	// Parse ASN from text to int
	asnInt := parseASN(row.Asn)

	// Get service name: prefer the process-aware value already stored in
	// traffic_events, fall back to port-based lookup for older/empty rows.
	serviceName := row.TopServiceName
	if serviceName == "" {
		serviceName = services.ServiceFromPort(int(row.TopTargetPort))
	}

	// Convert interface{} geo fields to proper pgtype
	countryCode := toPgText(row.CountryCode)
	countryName := toPgText(row.Country)
	city := toPgText(row.City)
	isp := toPgText(row.Isp)

	block, err := bm.queries.CreateBlock(ctx, database.CreateBlockParams{
		ServerID:        row.ServerID,
		UserID:          row.UserID,
		IpAddress:       row.SourceIp,
		IpVersion:       pgtype.Int4{Int32: ipVersion, Valid: true},
		ThreatScore:     row.ThreatScore,
		ThreatLevel:     decision.ThreatLevel,
		Reasons:         reasons,
		TargetPort:      pgtype.Int4{Int32: row.TopTargetPort, Valid: row.TopTargetPort > 0},
		ServiceName:     pgtype.Text{String: serviceName, Valid: serviceName != ""},
		Protocol:        pgtype.Text{String: row.TopProtocol, Valid: row.TopProtocol != ""},
		CountryCode:     countryCode,
		CountryName:     countryName,
		City:            city,
		Region:          pgtype.Text{Valid: false},
		Latitude:        pgtype.Float8{Valid: false},
		Longitude:       pgtype.Float8{Valid: false},
		Asn:             asnInt,
		AsnOrg:          isp,
		IsVpn:           pgtype.Bool{Bool: false, Valid: true},
		IsTor:           pgtype.Bool{Bool: false, Valid: true},
		IsDatacenter:    pgtype.Bool{Bool: false, Valid: true},
		BlockedAt:       database.ToPgTimestamptz(time.Now()),
		ExpiresAt:       expiresAtPg,
		DurationSeconds: int32(decision.Duration.Seconds()),
		IsAutoBlocked:   pgtype.Bool{Bool: true, Valid: true},
		AgentVersion:    pgtype.Text{Valid: false},
		RawMetrics:      nil,
		EnforcementType: string(decision.Type),
	})
	if err != nil {
		log.Printf("[BlockManager] Failed to create block for %s: %v", ipStr, err)
		return
	}

	bm.mu.Lock()
	bm.activeBlocks[ipStr] = &ActiveBlock{
		IP:              ipStr,
		ServerID:        row.ServerID,
		UserID:          row.UserID,
		Score:           int(row.ThreatScore),
		Reason:          row.ThreatType,
		EnforcementType: decision.Type,
		Duration:        decision.Duration,
		BlockedAt:       time.Now(),
		ExpiresAt:       expiresAt,
		IsPermanent:     decision.Type == EnforcementPermanent,
	}
	agentID := row.ServerID.String()
	bm.mu.Unlock()

	// Alert severity based on score
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
		Reason:      fmt.Sprintf("Auto-%s: %s (%s)", decision.Type, row.ThreatType, decision.Escalation),
		Severity:    severity,
		Status:      "active",
	})
	if err != nil {
		log.Printf("[BlockManager] Failed to create alert for %s: %v", ipStr, err)
	}

	// Map enforcement type to agent block command type
	agentBlockType := "blocklist"
	if decision.Type == EnforcementRateLimit {
		agentBlockType = "ratelimit"
	}

	bm.sendBlockCommand(agentID, ipStr, decision.Duration, row.ThreatType, agentBlockType, block.ID.String())

	if bm.hub != nil && row.UserID.Valid {
		bm.hub.BroadcastToUser(database.FromPgUUID(row.UserID), "new_block", map[string]interface{}{
			"id":               block.ID.String(),
			"block_id":         block.ID.String(),
			"ip_address":       ipStr,
			"server_id":        row.ServerID.String(),
			"server_name":      row.ServerName,
			"threat_score":     row.ThreatScore,
			"threat_level":     decision.ThreatLevel,
			"threat_type":      row.ThreatType,
			"reasons":          reasons,
			"country_code":     toString(row.CountryCode),
			"country_name":     toString(row.Country),
			"city":             toString(row.City),
			"enforcement_type": string(decision.Type),
			"duration":         decision.Duration.Seconds(),
			"blocked_at":       block.BlockedAt.Time,
			"expires_at":       expiresAt,
			"block_type":       agentBlockType,
			"escalation":       decision.Escalation,
		})
	}

	log.Printf("[BlockManager] %s %s (score=%d, duration=%v, escalation=%s)",
		decision.Type, ipStr, row.ThreatScore, decision.Duration, decision.Escalation)
}

// signCommand computes an HMAC signature over the command fields and adds
// the signature + nonce to the command map. When CMD_SIGNING_KEY is not set,
// signing is skipped (unsigned commands are still delivered, for dev/testing).
func (bm *BlockManager) signCommand(cmd map[string]interface{}) map[string]interface{} {
	key := cmdsigning.Key()
	if key == "" {
		log.Println("[BlockManager] WARNING: CMD_SIGNING_KEY not set — commands are unsigned")
		return cmd
	}

	action, _ := cmd["action"].(string)
	ip, _ := cmd["ip"].(string)
	duration, _ := cmd["duration"].(int64)
	reason, _ := cmd["reason"].(string)
	blockID, _ := cmd["block_id"].(string)

	nonce := time.Now().UnixNano()
	actedAt := time.Now().UnixNano()

	var actionCode int32
	switch action {
	case "block":
		actionCode = 0
	case "unblock":
		actionCode = 1
	case "ratelimit":
		actionCode = 2
	}

	payload := cmdsigning.BuildCanonicalPayload(actionCode, ip, duration, reason, blockID, actedAt)
	sig := cmdsigning.Sign(key, nonce, payload)

	cmd["signature"] = sig
	cmd["nonce"] = fmt.Sprintf("%d", nonce)
	return cmd
}

func (bm *BlockManager) sendBlockCommand(agentID, ip string, duration time.Duration, reason, blockType, blockID string) {
	if bm.hub == nil {
		return
	}

	cmd := bm.signCommand(map[string]interface{}{
		"action":     "block",
		"ip":         ip,
		"duration":   int64(duration.Seconds()),
		"reason":     reason,
		"block_id":   blockID,
		"block_type": blockType,
	})
	bm.hub.SendCommandToAgent(agentID, cmd)
}

func (bm *BlockManager) Unblock(ctx context.Context, ip string, reason string) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	block, exists := bm.activeBlocks[ip]
	if !exists {
		return nil
	}

	agentID := block.ServerID.String()
	cmd := bm.signCommand(map[string]interface{}{
		"action": "unblock",
		"ip":     ip,
		"reason": reason,
	})
	bm.hub.SendCommandToAgent(agentID, cmd)

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

// buildBlockReasons creates detailed reasons based on threat type and traffic metrics
func (bm *BlockManager) buildBlockReasons(row database.GetBlockableIPsRow) []string {
	reasons := []string{}

	// Add threat type as first reason
	if row.ThreatType != "" {
		reasons = append(reasons, row.ThreatType)
	}

	// Add traffic details based on threat type
	switch row.ThreatType {
	case "syn_flood":
		if row.TotalSyn > 0 {
			reasons = append(reasons, fmt.Sprintf("SYN count: %d", row.TotalSyn))
		}
	case "port_scan":
		if row.UniquePorts > 0 {
			reasons = append(reasons, fmt.Sprintf("Ports scanned: %d", row.UniquePorts))
		}
	case "service_abuse":
		if row.TopTargetPort > 0 {
			reasons = append(reasons, fmt.Sprintf("Target port: %d (%s)", row.TopTargetPort, services.ServiceFromPort(int(row.TopTargetPort))))
		}
	case "failed_handshake":
		if row.TotalFailed > 0 {
			reasons = append(reasons, fmt.Sprintf("Failed handshakes: %d", row.TotalFailed))
		}
	}

	// Add protocol info
	if row.TopProtocol != "" {
		reasons = append(reasons, fmt.Sprintf("Protocol: %s", row.TopProtocol))
	}

	// Add score info
	reasons = append(reasons, fmt.Sprintf("Threat score: %d", row.ThreatScore))

	return reasons
}

// parseASN converts ASN from interface{} (text) to pgtype.Int4
func parseASN(asn interface{}) pgtype.Int4 {
	if asn == nil {
		return pgtype.Int4{Valid: false}
	}

	switch v := asn.(type) {
	case string:
		if v == "" || v == "Unknown" {
			return pgtype.Int4{Valid: false}
		}
		// Try to parse ASN number from string (may have "AS" prefix)
		v = strings.TrimPrefix(v, "AS")
		v = strings.TrimSpace(v)
		if num, err := strconv.ParseInt(v, 10, 32); err == nil {
			return pgtype.Int4{Int32: int32(num), Valid: true}
		}
	case int:
		return pgtype.Int4{Int32: int32(v), Valid: true}
	case int32:
		return pgtype.Int4{Int32: v, Valid: true}
	case int64:
		return pgtype.Int4{Int32: int32(v), Valid: true}
	}

	return pgtype.Int4{Valid: false}
}

// toPgText converts interface{} to pgtype.Text
func toPgText(v interface{}) pgtype.Text {
	if v == nil {
		return pgtype.Text{Valid: false}
	}

	switch s := v.(type) {
	case string:
		if s == "" || s == "Unknown" {
			return pgtype.Text{Valid: false}
		}
		return pgtype.Text{String: s, Valid: true}
	default:
		str := fmt.Sprintf("%v", s)
		if str == "" || str == "Unknown" || str == "<nil>" {
			return pgtype.Text{Valid: false}
		}
		return pgtype.Text{String: str, Valid: true}
	}
}
