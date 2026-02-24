package analysis

import (
	"context"
	"log"
	"time"

	"github.com/kerneleye/backend/internal/database"
	"github.com/kerneleye/shared/scoring"
)

type WorkerConfig struct {
	Interval       time.Duration
	ScoreThreshold int
	BlockThreshold int
	TimeWindowMins int
	MinEvents      int
}

type Worker struct {
	config  WorkerConfig
	queries *database.Queries
	scorer  *scoring.ThreatScorer
	hub     interface {
		BroadcastToUser(userID string, eventType string, data interface{})
	}
	stopChan chan struct{}
}

func NewWorker(cfg WorkerConfig, queries *database.Queries, hub interface {
	BroadcastToUser(userID string, eventType string, data interface{})
}) *Worker {
	return &Worker{
		config:   cfg,
		queries:  queries,
		scorer:   scoring.NewThreatScorer(),
		hub:      hub,
		stopChan: make(chan struct{}, 1),
	}
}

func (w *Worker) Start(ctx context.Context) {
	ticker := time.NewTicker(w.config.Interval)
	defer ticker.Stop()

	log.Printf("[ScoringWorker] Started with interval=%v, threshold=%d",
		w.config.Interval, w.config.ScoreThreshold)

	for {
		select {
		case <-ticker.C:
			w.runScoring(ctx)
		case <-ctx.Done():
			log.Printf("[ScoringWorker] Shutting down...")
			return
		case <-w.stopChan:
			log.Printf("[ScoringWorker] Stopped")
			return
		}
	}
}

func (w *Worker) Stop() {
	w.stopChan <- struct{}{}
}

func (w *Worker) runScoring(ctx context.Context) {
	startTime := time.Now()

	servers, err := w.queries.ListAllActiveServers(ctx)
	if err != nil {
		log.Printf("[ScoringWorker] Failed to list servers: %v", err)
		return
	}

	totalScored := 0
	totalBlockable := 0

	for _, server := range servers {
		if err := w.scoreServerTraffic(ctx, server); err != nil {
			log.Printf("[ScoringWorker] Failed to score traffic for server %s: %v",
				server.Hostname, err)
			continue
		}

		blockable, err := w.processBlockableTraffic(ctx, server)
		if err != nil {
			log.Printf("[ScoringWorker] Failed to process blockable for server %s: %v",
				server.Hostname, err)
			continue
		}

		totalScored++
		totalBlockable += blockable
	}

	log.Printf("[ScoringWorker] Scored %d servers, found %d blockable IPs in %v",
		totalScored, totalBlockable, time.Since(startTime))
}

func (w *Worker) scoreServerTraffic(ctx context.Context, server database.ListAllActiveServersRow) error {
	windowStart := time.Now().Add(-time.Duration(w.config.TimeWindowMins) * time.Minute)

	agg, err := w.queries.GetTrafficAggregationByIP(ctx, database.GetTrafficAggregationByIPParams{
		ServerID: server.ID,
		LastSeen: database.ToPgTimestamptz(windowStart),
	})
	if err != nil {
		return err
	}

	for _, row := range agg {
		if row.EventCount < int32(w.config.MinEvents) {
			continue
		}

		metrics := w.buildMetrics(row)
		score := w.scorer.CalculateScore(metrics)

		err := w.queries.UpdateTrafficScore(ctx, database.UpdateTrafficScoreParams{
			ServerID:    server.ID,
			SourceIp:    row.SourceIp,
			ThreatScore: int32(score.Score),
			ThreatLevel: string(score.Level),
			ThreatType:  database.ToPgText(string(score.Type)),
		})
		if err != nil {
			log.Printf("[ScoringWorker] Failed to update score for %s: %v", row.SourceIp, err)
		}
	}

	return nil
}

func (w *Worker) processBlockableTraffic(ctx context.Context, server database.ListAllActiveServersRow) (int, error) {
	windowStart := time.Now().Add(-time.Duration(w.config.TimeWindowMins) * time.Minute)

	blockable, err := w.queries.GetBlockableIPs(ctx, database.GetBlockableIPsParams{
		LastSeen:    database.ToPgTimestamptz(windowStart),
		ThreatScore: int32(w.config.BlockThreshold),
	})
	if err != nil {
		return 0, err
	}

	count := 0
	for _, row := range blockable {
		if row.ServerID != server.ID {
			continue
		}

		count++

		if w.hub != nil && row.UserID.Valid {
			w.hub.BroadcastToUser(database.FromPgUUID(row.UserID), "threat_detected", map[string]interface{}{
				"source_ip":    row.SourceIp.String(),
				"server_id":    row.ServerID.String(),
				"server_name":  row.ServerName,
				"threat_score": row.ThreatScore,
				"threat_level": row.ThreatLevel,
				"threat_type":  row.ThreatType,
				"total_syn":    row.TotalSyn,
				"total_failed": row.TotalFailed,
				"unique_ports": row.UniquePorts,
				"country":      row.Country.String,
				"city":         row.City.String,
				"isp":          row.Isp.String,
				"last_seen":    row.LastSeen,
			})
		}
	}

	return count, nil
}

func (w *Worker) buildMetrics(row database.GetTrafficAggregationByIPRow) scoring.IPMetrics {
	windowStart, ok := row.WindowStart.(time.Time)
	if !ok {
		windowStart = time.Now().Add(-time.Minute * 10)
	}
	windowEnd, ok := row.WindowEnd.(time.Time)
	if !ok {
		windowEnd = time.Now()
	}

	windowDuration := windowEnd.Sub(windowStart).Seconds()
	if windowDuration < 1 {
		windowDuration = 1
	}

	established := int(row.AckCount) - int(row.SynCount)
	if established < 0 {
		established = 0
	}

	return scoring.IPMetrics{
		SYNCount:               int(row.SynCount),
		ACKCount:               int(row.AckCount),
		FailedHandshakes:       int(row.FailedHandshakes),
		UniquePorts:            int(row.PortCount),
		TotalConnections:       int(row.SynCount + row.AckCount),
		BytesIn:                uint64(row.BytesIn),
		BytesOut:               uint64(row.BytesOut),
		WindowStart:            windowStart,
		WindowEnd:              windowEnd,
		EstablishedConnections: established,
		PreviousScore:          int(row.MaxThreatScore),
	}
}
