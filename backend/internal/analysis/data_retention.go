// Package analysis provides traffic analysis and data retention
package analysis

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/kerneleye/backend/internal/database"
)

// DataRetentionManager handles archiving and cleanup of old traffic data
type DataRetentionManager struct {
	queries    *database.Queries
	stopChan   chan struct{}
	wg         sync.WaitGroup
	config     DataRetentionConfig
}

// DataRetentionConfig configuration for data retention
type DataRetentionConfig struct {
	// How often to run the archival job
	ArchiveInterval time.Duration
	// How often to run cleanup of old archives
	CleanupInterval time.Duration
}

// DefaultDataRetentionConfig returns sensible defaults
func DefaultDataRetentionConfig() DataRetentionConfig {
	return DataRetentionConfig{
		ArchiveInterval:  6 * time.Hour,  // Archive every 6 hours
		CleanupInterval:  24 * time.Hour, // Cleanup once a day
	}
}

// NewDataRetentionManager creates a new data retention manager
func NewDataRetentionManager(queries *database.Queries, config DataRetentionConfig) *DataRetentionManager {
	return &DataRetentionManager{
		queries:  queries,
		stopChan: make(chan struct{}),
		config:   config,
	}
}

// Start begins the data retention background jobs
func (drm *DataRetentionManager) Start(ctx context.Context) {
	drm.wg.Add(1)
	go drm.archiveLoop(ctx)
	
	log.Printf("[DataRetention] Started with archive interval: %v, cleanup interval: %v",
		drm.config.ArchiveInterval, drm.config.CleanupInterval)
}

// Stop gracefully stops the data retention manager
func (drm *DataRetentionManager) Stop() {
	close(drm.stopChan)
	drm.wg.Wait()
	log.Println("[DataRetention] Stopped")
}

// archiveLoop periodically archives old traffic events
func (drm *DataRetentionManager) archiveLoop(ctx context.Context) {
	defer drm.wg.Done()

	archiveTicker := time.NewTicker(drm.config.ArchiveInterval)
	defer archiveTicker.Stop()

	cleanupTicker := time.NewTicker(drm.config.CleanupInterval)
	defer cleanupTicker.Stop()

	// Run immediately on start
	drm.runArchival(ctx)

	for {
		select {
		case <-archiveTicker.C:
			drm.runArchival(ctx)
		case <-cleanupTicker.C:
			drm.runCleanup(ctx)
		case <-ctx.Done():
			return
		case <-drm.stopChan:
			return
		}
	}
}

// runArchival archives old traffic events for all servers
func (drm *DataRetentionManager) runArchival(ctx context.Context) {
	start := time.Now()
	log.Println("[DataRetention] Starting archival job...")

	// Get all servers with their retention settings
	servers, err := drm.queries.GetAllServersWithRetention(ctx)
	if err != nil {
		log.Printf("[DataRetention] Failed to get servers: %v", err)
		return
	}

	totalArchived := int64(0)
	for _, server := range servers {
		// Archive traffic events for this server
		archivedCount, err := drm.archiveServerTraffic(ctx, server.ServerID, int32(server.RetentionDays))
		if err != nil {
			log.Printf("[DataRetention] Failed to archive server %s: %v", 
				database.FromPgUUID(server.ServerID), err)
			continue
		}
		totalArchived += archivedCount
	}

	log.Printf("[DataRetention] Archival complete: %d events archived in %v", 
		totalArchived, time.Since(start))
}

// archiveServerTraffic archives old traffic events for a specific server
// Uses the database function for atomic move
func (drm *DataRetentionManager) archiveServerTraffic(ctx context.Context, serverID pgtype.UUID, retentionDays int32) (int64, error) {
	result, err := drm.queries.ArchiveTrafficEvents(ctx, database.ArchiveTrafficEventsParams{
		PServerID:      serverID,
		PRetentionDays: retentionDays,
	})
	if err != nil {
		return 0, fmt.Errorf("archive failed: %w", err)
	}
	
	return int64(result), nil
}

// runCleanup deletes archived data older than 1 year
func (drm *DataRetentionManager) runCleanup(ctx context.Context) {
	start := time.Now()
	log.Println("[DataRetention] Starting cleanup of old archives...")

	deletedCount, err := drm.queries.CleanupOldArchives(ctx)
	if err != nil {
		log.Printf("[DataRetention] Cleanup failed: %v", err)
		return
	}

	log.Printf("[DataRetention] Cleanup complete: %d old archives deleted in %v", 
		deletedCount, time.Since(start))
}

// ArchiveNow triggers an immediate archival (for testing/manual use)
func (drm *DataRetentionManager) ArchiveNow(ctx context.Context) error {
	drm.runArchival(ctx)
	return nil
}

// CleanupNow triggers an immediate cleanup (for testing/manual use)
func (drm *DataRetentionManager) CleanupNow(ctx context.Context) error {
	drm.runCleanup(ctx)
	return nil
}
