// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	fiberrecover "github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/kerneleye/backend/internal/analysis"
	"github.com/kerneleye/backend/internal/api"
	"github.com/kerneleye/backend/internal/database"
	"github.com/kerneleye/backend/internal/email"
	"github.com/kerneleye/backend/internal/geoip"
	pb "github.com/kerneleye/proto/kerneleye/v1"
	"github.com/kerneleye/shared/scoring"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var AppVersion = "dev"

func init() {
	if data, err := os.ReadFile("VERSION"); err == nil {
		AppVersion = string(bytes.TrimSpace(data))
	}
}

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment")
	}

	// Initialize database
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}

	ctx := context.Background()
	dbpool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer dbpool.Close()

	// Test connection
	if err := dbpool.Ping(ctx); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	log.Println("✅ Database connected")

	// Create sqlc queries instance
	queries := database.New(dbpool)

	// Initialize scoring engine
	scorer := scoring.NewThreatScorer()

	// Initialize WebSocket Hub
	hub := api.NewHub()
	go hub.Run()

	// Initialize Rate Limiter
	rateLimiter, err := api.InitRateLimiterFromEnv()
	if err != nil {
		log.Printf("Warning: Rate limiter initialization failed: %v", err)
	}
	if rateLimiter != nil {
		defer rateLimiter.Close()
	}

	// Initialize Email Service
	emailService := email.NewService()
	if emailService != nil && emailService.IsEnabled() {
		log.Println("📧 Email service initialized (Mailtrap)")
	} else {
		log.Println("⚠️  Email service not configured (MAILTRAP_API_TOKEN not set)")
	}

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName:      "KernelEye API v1.0",
		ServerHeader: "KernelEye",
		ErrorHandler: api.ErrorHandler,
	})

	// Middleware
	app.Use(fiberrecover.New())

	// Setup file logger
	logFile, err := os.OpenFile("./api.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0640)
	if err != nil {
		log.Printf("Warning: Could not open log file: %v, using stdout", err)
		logFile = os.Stdout
	}

	app.Use(logger.New(logger.Config{
		Format:     "${time} | ${status} | ${latency} | ${method} ${path} | ${error}\n",
		TimeFormat: "2006-01-02 15:04:05",
		Output:     logFile,
	}))
	corsOrigins := os.Getenv("CORS_ORIGINS")
	if corsOrigins == "" {
		corsOrigins = "http://localhost:3000,http://localhost:5173,https://app.kerneleye.net"
	}

	app.Use(cors.New(cors.Config{
		AllowOrigins:     corsOrigins,
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
		AllowCredentials: true,
	}))

	// Rate limiting (if configured)
	if rateLimiter != nil {
		app.Use(api.RateLimitMiddleware(rateLimiter))
	}

	// Health check
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "healthy",
			"service": "kerneleye-api",
			"version": AppVersion,
		})
	})

	// Version endpoint
	app.Get("/version", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"version":      AppVersion,
			"agent":        "kerneleye-agent",
			"agentVersion": AppVersion,
		})
	})

	// API v1 routes
	v1 := app.Group("/api/v1")

	// Public routes
	v1.Post("/auth/refresh", api.HandleRefreshToken(queries))
	v1.Get("/auth/providers", api.HandleGetAuthProviders())

	// OAuth routes
	v1.Get("/auth/github", api.HandleGitHubLogin())
	v1.Get("/auth/github/callback", api.HandleGitHubCallback(queries))
	v1.Get("/auth/google", api.HandleGoogleLogin())
	v1.Get("/auth/google/callback", api.HandleGoogleCallback(queries))

	// Initialize GeoIP Service
	geoipDir := os.Getenv("GEOIP_DIR")
	if geoipDir == "" {
		geoipDir = "/opt/kerneleye/geoip" // Default from script
	}
	geoIP, err := geoip.NewService(geoipDir)
	if err != nil {
		log.Printf("⚠️ GeoIP service failed to initialize: %v (continuing without enrichment)", err)
		// Proceed with nil service (handlers should handle nil)
	} else {
		log.Println("🌍 GeoIP service initialized")
		defer geoIP.Close()
	}

	// Start scoring worker for accumulated traffic analysis (must be before routes that need it)
	analysisWorker := analysis.NewWorker(analysis.WorkerConfig{
		Interval:       30 * time.Second,
		ScoreThreshold: 30,
		BlockThreshold: 60,
		TimeWindowMins: 5,
		MinEvents:      3,
	}, queries, hub)
	go analysisWorker.Start(ctx)

	// Start block manager for automatic blocking (must be before routes that need it)
	blockManager := analysis.NewBlockManager(analysis.BlockManagerConfig{
		AutoBlockEnabled:  true,
		BlockThreshold:    60,
		BaseBlockDuration: 1 * time.Hour,
		MaxBlockDuration:  24 * time.Hour,
		CheckInterval:     30 * time.Second,
	}, queries, hub)
	go blockManager.Start(ctx)

	// Mark servers offline when no heartbeat received within 2 minutes (4 missed beats at 30s interval)
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		const staleThresholdSeconds = 120
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n, err := queries.MarkStaleServersOffline(context.Background(), staleThresholdSeconds)
				if err != nil {
					log.Printf("[StaleChecker] Error marking stale servers offline: %v", err)
				} else if n > 0 {
					log.Printf("[StaleChecker] Marked %d server(s) offline (no heartbeat in %ds)", n, staleThresholdSeconds)
				}
			}
		}
	}()

	// Start data retention manager for archiving old traffic data
	dataRetention := analysis.NewDataRetentionManager(queries, analysis.DefaultDataRetentionConfig())
	dataRetention.Start(ctx)
	defer dataRetention.Stop()

	// Start monthly report manager
	monthlyReports := analysis.NewMonthlyReportManager(queries, emailService)
	monthlyReports.Start(ctx)
	defer monthlyReports.Stop()

	// Protected routes (require API key or JWT)
	protected := v1.Group("", api.AuthMiddleware(queries))

	// User info
	protected.Get("/auth/me", api.HandleMe(queries))

	// WebSocket endpoint
	protected.Use("/ws", api.UpgradeMiddleware)
	protected.Get("/ws", api.WebSocketHandler(hub))

	// Dashboard endpoints (used by React frontend)
	protected.Get("/servers", api.HandleListServers(queries, geoIP))
	protected.Get("/servers/generate-api-key", api.HandleGenerateAPIKey(queries))
	protected.Post("/servers", api.HandleCreateServerWithConfig(queries))
	protected.Patch("/servers/:id/status", api.HandleUpdateServerStatus(queries, hub))
	protected.Get("/servers/:id", api.HandleGetServer(queries))
	protected.Get("/servers/:id/traffic", api.HandleServerTraffic(queries))
	protected.Get("/servers/:id/port-traffic", api.HandleServerPortTraffic(queries))
	protected.Get("/servers/:id/port-traffic/:port/sources", api.HandleServerPortSources(queries))
	protected.Get("/servers/:id/protocol-traffic", api.HandleServerProtocolTraffic(queries))
	protected.Get("/servers/:id/stats", api.HandleServerStats(queries))
	protected.Get("/servers/:id/config", api.HandleGetServerConfig(queries))
	protected.Patch("/servers/:id/config", api.HandleUpdateServerConfig(queries, hub))
	protected.Delete("/servers/:id", api.HandleDeleteServer(queries))

	// Agent configuration endpoints
	protected.Get("/deployment-modes", api.HandleGetDeploymentModes)
	protected.Get("/agent-features", api.HandleGetAgentFeatures)
	protected.Get("/threats", api.HandleListThreats(queries))
	protected.Get("/alerts", api.HandleListAlerts(queries))
	protected.Get("/stats/overview", api.HandleStatsOverview(queries))

	// Analytics endpoints (Reports & Visualizer)
	protected.Get("/analytics/daily-attacks", api.HandleGetDailyAttackStats(queries))
	protected.Get("/analytics/daily-blocks", api.HandleGetDailyBlockStats(queries))
	protected.Get("/analytics/attack-types", api.HandleGetAttackTypeBreakdown(queries))
	protected.Get("/analytics/top-countries", api.HandleGetTopSourceCountries(queries))
	protected.Get("/analytics/hourly-distribution", api.HandleGetHourlyAttackDistribution(queries))
	protected.Get("/analytics/threat-trends", api.HandleGetThreatTrends(queries))
	protected.Get("/analytics/top-source-ips", api.HandleGetTopSourceIPs(queries))
	protected.Get("/analytics/top-asns", api.HandleGetTopASNs(queries))
	protected.Get("/analytics/ip-timeline", api.HandleGetSourceIPTimeline(queries))
	protected.Get("/analytics/ip-block-times", api.HandleGetSourceIPBlockTimes(queries))
	protected.Get("/analytics/top-ips-timeline", api.HandleGetTopIPsTimeline(queries))

	// Blocks endpoints
	protected.Get("/blocks", api.HandleListBlocks(queries))
	protected.Get("/blocks/stats", api.HandleGetBlockStats(queries))
	protected.Post("/blocks/:ip/unblock", api.HandleUnblockIP(queries, hub, blockManager))

	// Whitelist endpoints
	protected.Get("/whitelist", api.HandleListWhitelist(queries))
	protected.Post("/whitelist", api.RequireDashboardAuth(), api.HandleAddToWhitelist(queries, hub))
	protected.Delete("/whitelist/:ip", api.RequireDashboardAuth(), api.HandleRemoveFromWhitelist(queries, hub))
	protected.Get("/whitelist/check", api.HandleCheckWhitelist(queries))

	// gRPC Server setup with optional TLS/mTLS
	grpcPort := os.Getenv("GRPC_PORT")
	if grpcPort == "" {
		grpcPort = "9091"
	}

	lis, err := net.Listen("tcp", ":"+grpcPort)
	if err != nil {
		log.Fatalf("Failed to listen for gRPC: %v", err)
	}

	grpcServer := grpc.NewServer(append(buildGRPCServerOptions(), grpc.UnaryInterceptor(grpcPanicRecovery), grpc.StreamInterceptor(grpcStreamPanicRecovery))...)
	pb.RegisterIngestServiceServer(grpcServer, api.NewGrpcIngestHandler(queries, scorer, hub, geoIP))
	pb.RegisterBlockServiceServer(grpcServer, api.NewBlockHandler(queries, hub, geoIP))

	go func() {
		tlsStatus := "plaintext"
		if grpcHasTLS() {
			tlsStatus = "TLS"
			if os.Getenv("GRPC_MTLS_CA_FILE") != "" {
				tlsStatus = "mTLS"
			}
		}
		log.Printf("📡 KernelEye gRPC Ingestion listening on port %s (%s)\n", grpcPort, tlsStatus)
		if !grpcHasTLS() {
			log.Printf("⚠️  WARNING: gRPC server running without TLS. Set GRPC_TLS_CERT_FILE and GRPC_TLS_KEY_FILE for production.")
		}
		if err := grpcServer.Serve(lis); err != nil {
			log.Printf("gRPC server error: %v", err)
		}
	}()

	// Start HTTP server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("🚀 KernelEye API listening on port %s\n", port)
	if err := app.Listen(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func grpcPanicRecovery(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("PANIC in gRPC unary handler %s: %v", info.FullMethod, r)
			err = status.Errorf(codes.Internal, "internal server error")
		}
	}()
	return handler(ctx, req)
}

func grpcStreamPanicRecovery(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("PANIC in gRPC stream handler %s: %v", info.FullMethod, r)
			err = status.Errorf(codes.Internal, "internal server error")
		}
	}()
	return handler(srv, ss)
}

// grpcHasTLS reports whether the gRPC server is configured for TLS.
func grpcHasTLS() bool {
	return os.Getenv("GRPC_TLS_CERT_FILE") != "" && os.Getenv("GRPC_TLS_KEY_FILE") != ""
}

// buildGRPCServerOptions returns gRPC server options with TLS/mTLS if configured.
func buildGRPCServerOptions() []grpc.ServerOption {
	certFile := os.Getenv("GRPC_TLS_CERT_FILE")
	keyFile := os.Getenv("GRPC_TLS_KEY_FILE")

	if certFile == "" && keyFile == "" {
		// No TLS configured — plaintext (dev mode, or behind TLS-terminating proxy).
		// The agent should use the --insecure flag to connect when this is the case.
		return nil
	}

	if certFile == "" || keyFile == "" {
		log.Fatalf("Incomplete gRPC TLS configuration: both GRPC_TLS_CERT_FILE and GRPC_TLS_KEY_FILE must be set (got cert=%q key=%q)",
			certFile, keyFile)
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("Failed to load gRPC TLS certificate (cert=%s, key=%s): %v", certFile, keyFile, err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	// mTLS: verify client certificates against a custom CA
	caFile := os.Getenv("GRPC_MTLS_CA_FILE")
	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			log.Fatalf("Failed to read mTLS CA certificate from %s: %v", caFile, err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caPEM) {
			log.Fatalf("Failed to parse mTLS CA certificate from %s", caFile)
		}
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		tlsConfig.ClientCAs = caCertPool
		log.Printf("🔐 gRPC mTLS enabled: client certificates required (CA: %s)", caFile)
	} else {
		log.Printf("🔐 gRPC TLS enabled (server cert only, no client cert verification)")
	}

	return []grpc.ServerOption{grpc.Creds(credentials.NewTLS(tlsConfig))}
}
