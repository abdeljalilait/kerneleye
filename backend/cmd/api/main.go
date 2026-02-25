package main

import (
	"bytes"
	"context"
	"log"
	"os"
	"time"

	"net"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/kerneleye/backend/internal/analysis"
	"github.com/kerneleye/backend/internal/api"
	"github.com/kerneleye/backend/internal/database"
	"github.com/kerneleye/backend/internal/email"
	"github.com/kerneleye/backend/internal/geoip"
	"github.com/kerneleye/backend/internal/payments/polar"
	pb "github.com/kerneleye/proto/kerneleye/v1"
	"github.com/kerneleye/shared/scoring"
	"google.golang.org/grpc"
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

	// Initialize Polar Payments Client
	polarClient := polar.NewClient(polar.Config{
		AccessToken:   os.Getenv("POLAR_ACCESS_TOKEN"),
		WebhookSecret: os.Getenv("POLAR_WEBHOOK_SECRET"),
	})
	if polarClient.IsConfigured() {
		log.Println("💳 Polar Payments client initialized")
	} else {
		log.Println("⚠️  Polar Payments not configured (POLAR_ACCESS_TOKEN not set)")
	}

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName:      "KernelEye API v1.0",
		ServerHeader: "KernelEye",
		ErrorHandler: api.ErrorHandler,
	})

	// Middleware
	app.Use(recover.New())

	// Setup file logger
	logFile, err := os.OpenFile("./api.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
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
			"agentVersion": "0.4.0",
		})
	})

	// API v1 routes
	v1 := app.Group("/api/v1")

	// Public routes
	v1.Post("/auth/register", api.HandleRegister(queries))
	v1.Post("/auth/login", api.HandleLogin(queries))
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

	// Polar webhook (public, but signed) - MUST be registered BEFORE protected group
	// This ensures it doesn't inherit the AuthMiddleware from the protected group
	v1.Post("/webhooks/polar", api.HandlePolarWebhook(queries, emailService, polarClient))

	// Protected routes (require API key or JWT)
	protected := v1.Group("", api.AuthMiddleware(queries))

	// User info
	protected.Get("/auth/me", api.HandleMe(queries))

	// WebSocket endpoint
	protected.Use("/ws", api.UpgradeMiddleware)
	protected.Get("/ws", api.WebSocketHandler(hub))

	// Dashboard endpoints (used by React frontend)
	protected.Get("/servers", api.HandleListServers(queries))
	protected.Get("/servers/generate-api-key", api.HandleGenerateAPIKey(queries))
	protected.Post("/servers", api.HandleCreateServerWithConfig(queries))
	protected.Patch("/servers/:id/status", api.HandleUpdateServerStatus(queries, hub))
	protected.Get("/servers/:id", api.HandleGetServer(queries))
	protected.Get("/servers/:id/traffic", api.HandleServerTraffic(queries))
	protected.Get("/servers/:id/port-traffic", api.HandleServerPortTraffic(queries))
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

	// Blocks endpoints
	protected.Get("/blocks", api.HandleListBlocks(queries))
	protected.Get("/blocks/stats", api.HandleGetBlockStats(queries))
	protected.Post("/blocks/:ip/unblock", api.HandleUnblockIP(queries, hub))

	// Whitelist endpoints
	protected.Get("/whitelist", api.HandleListWhitelist(queries))
	protected.Post("/whitelist", api.HandleAddToWhitelist(queries, hub))
	protected.Delete("/whitelist/:ip", api.HandleRemoveFromWhitelist(queries, hub))
	protected.Get("/whitelist/check", api.HandleCheckWhitelist(queries))

	// Subscription endpoints (Polar)
	protected.Get("/subscription/plans", api.HandleListPlans(queries))
	protected.Get("/subscription/status", api.HandleGetSubscriptionStatus(queries))
	protected.Post("/subscription/checkout", api.HandleCreateCheckout(queries, polarClient))
	protected.Post("/subscription/portal", api.HandleCreateCustomerPortal(queries, polarClient))
	protected.Get("/subscription/debug", api.HandlePolarDebug(polarClient, queries))

	// gRPC Server setup
	grpcPort := os.Getenv("GRPC_PORT")
	if grpcPort == "" {
		grpcPort = "9091"
	}

	lis, err := net.Listen("tcp", ":"+grpcPort)
	if err != nil {
		log.Fatalf("Failed to listen for gRPC: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterIngestServiceServer(grpcServer, api.NewGrpcIngestHandler(queries, scorer, hub, geoIP))
	pb.RegisterBlockServiceServer(grpcServer, api.NewBlockHandler(queries, hub, geoIP))

	go func() {
		log.Printf("📡 KernelEye gRPC Ingestion listening on port %s\n", grpcPort)
		if err := grpcServer.Serve(lis); err != nil {
			log.Printf("gRPC server error: %v", err)
		}
	}()

	// Start scoring worker for accumulated traffic analysis
	analysisWorker := analysis.NewWorker(analysis.WorkerConfig{
		Interval:       30 * time.Second,
		ScoreThreshold: 30,
		BlockThreshold: 60,
		TimeWindowMins: 5,
		MinEvents:      3,
	}, queries, hub)
	go analysisWorker.Start(ctx)

	// Start block manager for automatic blocking
	blockManager := analysis.NewBlockManager(analysis.BlockManagerConfig{
		AutoBlockEnabled:  true,
		BlockThreshold:    60,
		BaseBlockDuration: 1 * time.Hour,
		MaxBlockDuration:  24 * time.Hour,
		CheckInterval:     30 * time.Second,
	}, queries, hub)
	go blockManager.Start(ctx)

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
