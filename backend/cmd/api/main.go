package main

import (
	"context"
	"log"
	"os"

	"net"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/kerneleye/backend/internal/api"
	"github.com/kerneleye/backend/internal/database"
	"github.com/kerneleye/backend/internal/email"
	"github.com/kerneleye/backend/internal/geoip"
	"github.com/kerneleye/backend/internal/scoring"
	pb "github.com/kerneleye/proto/kerneleye/v1"
	"google.golang.org/grpc"
)

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

	// Initialize Email Service
	emailService := email.NewService()
	if emailService != nil && emailService.IsEnabled() {
		log.Println("📧 Email service initialized")
	} else {
		log.Println("⚠️  Email service not configured (SENDGRID_API_KEY not set)")
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
		corsOrigins = "http://localhost:3000,http://localhost:5173,https://app.kerneleye.cloud"
	}

	app.Use(cors.New(cors.Config{
		AllowOrigins:     corsOrigins,
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
		AllowCredentials: true,
	}))

	// Health check
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "healthy",
			"service": "kerneleye-api",
			"version": "1.0.0",
		})
	})

	// API v1 routes
	v1 := app.Group("/api/v1")

	// Public routes
	v1.Post("/auth/register", api.HandleRegister(queries))
	v1.Post("/auth/login", api.HandleLogin(queries))

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
	protected.Patch("/servers/:id/status", api.HandleUpdateServerStatus(queries, hub))
	protected.Get("/servers/:id", api.HandleGetServer(queries))
	protected.Get("/servers/:id/traffic", api.HandleServerTraffic(queries))
	protected.Get("/servers/:id/stats", api.HandleServerStats(queries))
	protected.Delete("/servers/:id", api.HandleDeleteServer(queries))
	protected.Get("/threats", api.HandleListThreats(queries))
	protected.Get("/alerts", api.HandleListAlerts(queries))
	protected.Get("/stats/overview", api.HandleStatsOverview(queries))

	// Subscription endpoints
	protected.Get("/subscription/plans", api.HandleListPlans(queries))
	protected.Get("/subscription/status", api.HandleGetSubscriptionStatus(queries))
	protected.Post("/subscription/checkout", api.HandleCreateCheckout(queries))
	
	// Polar webhook (public, but signed)
	v1.Post("/webhooks/polar", api.HandlePolarWebhook(queries, emailService))

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

	go func() {
		log.Printf("📡 KernelEye gRPC Ingestion listening on port %s\n", grpcPort)
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
