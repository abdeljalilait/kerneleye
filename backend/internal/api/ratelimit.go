package api

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
)

type RateLimiter struct {
	client *redis.Client
}

type RateLimitConfig struct {
	Requests  int           // Number of requests allowed
	Window    time.Duration // Time window
	KeyPrefix string        // Prefix for Redis keys
}

var (
	defaultRateLimits = map[string]RateLimitConfig{
		"auth":      {Requests: 10, Window: time.Minute, KeyPrefix: "ratelimit:auth"},
		"api":       {Requests: 100, Window: time.Minute, KeyPrefix: "ratelimit:api"},
		"agent":     {Requests: 1000, Window: time.Minute, KeyPrefix: "ratelimit:agent"},
		"websocket": {Requests: 50, Window: time.Minute, KeyPrefix: "ratelimit:ws"},
	}
)

// NewRateLimiter creates a new Redis-based rate limiter
func NewRateLimiter(redisURL string) (*RateLimiter, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	client := redis.NewClient(opt)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RateLimiter{client: client}, nil
}

// Allow checks if the request is allowed under rate limit
func (r *RateLimiter) Allow(ctx context.Context, key string, config RateLimitConfig) (bool, error) {
	redisKey := fmt.Sprintf("%s:%s", config.KeyPrefix, key)

	// Increment counter
	count, err := r.client.Incr(ctx, redisKey).Result()
	if err != nil {
		return false, err
	}

	// Set expiry on first request
	if count == 1 {
		r.client.Expire(ctx, redisKey, config.Window)
	}

	// Check if within limit
	allowed := count <= int64(config.Requests)
	return allowed, nil
}

// GetClient returns the underlying Redis client
func (r *RateLimiter) GetClient() *redis.Client {
	return r.client
}

// Close closes the Redis connection
func (r *RateLimiter) Close() error {
	return r.client.Close()
}

// RateLimitMiddleware creates a Fiber middleware for rate limiting
func RateLimitMiddleware(limiter *RateLimiter) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if limiter == nil {
			return c.Next()
		}

		// Determine rate limit config based on path
		config := getRateLimitConfig(c.Path())

		// Get identifier (IP or user ID)
		identifier := getIdentifier(c)

		// Check rate limit
		allowed, err := limiter.Allow(c.Context(), identifier, config)
		if err != nil {
			log.Printf("[RateLimit] Error checking rate limit (failing closed): %v", err)
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error":       "Rate limit service unavailable, please retry",
				"retry_after": config.Window.Seconds(),
			})
		}

		if !allowed {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error":       "Rate limit exceeded",
				"retry_after": config.Window.Seconds(),
			})
		}

		return c.Next()
	}
}

// getRateLimitConfig returns the appropriate rate limit config for the given path
func getRateLimitConfig(path string) RateLimitConfig {
	switch {
	case strings.HasPrefix(path, "/api/v1/auth"):
		return defaultRateLimits["auth"]
	case strings.HasPrefix(path, "/api/v1/ws"):
		return defaultRateLimits["websocket"]
	case strings.HasPrefix(path, "/api/v1/agent"):
		return defaultRateLimits["agent"]
	default:
		return defaultRateLimits["api"]
	}
}

// getIdentifier returns the rate limit identifier (user ID or IP)
func getIdentifier(c *fiber.Ctx) string {
	// Try to get user ID from context (set by auth middleware)
	if userID, ok := c.Locals("user_id").(string); ok && userID != "" {
		return fmt.Sprintf("user:%s", userID)
	}

	// Fall back to IP address
	return fmt.Sprintf("ip:%s", c.IP())
}

// GRPCRateLimiter provides rate limiting for gRPC calls
type GRPCRateLimiter struct {
	limiter *RateLimiter
}

// NewGRPCRateLimiter creates a new gRPC rate limiter
func NewGRPCRateLimiter(redisURL string) (*GRPCRateLimiter, error) {
	limiter, err := NewRateLimiter(redisURL)
	if err != nil {
		return nil, err
	}
	return &GRPCRateLimiter{limiter: limiter}, nil
}

// Allow checks if the gRPC request is allowed
func (g *GRPCRateLimiter) Allow(ctx context.Context, key string, requests int, window time.Duration) (bool, error) {
	config := RateLimitConfig{
		Requests:  requests,
		Window:    window,
		KeyPrefix: "ratelimit:grpc",
	}
	return g.limiter.Allow(ctx, key, config)
}

// GetLimiter returns the underlying rate limiter
func (g *GRPCRateLimiter) GetLimiter() *RateLimiter {
	return g.limiter
}

// Close closes the gRPC rate limiter
func (g *GRPCRateLimiter) Close() error {
	return g.limiter.Close()
}

// InitRateLimiterFromEnv initializes rate limiter from environment variable
func InitRateLimiterFromEnv() (*RateLimiter, error) {
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		log.Println("[RateLimit] REDIS_URL not set, rate limiting disabled")
		return nil, nil
	}
	log.Println("[RateLimit] Initializing Redis rate limiter...")
	limiter, err := NewRateLimiter(redisURL)
	if err != nil {
		log.Printf("[RateLimit] Failed to initialize rate limiter: %v", err)
		return nil, err
	}
	log.Println("[RateLimit] Redis rate limiter initialized")
	return limiter, nil
}
