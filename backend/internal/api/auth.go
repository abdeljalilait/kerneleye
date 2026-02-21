package api

import (
	"log"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kerneleye/backend/internal/database"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret []byte

func init() {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "default-jwt-secret-change-in-production"
	}
	jwtSecret = []byte(secret)
}

// Claims represents JWT claims
type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

// GenerateJWT creates a new JWT token for a user
func GenerateJWT(userID, email string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "kerneleye",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// ValidateJWT validates a JWT token and returns the claims
func ValidateJWT(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		return nil, err
	}

	return claims, nil
}

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPassword compares a password with a hash
func CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// AuthMiddleware validates API keys or JWT tokens
func AuthMiddleware(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Check for API key in header (agent authentication)
		apiKey := c.Get("X-API-Key")
		if apiKey != "" {
			// Step 1: Validate API key format and HMAC signature
			if !strings.HasPrefix(apiKey, "ke_") {
				return fiber.NewError(fiber.StatusUnauthorized, "Invalid API key format")
			}

			// Step 2: Verify HMAC signature (cryptographic validation)
			decodedUserID, decodedServerID, err := DecodeAPIKey(apiKey)
			if err != nil {
				log.Printf("[Auth] API key HMAC verification failed from %s: %v", c.IP(), err)
				return fiber.NewError(fiber.StatusUnauthorized, "Invalid API key signature")
			}

			// Step 3: Validate against database (ensure key exists and matches)
			server, err := queries.GetServerByAPIKey(c.Context(), database.ToPgText(apiKey))
			if err != nil {
				log.Printf("[Auth] API key not found in database from %s", c.IP())
				return fiber.NewError(fiber.StatusUnauthorized, "Invalid API key")
			}

			// Step 4: Verify decoded userID/serverID matches database record
			// This prevents replay attacks with forged keys
			if decodedUserID != database.FromPgUUID(server.UserID) ||
				decodedServerID != database.FromPgUUID(server.ID) {
				log.Printf("[Auth] API key mismatch: decoded=%s/%s, expected=%s/%s from %s",
					decodedUserID, decodedServerID,
					database.FromPgUUID(server.UserID), database.FromPgUUID(server.ID),
					c.IP())
				return fiber.NewError(fiber.StatusUnauthorized, "Invalid API key")
			}

			// Step 5: Check server status
			if server.Status == "deleted" || server.Status == "rejected" {
				return fiber.NewError(fiber.StatusForbidden, "Server access revoked")
			}

			c.Locals("server_id", database.FromPgUUID(server.ID))
			c.Locals("user_id", database.FromPgUUID(server.UserID))
			c.Locals("api_key", apiKey)
			c.Locals("auth_type", "agent")
			return c.Next()
		}

		// Check for Bearer token (dashboard authentication)
		authHeader := c.Get("Authorization")
		var token string

		if authHeader != "" {
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				return fiber.NewError(fiber.StatusUnauthorized, "Invalid authorization header")
			}
			token = parts[1]
		} else {
			// Check query parameter (common for WebSockets)
			token = c.Query("token")
		}

		if token == "" {
			return fiber.NewError(fiber.StatusUnauthorized, "Missing authentication")
		}

		// Validate JWT token
		claims, err := ValidateJWT(token)
		if err != nil {
			return fiber.NewError(fiber.StatusUnauthorized, "Invalid or expired token")
		}

		c.Locals("user_id", claims.UserID)
		c.Locals("email", claims.Email)
		c.Locals("auth_type", "dashboard")

		return c.Next()
	}
}

// ErrorHandler provides consistent error responses
func ErrorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	message := "Internal Server Error"

	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
		message = e.Message
	}

	return c.Status(code).JSON(fiber.Map{
		"error": message,
		"code":  code,
	})
}

// HandleRegister creates a new user account (DISABLED - OAuth only)
func HandleRegister(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		return fiber.NewError(fiber.StatusForbidden, "Account registration is only available via GitHub or Google OAuth. Please use the social login buttons above.")
	}
}

// HandleLogin authenticates a user
func HandleLogin(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		type LoginRequest struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		var req LoginRequest
		if err := c.BodyParser(&req); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
		}

		user, err := queries.GetUserByEmail(c.Context(), req.Email)
		if err != nil {
			return fiber.NewError(fiber.StatusUnauthorized, "Invalid credentials")
		}

		// Verify password
		if !CheckPassword(req.Password, user.PasswordHash) {
			return fiber.NewError(fiber.StatusUnauthorized, "Invalid credentials")
		}

		// Generate JWT token
		token, err := GenerateJWT(database.FromPgUUID(user.ID), user.Email)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to generate token")
		}

		return c.JSON(fiber.Map{
			"user":  user,
			"token": token,
		})
	}
}

// HandleMe returns the current user's info
func HandleMe(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := c.Locals("user_id")
		if userID == nil {
			return fiber.NewError(fiber.StatusUnauthorized, "Not authenticated")
		}

		user, err := queries.GetUserByID(c.Context(), database.ToPgUUID(userID.(string)))
		if err != nil {
			return fiber.NewError(fiber.StatusNotFound, "User not found")
		}

		return c.JSON(fiber.Map{
			"id":    database.FromPgUUID(user.ID),
			"email": user.Email,
			"plan":  user.Plan,
		})
	}
}
