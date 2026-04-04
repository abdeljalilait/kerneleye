package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/kerneleye/backend/internal/database"
)

// GenerateAPIKey creates a unique API key for a server
// Format: ke_<base64(userID.serverID.timestamp.signature)>
func GenerateAPIKey(userID, serverID string) string {
	secret := os.Getenv("API_KEY_SECRET")
	if secret == "" {
		log.Fatal("FATAL: API_KEY_SECRET environment variable is required but not set")
	}

	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	payload := fmt.Sprintf("%s.%s.%s", userID, serverID, timestamp)

	// Create HMAC signature
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(payload))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	// Combine payload and signature
	fullKey := fmt.Sprintf("%s.%s", payload, signature)
	encodedKey := base64.RawURLEncoding.EncodeToString([]byte(fullKey))

	return "ke_" + encodedKey
}

// DecodeAPIKey decodes and validates an API key, returning userID and serverID
// Returns error if signature is invalid or format is wrong
func DecodeAPIKey(apiKey string) (userID, serverID string, err error) {
	if !strings.HasPrefix(apiKey, "ke_") {
		return "", "", fmt.Errorf("invalid API key format: must start with 'ke_'")
	}

	encodedKey := strings.TrimPrefix(apiKey, "ke_")
	decoded, err := base64.RawURLEncoding.DecodeString(encodedKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode API key: %w", err)
	}

	parts := strings.Split(string(decoded), ".")
	if len(parts) != 4 {
		return "", "", fmt.Errorf("invalid API key structure: expected 4 parts, got %d", len(parts))
	}

	userID = parts[0]
	serverID = parts[1]
	// timestamp = parts[2]
	signature := parts[3]

	// Verify signature
	secret := os.Getenv("API_KEY_SECRET")
	if secret == "" {
		return "", "", fmt.Errorf("API_KEY_SECRET environment variable is required but not set")
	}

	payload := fmt.Sprintf("%s.%s.%s", parts[0], parts[1], parts[2])
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(payload))
	expectedSig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		return "", "", fmt.Errorf("invalid API key signature: possible forgery attempt")
	}

	return userID, serverID, nil
}

// ValidateAPIKey performs full API key validation including HMAC and database lookup
// Returns the server record if valid, error otherwise
func ValidateAPIKey(ctx context.Context, queries *database.Queries, apiKey string) (database.Server, error) {
	var emptyServer database.Server

	// Step 1: Format validation
	if !strings.HasPrefix(apiKey, "ke_") {
		return emptyServer, fmt.Errorf("invalid API key format")
	}

	if len(apiKey) < 20 {
		return emptyServer, fmt.Errorf("API key too short")
	}

	// Step 2: HMAC signature verification (cryptographic proof of authenticity)
	decodedUserID, decodedServerID, err := DecodeAPIKey(apiKey)
	if err != nil {
		log.Printf("[ValidateAPIKey] HMAC verification failed: %v", err)
		return emptyServer, fmt.Errorf("invalid API key signature")
	}

	// Step 3: Database lookup
	server, err := queries.GetServerByAPIKey(ctx, database.ToPgText(apiKey))
	if err != nil {
		log.Printf("[ValidateAPIKey] Database lookup failed: %v", err)
		return emptyServer, fmt.Errorf("API key not found")
	}

	// Step 4: Verify decoded IDs match database record (prevent replay/tampering)
	if decodedUserID != database.FromPgUUID(server.UserID) ||
		decodedServerID != database.FromPgUUID(server.ID) {
		log.Printf("[ValidateAPIKey] ID mismatch: decoded=%s/%s, db=%s/%s",
			decodedUserID, decodedServerID,
			database.FromPgUUID(server.UserID), database.FromPgUUID(server.ID))
		return emptyServer, fmt.Errorf("API key mismatch")
	}

	// Step 5: Check server status
	if server.Status == "deleted" || server.Status == "rejected" || server.Status == "suspended" {
		return emptyServer, fmt.Errorf("server access revoked")
	}

	// Step 6: Check user subscription entitlement
	user, err := queries.GetUserByID(ctx, server.UserID)
	if err != nil {
		log.Printf("[ValidateAPIKey] Failed to fetch user for entitlement check: %v", err)
		return emptyServer, fmt.Errorf("user not found")
	}
	if !hasSubscriptionEntitlement(user, time.Now()) {
		log.Printf("[ValidateAPIKey] User %s has no active subscription — rejecting agent request", database.FromPgUUID(server.UserID))
		return emptyServer, fmt.Errorf("subscription_inactive")
	}

	return server, nil
}
