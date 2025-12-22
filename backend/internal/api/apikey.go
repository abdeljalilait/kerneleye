package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"
)

// GenerateAPIKey creates a unique API key for a server
// Format: ke_<base64(userID.serverID.timestamp.signature)>
func GenerateAPIKey(userID, serverID string) string {
	secret := os.Getenv("API_KEY_SECRET")
	if secret == "" {
		secret = "default-secret-change-in-production"
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
// This is optional since we primarily validate via database lookup
func DecodeAPIKey(apiKey string) (userID, serverID string, err error) {
	if !strings.HasPrefix(apiKey, "ke_") {
		return "", "", fmt.Errorf("invalid API key format")
	}

	encodedKey := strings.TrimPrefix(apiKey, "ke_")
	decoded, err := base64.RawURLEncoding.DecodeString(encodedKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode API key")
	}

	parts := strings.Split(string(decoded), ".")
	if len(parts) != 4 {
		return "", "", fmt.Errorf("invalid API key structure")
	}

	userID = parts[0]
	serverID = parts[1]
	// timestamp = parts[2]
	signature := parts[3]

	// Verify signature
	secret := os.Getenv("API_KEY_SECRET")
	if secret == "" {
		secret = "default-secret-change-in-production"
	}

	payload := fmt.Sprintf("%s.%s.%s", parts[0], parts[1], parts[2])
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(payload))
	expectedSig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		return "", "", fmt.Errorf("invalid API key signature")
	}

	return userID, serverID, nil
}
