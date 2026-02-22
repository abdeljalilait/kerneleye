package main

import (
	"encoding/base64"
	"strings"
)

// extractServerIDFromAPIKey parses the server UUID embedded in the API key.
// API key format:
//
//	ke_<base64(userID.serverID.timestamp.signature)>
func extractServerIDFromAPIKey(apiKey string) string {
	if !strings.HasPrefix(apiKey, "ke_") {
		return ""
	}

	encoded := strings.TrimPrefix(apiKey, "ke_")
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return ""
	}

	parts := strings.Split(string(decoded), ".")
	if len(parts) < 2 {
		return ""
	}

	serverID := parts[1]
	if !isLikelyUUID(serverID) {
		return ""
	}
	return serverID
}

func isLikelyUUID(v string) bool {
	if len(v) != 36 {
		return false
	}
	for i := 0; i < len(v); i++ {
		switch i {
		case 8, 13, 18, 23:
			if v[i] != '-' {
				return false
			}
		default:
			c := v[i]
			isHex := (c >= '0' && c <= '9') ||
				(c >= 'a' && c <= 'f') ||
				(c >= 'A' && c <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}
