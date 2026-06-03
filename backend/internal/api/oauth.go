package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kerneleye/backend/internal/database"
)

// OAuthConfig holds OAuth configuration
type OAuthConfig struct {
	GitHubClientID     string
	GitHubClientSecret string
	GoogleClientID     string
	GoogleClientSecret string
	RedirectURL        string
	DashboardURL       string
}

// GetOAuthConfig returns OAuth configuration from environment
func GetOAuthConfig() OAuthConfig {
	dashboardURL := os.Getenv("DASHBOARD_URL")
	if dashboardURL == "" {
		dashboardURL = "http://localhost:3000"
	}

	return OAuthConfig{
		GitHubClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		GitHubClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:        os.Getenv("OAUTH_REDIRECT_URL"),
		DashboardURL:       dashboardURL,
	}
}

// IsOAuthEnabled returns true if any OAuth provider is configured
func (c OAuthConfig) IsOAuthEnabled() bool {
	return c.GitHubClientID != "" || c.GoogleClientID != ""
}

// OAuthState stores state for OAuth flow
type OAuthState struct {
	Provider string `json:"provider"`
	Nonce    string `json:"nonce"`
}

// generateState generates a random state string
func generateState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// GitHubUser represents GitHub user info
type GitHubUser struct {
	ID        int64  `json:"id"`
	Email     string `json:"email"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
}

// GoogleUser represents Google user info
type GoogleUser struct {
	ID      string `json:"sub"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
}

// HandleGetAuthProviders returns available OAuth providers
func HandleGetAuthProviders() fiber.Handler {
	return func(c *fiber.Ctx) error {
		config := GetOAuthConfig()

		// If AUTH_OWNER_EMAIL is not configured, hide all providers.
		if ownerNotConfigured() {
			return c.JSON(fiber.Map{
				"providers":        []map[string]interface{}{},
				"owner_configured": false,
			})
		}

		providers := []map[string]interface{}{}

		if config.GitHubClientID != "" {
			providers = append(providers, map[string]interface{}{
				"id":   "github",
				"name": "GitHub",
				"icon": "github",
			})
		}

		if config.GoogleClientID != "" {
			providers = append(providers, map[string]interface{}{
				"id":   "google",
				"name": "Google",
				"icon": "google",
			})
		}

		return c.JSON(fiber.Map{
			"providers":        providers,
			"owner_configured": true,
		})
	}
}

// HandleGitHubLogin initiates GitHub OAuth flow
func HandleGitHubLogin() fiber.Handler {
	return func(c *fiber.Ctx) error {
		config := GetOAuthConfig()
		if config.GitHubClientID == "" {
			return fiber.NewError(fiber.StatusServiceUnavailable, "GitHub OAuth not configured")
		}

		state, err := generateState()
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to generate state")
		}

		// Store state in cookie (always Secure — OAuth only works over HTTPS)
		c.Cookie(&fiber.Cookie{
			Name:     "oauth_state",
			Value:    state,
			MaxAge:   600,
			HTTPOnly: true,
			Secure:   true,
			SameSite: "Lax",
		})

		// Build authorization URL
		authURL := fmt.Sprintf(
			"https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s&state=%s&scope=user:email",
			config.GitHubClientID,
			url.QueryEscape(config.RedirectURL+"/api/v1/auth/github/callback"),
			state,
		)

		return c.Redirect(authURL, fiber.StatusTemporaryRedirect)
	}
}

// HandleGitHubCallback handles GitHub OAuth callback
func HandleGitHubCallback(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		config := GetOAuthConfig()

		// Verify state
		state := c.Query("state")
		cookieState := c.Cookies("oauth_state")
		if state == "" || state != cookieState {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid state parameter")
		}

		// Clear state cookie
		c.Cookie(&fiber.Cookie{
			Name:   "oauth_state",
			Value:  "",
			MaxAge: -1,
		})

		code := c.Query("code")
		if code == "" {
			return fiber.NewError(fiber.StatusBadRequest, "Missing authorization code")
		}

		// Exchange code for access token
		tokenResp, err := exchangeGitHubCode(config, code)
		if err != nil {
			log.Printf("[OAuth] Failed to exchange GitHub code: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to authenticate with GitHub")
		}

		// Get user info
		githubUser, err := getGitHubUser(tokenResp.AccessToken)
		if err != nil {
			log.Printf("[OAuth] Failed to get GitHub user: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to get user info")
		}

		// Get email if not provided
		if githubUser.Email == "" {
			email, err := getGitHubEmail(tokenResp.AccessToken)
			if err != nil {
				log.Printf("[OAuth] Failed to get GitHub email: %v", err)
			} else {
				githubUser.Email = email
			}
		}

		// Enforce owner email restriction for self-hosted single-owner access.
		if ownerNotConfigured() {
			redirectURL := fmt.Sprintf("%s/oauth/callback?error=owner_not_configured", config.DashboardURL)
			return c.Redirect(redirectURL, fiber.StatusTemporaryRedirect)
		}
		if !isOwnerEmail(githubUser.Email) {
			log.Printf("[OAuth] GitHub login rejected: %s is not the configured owner", githubUser.Email)
			redirectURL := fmt.Sprintf("%s/oauth/callback?error=unauthorized_owner", config.DashboardURL)
			return c.Redirect(redirectURL, fiber.StatusTemporaryRedirect)
		}

		// Find or create user
		user, err := queries.GetUserByEmail(c.Context(), githubUser.Email)
		if err != nil {
			// Create new user
			user, err = queries.CreateUser(c.Context(), githubUser.Email)
			if err != nil {
				log.Printf("[OAuth] Failed to create user: %v", err)
				return fiber.NewError(fiber.StatusInternalServerError, "Failed to create user")
			}
		}

		// Generate and store refresh token
		refreshToken, err := GenerateRefreshToken()
		if err != nil {
			log.Printf("[OAuth] Warning: Failed to generate refresh token: %v", err)
		} else {
			if err := StoreRefreshToken(queries, c.Context(), user.ID, refreshToken); err != nil {
				log.Printf("[OAuth] Warning: Failed to store refresh token: %v", err)
			} else {
				SetRefreshTokenCookie(c, refreshToken)
			}
		}

		// Redirect to dashboard (refresh token is in HttpOnly cookie)
		redirectURL := fmt.Sprintf("%s/oauth/callback", config.DashboardURL)
		return c.Redirect(redirectURL, fiber.StatusTemporaryRedirect)
	}
}

// GitHubTokenResponse represents GitHub access token response
type GitHubTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

func exchangeGitHubCode(config OAuthConfig, code string) (*GitHubTokenResponse, error) {
	data := url.Values{}
	data.Set("client_id", config.GitHubClientID)
	data.Set("client_secret", config.GitHubClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", config.RedirectURL+"/api/v1/auth/github/callback")

	req, err := http.NewRequest("POST", "https://github.com/login/oauth/access_token", nil)
	if err != nil {
		return nil, err
	}
	req.URL.RawQuery = data.Encode()
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var tokenResp GitHubTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, err
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("no access token received")
	}

	return &tokenResp, nil
}

func getGitHubUser(accessToken string) (*GitHubUser, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var user GitHubUser
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

func getGitHubEmail(accessToken string) (string, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.Unmarshal(body, &emails); err != nil {
		return "", err
	}

	for _, email := range emails {
		if email.Primary && email.Verified {
			return email.Email, nil
		}
	}

	for _, email := range emails {
		if email.Verified {
			return email.Email, nil
		}
	}

	return "", fmt.Errorf("no verified email found")
}

// HandleGoogleLogin initiates Google OAuth flow
func HandleGoogleLogin() fiber.Handler {
	return func(c *fiber.Ctx) error {
		config := GetOAuthConfig()
		if config.GoogleClientID == "" {
			return fiber.NewError(fiber.StatusServiceUnavailable, "Google OAuth not configured")
		}

		state, err := generateState()
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to generate state")
		}

		// Store state in cookie (always Secure — OAuth only works over HTTPS)
		c.Cookie(&fiber.Cookie{
			Name:     "oauth_state",
			Value:    state,
			MaxAge:   600,
			HTTPOnly: true,
			Secure:   true,
			SameSite: "Lax",
		})

		// Build authorization URL
		authURL := fmt.Sprintf(
			"https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=openid+email+profile&state=%s",
			config.GoogleClientID,
			url.QueryEscape(config.RedirectURL+"/api/v1/auth/google/callback"),
			state,
		)

		return c.Redirect(authURL, fiber.StatusTemporaryRedirect)
	}
}

// HandleGoogleCallback handles Google OAuth callback
func HandleGoogleCallback(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		config := GetOAuthConfig()

		// Verify state
		state := c.Query("state")
		cookieState := c.Cookies("oauth_state")
		if state == "" || state != cookieState {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid state parameter")
		}

		// Clear state cookie
		c.Cookie(&fiber.Cookie{
			Name:   "oauth_state",
			Value:  "",
			MaxAge: -1,
		})

		code := c.Query("code")
		if code == "" {
			return fiber.NewError(fiber.StatusBadRequest, "Missing authorization code")
		}

		// Exchange code for access token
		tokenResp, err := exchangeGoogleCode(config, code)
		if err != nil {
			log.Printf("[OAuth] Failed to exchange Google code: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to authenticate with Google")
		}

		// Get user info
		googleUser, err := getGoogleUser(tokenResp.IDToken)
		if err != nil {
			log.Printf("[OAuth] Failed to get Google user: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to get user info")
		}

		if googleUser.Email == "" {
			return fiber.NewError(fiber.StatusBadRequest, "Email is required")
		}

		// Enforce owner email restriction for self-hosted single-owner access.
		if ownerNotConfigured() {
			redirectURL := fmt.Sprintf("%s/oauth/callback?error=owner_not_configured", config.DashboardURL)
			return c.Redirect(redirectURL, fiber.StatusTemporaryRedirect)
		}
		if !isOwnerEmail(googleUser.Email) {
			log.Printf("[OAuth] Google login rejected: %s is not the configured owner", googleUser.Email)
			redirectURL := fmt.Sprintf("%s/oauth/callback?error=unauthorized_owner", config.DashboardURL)
			return c.Redirect(redirectURL, fiber.StatusTemporaryRedirect)
		}

		// Find or create user
		user, err := queries.GetUserByEmail(c.Context(), googleUser.Email)
		if err != nil {
			// Create new user
			user, err = queries.CreateUser(c.Context(), googleUser.Email)
			if err != nil {
				log.Printf("[OAuth] Failed to create user: %v", err)
				return fiber.NewError(fiber.StatusInternalServerError, "Failed to create user")
			}
		}

		// Generate and store refresh token
		refreshToken, err := GenerateRefreshToken()
		if err != nil {
			log.Printf("[OAuth] Warning: Failed to generate refresh token: %v", err)
		} else {
			if err := StoreRefreshToken(queries, c.Context(), user.ID, refreshToken); err != nil {
				log.Printf("[OAuth] Warning: Failed to store refresh token: %v", err)
			} else {
				SetRefreshTokenCookie(c, refreshToken)
			}
		}

		// Redirect to dashboard (refresh token is in HttpOnly cookie)
		redirectURL := fmt.Sprintf("%s/oauth/callback", config.DashboardURL)
		return c.Redirect(redirectURL, fiber.StatusTemporaryRedirect)
	}
}

// GoogleTokenResponse represents Google token response
type GoogleTokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
}

func exchangeGoogleCode(config OAuthConfig, code string) (*GoogleTokenResponse, error) {
	data := url.Values{}
	data.Set("client_id", config.GoogleClientID)
	data.Set("client_secret", config.GoogleClientSecret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", config.RedirectURL+"/api/v1/auth/google/callback")

	resp, err := http.PostForm("https://oauth2.googleapis.com/token", data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var tokenResp GoogleTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, err
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("no access token received")
	}

	return &tokenResp, nil
}

func getGoogleUser(idToken string) (*GoogleUser, error) {
	// Verify ID token via Google's tokeninfo endpoint (validates signature, issuer, expiry)
	resp, err := http.Get("https://oauth2.googleapis.com/tokeninfo?id_token=" + url.QueryEscape(idToken))
	if err != nil {
		return nil, fmt.Errorf("failed to verify Google ID token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Google token verification failed (status %d): %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read tokeninfo response: %w", err)
	}

	var tokenInfo struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified string `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
		Aud           string `json:"aud"`
		Iss           string `json:"iss"`
		Exp           string `json:"exp"`
	}
	if err := json.Unmarshal(body, &tokenInfo); err != nil {
		return nil, fmt.Errorf("failed to parse tokeninfo response: %w", err)
	}

	// Verify the audience matches our client ID
	config := GetOAuthConfig()
	if tokenInfo.Aud != config.GoogleClientID {
		return nil, fmt.Errorf("token audience mismatch: got %s, expected %s", tokenInfo.Aud, config.GoogleClientID)
	}

	// Verify the issuer is Google
	if tokenInfo.Iss != "accounts.google.com" && tokenInfo.Iss != "https://accounts.google.com" {
		return nil, fmt.Errorf("unexpected token issuer: %s", tokenInfo.Iss)
	}

	// Verify email is verified
	if tokenInfo.EmailVerified != "true" {
		return nil, fmt.Errorf("Google email not verified")
	}

	return &GoogleUser{
		ID:      tokenInfo.Sub,
		Email:   tokenInfo.Email,
		Name:    tokenInfo.Name,
		Picture: tokenInfo.Picture,
	}, nil
}
