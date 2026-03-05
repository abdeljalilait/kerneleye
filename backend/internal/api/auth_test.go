package api

import (
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func TestRequireDashboardAuth(t *testing.T) {
	tests := []struct {
		name       string
		authType   string
		wantStatus int
	}{
		{
			name:       "dashboard auth allowed",
			authType:   "dashboard",
			wantStatus: fiber.StatusOK,
		},
		{
			name:       "agent auth forbidden",
			authType:   "agent",
			wantStatus: fiber.StatusForbidden,
		},
		{
			name:       "missing auth forbidden",
			authType:   "",
			wantStatus: fiber.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := fiber.New()
			app.Use(func(c *fiber.Ctx) error {
				if tt.authType != "" {
					c.Locals("auth_type", tt.authType)
				}
				return c.Next()
			})
			app.Post("/whitelist", RequireDashboardAuth(), func(c *fiber.Ctx) error {
				return c.SendStatus(fiber.StatusOK)
			})

			req := httptest.NewRequest("POST", "/whitelist", nil)
			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("app.Test error: %v", err)
			}
			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
		})
	}
}
