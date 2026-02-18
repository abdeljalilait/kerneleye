package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kerneleye/backend/internal/database"
)

// PolarWebhookPayload represents a webhook event from Polar
type PolarWebhookPayload struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// PolarSubscription represents Polar subscription data
type PolarSubscription struct {
	ID                    string    `json:"id"`
	Status                string    `json:"status"`
	CurrentPeriodStart    time.Time `json:"current_period_start"`
	CurrentPeriodEnd      time.Time `json:"current_period_end"`
	CancelAtPeriodEnd     bool      `json:"cancel_at_period_end"`
	CustomerID            string    `json:"customer_id"`
	ProductID             string    `json:"product_id"`
	PriceID               string    `json:"price_id"`
	Metadata              map[string]string `json:"metadata"`
}

// PolarCustomer represents Polar customer data
type PolarCustomer struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// PlanResponse represents a subscription plan for the frontend
type PlanResponse struct {
	ID                string                 `json:"id"`
	Name              string                 `json:"name"`
	DisplayName       string                 `json:"display_name"`
	Description       string                 `json:"description"`
	PriceCents        int32                  `json:"price_cents"`
	Currency          string                 `json:"currency"`
	BillingInterval   string                 `json:"billing_interval"`
	MaxServers        int32                  `json:"max_servers"`
	DataRetentionDays int32                  `json:"data_retention_days"`
	Features          map[string]interface{} `json:"features"`
	IsDefault         bool                   `json:"is_default"`
}

// SubscriptionStatusResponse represents user's subscription status
type SubscriptionStatusResponse struct {
	Plan                  string                 `json:"plan"`
	PlanDisplayName       string                 `json:"plan_display_name"`
	Status                string                 `json:"status"`
	MaxServers            int32                  `json:"max_servers"`
	CurrentServers        int32                  `json:"current_servers"`
	DataRetentionDays     int32                  `json:"data_retention_days"`
	Features              map[string]interface{} `json:"features"`
	CurrentPeriodStart    *time.Time             `json:"current_period_start,omitempty"`
	CurrentPeriodEnd      *time.Time             `json:"current_period_end,omitempty"`
	CancelAtPeriodEnd     bool                   `json:"cancel_at_period_end"`
	TrialEndsAt           *time.Time             `json:"trial_ends_at,omitempty"`
	IsTrialing            bool                   `json:"is_trialing"`
}

// getPolarWebhookSecret returns the Polar webhook secret from environment
func getPolarWebhookSecret() string {
	return os.Getenv("POLAR_WEBHOOK_SECRET")
}

// getPolarAccessToken returns the Polar access token from environment
func getPolarAccessToken() string {
	return os.Getenv("POLAR_ACCESS_TOKEN")
}

// verifyPolarWebhook verifies the webhook signature from Polar
func verifyPolarWebhook(payload []byte, signature string) bool {
	secret := getPolarWebhookSecret()
	if secret == "" {
		log.Println("[Polar] Warning: POLAR_WEBHOOK_SECRET not set, skipping signature verification")
		return true
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expectedSignature := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(signature), []byte(expectedSignature))
}

// HandleListPlans returns available subscription plans
func HandleListPlans(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		plans, err := queries.ListActivePlans(c.Context())
		if err != nil {
			log.Printf("[Subscription] Error listing plans: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to fetch plans")
		}

		response := make([]PlanResponse, len(plans))
		for i, plan := range plans {
			var features map[string]interface{}
			if plan.Features != nil {
				json.Unmarshal(plan.Features, &features)
			}

			response[i] = PlanResponse{
				ID:                database.FromPgUUID(plan.ID),
				Name:              plan.Name,
				DisplayName:       plan.DisplayName,
				Description:       plan.Description.String,
				PriceCents:        plan.PriceCents,
				Currency:          plan.Currency.String,
				BillingInterval:   plan.BillingInterval,
				MaxServers:        plan.MaxServers,
				DataRetentionDays: plan.DataRetentionDays,
				Features:          features,
				IsDefault:         plan.IsDefault.Bool,
			}
		}

		return c.JSON(response)
	}
}

// HandleGetSubscriptionStatus returns the current user's subscription status
func HandleGetSubscriptionStatus(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := c.Locals("user_id").(string)

		user, err := queries.GetUserByID(c.Context(), database.ToPgUUID(userID))
		if err != nil {
			log.Printf("[Subscription] Error fetching user %s: %v", userID, err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to fetch subscription")
		}

		// Get plan details
		plan, err := queries.GetPlanByName(c.Context(), user.Plan)
		if err != nil {
			log.Printf("[Subscription] Error fetching plan %s: %v", user.Plan, err)
			// Use default values if plan not found
			plan.Name = "starter"
			plan.DisplayName = "Starter"
			plan.MaxServers = 10
			plan.DataRetentionDays = 7
		}

		// Count current servers
		serverCount, err := queries.CountServersByUser(c.Context(), database.ToPgUUID(userID))
		if err != nil {
			log.Printf("[Subscription] Error counting servers: %v", err)
			serverCount = 0
		}

		var features map[string]interface{}
		if plan.Features != nil {
			json.Unmarshal(plan.Features, &features)
		}

		// Check if user is in trial
		isTrialing := user.TrialEndsAt.Valid && user.TrialEndsAt.Time.After(time.Now())

		response := SubscriptionStatusResponse{
			Plan:              user.Plan,
			PlanDisplayName:   plan.DisplayName,
			Status:            user.SubscriptionStatus.String,
			MaxServers:        user.MaxServers,
			CurrentServers:    int32(serverCount),
			DataRetentionDays: plan.DataRetentionDays,
			Features:          features,
			CancelAtPeriodEnd: user.SubscriptionCancelAtPeriodEnd.Bool,
			IsTrialing:        isTrialing,
		}

		if user.SubscriptionCurrentPeriodStart.Valid {
			response.CurrentPeriodStart = &user.SubscriptionCurrentPeriodStart.Time
		}
		if user.SubscriptionCurrentPeriodEnd.Valid {
			response.CurrentPeriodEnd = &user.SubscriptionCurrentPeriodEnd.Time
		}
		if user.TrialEndsAt.Valid {
			response.TrialEndsAt = &user.TrialEndsAt.Time
		}

		return c.JSON(response)
	}
}

// HandleCreateCheckout creates a Polar checkout session
func HandleCreateCheckout(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		type Request struct {
			PlanName string `json:"plan_name"`
		}

		var req Request
		if err := c.BodyParser(&req); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
		}

		userID := c.Locals("user_id").(string)

		// Get user details
		user, err := queries.GetUserByID(c.Context(), database.ToPgUUID(userID))
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to fetch user")
		}

		// Get plan details
		plan, err := queries.GetPlanByName(c.Context(), req.PlanName)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid plan")
		}

		// In a real implementation, you would call Polar's API to create a checkout session
		// For now, return the Polar product/price IDs for the frontend to use
		return c.JSON(fiber.Map{
			"checkout_url": fmt.Sprintf("https://polar.sh/checkout/%s", plan.PolarPriceID.String),
			"customer_email": user.Email,
			"metadata": fiber.Map{
				"user_id": userID,
				"plan":    req.PlanName,
			},
		})
	}
}

// HandlePolarWebhook handles webhook events from Polar
func HandlePolarWebhook(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get the signature from header
		signature := c.Get("Polar-Signature")
		if signature == "" {
			return fiber.NewError(fiber.StatusUnauthorized, "Missing signature")
		}

		// Verify webhook signature
		payload := c.Body()
		if !verifyPolarWebhook(payload, signature) {
			log.Println("[Polar] Webhook signature verification failed")
			return fiber.NewError(fiber.StatusUnauthorized, "Invalid signature")
		}

		var event PolarWebhookPayload
		if err := json.Unmarshal(payload, &event); err != nil {
			log.Printf("[Polar] Failed to parse webhook payload: %v", err)
			return fiber.NewError(fiber.StatusBadRequest, "Invalid payload")
		}

		log.Printf("[Polar] Received webhook event: %s", event.Type)

		// Store the event for audit trail
		var polarEventID string
		var userID string

		switch event.Type {
		case "subscription.created", "subscription.updated", "subscription.active":
			var sub PolarSubscription
			if err := json.Unmarshal(event.Data, &sub); err != nil {
				log.Printf("[Polar] Failed to parse subscription: %v", err)
				return fiber.NewError(fiber.StatusBadRequest, "Invalid subscription data")
			}
			polarEventID = sub.ID
			if uid, ok := sub.Metadata["user_id"]; ok {
				userID = uid
			}

			// Update user's subscription
			if userID != "" {
				if err := updateUserSubscription(queries, c, userID, sub); err != nil {
					log.Printf("[Polar] Failed to update user subscription: %v", err)
				}
			}

		case "subscription.canceled":
			var sub PolarSubscription
			if err := json.Unmarshal(event.Data, &sub); err != nil {
				log.Printf("[Polar] Failed to parse subscription cancellation: %v", err)
				return fiber.NewError(fiber.StatusBadRequest, "Invalid subscription data")
			}
			polarEventID = sub.ID
			if uid, ok := sub.Metadata["user_id"]; ok {
				userID = uid
			}

			if userID != "" {
				if err := cancelUserSubscription(queries, c, userID, sub); err != nil {
					log.Printf("[Polar] Failed to cancel user subscription: %v", err)
				}
			}

		case "subscription.uncanceled":
			var sub PolarSubscription
			if err := json.Unmarshal(event.Data, &sub); err != nil {
				log.Printf("[Polar] Failed to parse subscription uncancel: %v", err)
				return fiber.NewError(fiber.StatusBadRequest, "Invalid subscription data")
			}
			polarEventID = sub.ID
			if uid, ok := sub.Metadata["user_id"]; ok {
				userID = uid
			}

			if userID != "" {
				if err := uncancelUserSubscription(queries, c, userID, sub); err != nil {
					log.Printf("[Polar] Failed to uncancel user subscription: %v", err)
				}
			}

		default:
			log.Printf("[Polar] Unhandled event type: %s", event.Type)
		}

		// Store event in database for audit trail
		_, err := queries.CreateSubscriptionEvent(c.Context(), database.CreateSubscriptionEventParams{
			UserID:       database.ToPgUUID(userID),
			PolarEventID: database.ToPgText(polarEventID),
			EventType:    event.Type,
			Payload:      payload,
			Processed:    database.ToPgBool(true),
			ProcessedAt:  database.ToPgTimestamptz(time.Now()),
		})
		if err != nil {
			log.Printf("[Polar] Failed to store event: %v", err)
		}

		return c.JSON(fiber.Map{"status": "ok"})
	}
}

// updateUserSubscription updates a user's subscription based on Polar data
func updateUserSubscription(queries *database.Queries, c *fiber.Ctx, userID string, sub PolarSubscription) error {
	// Map Polar product/price to our plan names
	planName := "starter" // default

	// You would typically have a mapping from Polar product IDs to plan names
	// For now, we'll derive from metadata
	if p, ok := sub.Metadata["plan"]; ok {
		planName = p
	}

	params := database.UpdateUserSubscriptionParams{
		ID:                            database.ToPgUUID(userID),
		Plan:                          planName,
		PolarSubscriptionID:           database.ToPgText(sub.ID),
		SubscriptionStatus:            database.ToPgText(sub.Status),
		SubscriptionCurrentPeriodStart: database.ToPgTimestamptz(sub.CurrentPeriodStart),
		SubscriptionCurrentPeriodEnd:   database.ToPgTimestamptz(sub.CurrentPeriodEnd),
		SubscriptionCancelAtPeriodEnd:  database.ToPgBool(sub.CancelAtPeriodEnd),
	}

	if err := queries.UpdateUserSubscription(c.Context(), params); err != nil {
		return fmt.Errorf("failed to update subscription: %w", err)
	}

	log.Printf("[Polar] Updated subscription for user %s to plan %s", userID, planName)
	return nil
}

// cancelUserSubscription marks a user's subscription as canceled
func cancelUserSubscription(queries *database.Queries, c *fiber.Ctx, userID string, sub PolarSubscription) error {
	params := database.UpdateUserSubscriptionParams{
		ID:                            database.ToPgUUID(userID),
		Plan:                          "starter", // Downgrade to starter
		PolarSubscriptionID:           database.ToPgText(sub.ID),
		SubscriptionStatus:            database.ToPgText("canceled"),
		SubscriptionCurrentPeriodEnd:   database.ToPgTimestamptz(sub.CurrentPeriodEnd),
		SubscriptionCancelAtPeriodEnd:  database.ToPgBool(true),
	}

	if err := queries.UpdateUserSubscription(c.Context(), params); err != nil {
		return fmt.Errorf("failed to cancel subscription: %w", err)
	}

	log.Printf("[Polar] Canceled subscription for user %s", userID)
	return nil
}

// uncancelUserSubscription reactivates a user's subscription
func uncancelUserSubscription(queries *database.Queries, c *fiber.Ctx, userID string, sub PolarSubscription) error {
	params := database.UpdateUserSubscriptionParams{
		ID:                            database.ToPgUUID(userID),
		Plan:                          sub.Metadata["plan"],
		PolarSubscriptionID:           database.ToPgText(sub.ID),
		SubscriptionStatus:            database.ToPgText(sub.Status),
		SubscriptionCurrentPeriodStart: database.ToPgTimestamptz(sub.CurrentPeriodStart),
		SubscriptionCurrentPeriodEnd:   database.ToPgTimestamptz(sub.CurrentPeriodEnd),
		SubscriptionCancelAtPeriodEnd:  database.ToPgBool(false),
	}

	if err := queries.UpdateUserSubscription(c.Context(), params); err != nil {
		return fmt.Errorf("failed to uncancel subscription: %w", err)
	}

	log.Printf("[Polar] Uncanceled subscription for user %s", userID)
	return nil
}

// CheckServerLimit middleware checks if user has reached their server limit
func CheckServerLimit(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Only check for POST requests (creating new servers)
		if c.Method() != "POST" {
			return c.Next()
		}

		userID := c.Locals("user_id").(string)

		// Get user's subscription status
		user, err := queries.GetUserByID(c.Context(), database.ToPgUUID(userID))
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to verify subscription")
		}

		// Count current servers
		serverCount, err := queries.CountServersByUser(c.Context(), database.ToPgUUID(userID))
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to count servers")
		}

		// Check if limit reached
		if int32(serverCount) >= user.MaxServers {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Server limit reached",
				"message": fmt.Sprintf("Your %s plan allows up to %d servers. Please upgrade to add more.", user.Plan, user.MaxServers),
				"current": serverCount,
				"limit":   user.MaxServers,
				"upgrade_url": "/subscription/plans",
			})
		}

		return c.Next()
	}
}
