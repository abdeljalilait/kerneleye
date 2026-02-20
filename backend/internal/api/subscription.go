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
	"github.com/kerneleye/backend/internal/email"
	"github.com/kerneleye/backend/internal/payments/polar"
)

// PolarWebhookPayload represents a webhook event from Polar
type PolarWebhookPayload struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// PolarSubscription represents Polar subscription data
type PolarSubscription struct {
	ID                 string            `json:"id"`
	Status             string            `json:"status"`
	CurrentPeriodStart time.Time         `json:"current_period_start"`
	CurrentPeriodEnd   time.Time         `json:"current_period_end"`
	CancelAtPeriodEnd  bool              `json:"cancel_at_period_end"`
	CustomerID         string            `json:"customer_id"`
	ProductID          string            `json:"product_id"`
	PriceID            string            `json:"price_id"`
	Metadata           map[string]string `json:"metadata"`
	// Trial fields
	IsTrialing  bool       `json:"is_trialing,omitempty"`
	TrialEndsAt *time.Time `json:"trial_ends_at,omitempty"`
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
	PolarPriceID      string                 `json:"polar_price_id,omitempty"`
}

// SubscriptionStatusResponse represents user's subscription status
type SubscriptionStatusResponse struct {
	Plan               string                 `json:"plan"`
	PlanDisplayName    string                 `json:"plan_display_name"`
	Status             string                 `json:"status"`
	MaxServers         int32                  `json:"max_servers"`
	CurrentServers     int32                  `json:"current_servers"`
	DataRetentionDays  int32                  `json:"data_retention_days"`
	Features           map[string]interface{} `json:"features"`
	CurrentPeriodStart *time.Time             `json:"current_period_start,omitempty"`
	CurrentPeriodEnd   *time.Time             `json:"current_period_end,omitempty"`
	CancelAtPeriodEnd  bool                   `json:"cancel_at_period_end"`
	TrialEndsAt        *time.Time             `json:"trial_ends_at,omitempty"`
	IsTrialing         bool                   `json:"is_trialing"`
	CustomerPortalURL  string                 `json:"customer_portal_url,omitempty"`
}

// getPolarWebhookSecret returns the Polar webhook secret from environment
func getPolarWebhookSecret() string {
	return os.Getenv("POLAR_WEBHOOK_SECRET")
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
		log.Printf("[API] GET /subscription/plans - Fetching active plans")

		plans, err := queries.ListActivePlans(c.Context())
		if err != nil {
			log.Printf("[API] GET /subscription/plans - ERROR: Failed to list plans: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to fetch plans")
		}

		log.Printf("[API] GET /subscription/plans - SUCCESS: Found %d active plans", len(plans))

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
				PolarPriceID:      plan.PolarPriceID.String,
			}
		}

		return c.JSON(response)
	}
}

// HandleGetSubscriptionStatus returns the current user's subscription status
func HandleGetSubscriptionStatus(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := c.Locals("user_id").(string)
		log.Printf("[API] GET /subscription/status - User: %s", userID)

		user, err := queries.GetUserByID(c.Context(), database.ToPgUUID(userID))
		if err != nil {
			log.Printf("[API] GET /subscription/status - ERROR: Failed to fetch user %s: %v", userID, err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to fetch subscription")
		}
		log.Printf("[API] GET /subscription/status - User plan: %s, status: %s", user.Plan, user.SubscriptionStatus.String)

		// Count current servers
		serverCount, err := queries.CountServersByUser(c.Context(), database.ToPgUUID(userID))
		if err != nil {
			log.Printf("[Subscription] Error counting servers: %v", err)
			serverCount = 0
		}

		// Check if user is in trial
		isTrialing := user.TrialEndsAt.Valid && user.TrialEndsAt.Time.After(time.Now())

		// Determine effective status
		status := user.SubscriptionStatus.String
		if status == "" {
			status = "inactive"
		}

		// If user has no active subscription or trial, return "no_subscription" state
		if status != "active" && !isTrialing {
			return c.JSON(SubscriptionStatusResponse{
				Plan:              "none",
				PlanDisplayName:   "No Active Plan",
				Status:            "inactive",
				MaxServers:        0,
				CurrentServers:    int32(serverCount),
				DataRetentionDays: 0,
				Features:          map[string]interface{}{},
				CancelAtPeriodEnd: false,
				IsTrialing:        false,
			})
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

		var features map[string]interface{}
		if plan.Features != nil {
			json.Unmarshal(plan.Features, &features)
		}

		response := SubscriptionStatusResponse{
			Plan:              user.Plan,
			PlanDisplayName:   plan.DisplayName,
			Status:            status,
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

// HandleCreateCheckout creates a Polar checkout session using the SDK
func HandleCreateCheckout(queries *database.Queries, polarClient *polar.Client) fiber.Handler {
	return func(c *fiber.Ctx) error {
		log.Printf("[API] POST /subscription/checkout - Starting checkout creation")

		// Safely extract user_id from context
		userIDVal := c.Locals("user_id")
		if userIDVal == nil {
			log.Printf("[API] POST /subscription/checkout - ERROR: user_id not found in context")
			return fiber.NewError(fiber.StatusUnauthorized, "Authentication required")
		}
		userID, ok := userIDVal.(string)
		if !ok {
			log.Printf("[API] POST /subscription/checkout - ERROR: user_id is not a string: %T", userIDVal)
			return fiber.NewError(fiber.StatusInternalServerError, "Invalid user context")
		}
		log.Printf("[API] POST /subscription/checkout - User ID: %s", userID)

		type Request struct {
			PlanName    string `json:"plan_name"`
			EmbedOrigin string `json:"embed_origin,omitempty"`
		}

		var req Request
		if err := c.BodyParser(&req); err != nil {
			log.Printf("[API] POST /subscription/checkout - ERROR: Failed to parse request body: %v", err)
			return fiber.NewError(fiber.StatusBadRequest, "Invalid request body: "+err.Error())
		}
		log.Printf("[API] POST /subscription/checkout - Request plan_name: '%s', embed_origin: '%s'", req.PlanName, req.EmbedOrigin)

		// Validate plan name
		if req.PlanName == "" {
			log.Printf("[API] POST /subscription/checkout - ERROR: plan_name is empty")
			return fiber.NewError(fiber.StatusBadRequest, "Plan name is required")
		}

		// Get user details
		user, err := queries.GetUserByID(c.Context(), database.ToPgUUID(userID))
		if err != nil {
			log.Printf("[API] POST /subscription/checkout - ERROR: Failed to fetch user %s: %v", userID, err)
			if err.Error() == "no rows in result set" {
				return fiber.NewError(fiber.StatusNotFound, "User not found")
			}
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to fetch user")
		}
		log.Printf("[API] POST /subscription/checkout - User email: %s", user.Email)

		// Get plan details
		plan, err := queries.GetPlanByName(c.Context(), req.PlanName)
		if err != nil {
			log.Printf("[API] POST /subscription/checkout - ERROR: Invalid plan '%s': %v", req.PlanName, err)
			if err.Error() == "no rows in result set" {
				return fiber.NewError(fiber.StatusBadRequest, "Plan not found: "+req.PlanName)
			}
			return fiber.NewError(fiber.StatusInternalServerError, "Database error fetching plan")
		}
		log.Printf("[API] POST /subscription/checkout - Plan found: %s (ID: %v)", plan.DisplayName, plan.ID)

		// Check if we have a Polar price ID
		if !plan.PolarPriceID.Valid || plan.PolarPriceID.String == "" {
			log.Printf("[API] POST /subscription/checkout - ERROR: Plan '%s' has no polar_price_id configured", req.PlanName)
			return fiber.NewError(fiber.StatusInternalServerError, "Plan not configured for checkout")
		}
		log.Printf("[API] POST /subscription/checkout - Polar Price ID: %s", plan.PolarPriceID.String)

		// Build success URL
		dashboardURL := os.Getenv("DASHBOARD_URL")
		if dashboardURL == "" {
			dashboardURL = "http://localhost:3000"
		}
		successURL := dashboardURL + "/subscription/success"
		log.Printf("[API] POST /subscription/checkout - Success URL: %s", successURL)

		// Check Polar client status
		if polarClient == nil {
			log.Printf("[API] POST /subscription/checkout - ERROR: Polar client is nil")
		} else {
			log.Printf("[API] POST /subscription/checkout - Polar client configured: %v", polarClient.IsConfigured())
		}

		// Use Polar SDK to create checkout session
		if polarClient == nil || !polarClient.IsConfigured() {
			log.Printf("[API] POST /subscription/checkout - ERROR: Polar SDK not configured")
			return fiber.NewError(fiber.StatusServiceUnavailable, 
				"Payment processing is not configured. Please contact support.")
		}

		log.Printf("[API] POST /subscription/checkout - Creating checkout session via Polar SDK")

		// Wrap SDK call in panic recovery
		var sessionURL string
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[API] POST /subscription/checkout - PANIC in Polar SDK: %v", r)
				}
			}()

			session, err := polarClient.CreateCheckoutSession(
				c.Context(),
				plan.PolarPriceID.String,
				&user.Email,
				successURL,
			)

			if err != nil {
				log.Printf("[API] POST /subscription/checkout - ERROR: Polar SDK CreateCheckoutSession failed: %v", err)
				return
			}
			if session == nil {
				log.Printf("[API] POST /subscription/checkout - ERROR: Polar SDK returned nil session")
				return
			}
			if session.URL == nil {
				log.Printf("[API] POST /subscription/checkout - ERROR: Polar SDK returned session with nil URL")
				return
			}

			log.Printf("[API] POST /subscription/checkout - SUCCESS: Created checkout session via SDK")
			log.Printf("[API] POST /subscription/checkout - Checkout URL: %s", *session.URL)
			sessionURL = *session.URL
		}()

		if sessionURL == "" {
			return fiber.NewError(fiber.StatusInternalServerError, 
				"Failed to create checkout session. Please try again or contact support.")
		}

		return c.JSON(fiber.Map{
			"checkout_url":   sessionURL,
			"customer_email": user.Email,
			"is_trial":       true,
			"trial_days":     7,
			"embedded":       req.EmbedOrigin != "",
			"metadata": fiber.Map{
				"user_id": userID,
				"plan":    req.PlanName,
			},
		})
	}
}

// HandlePolarDebug returns Polar configuration status (admin only)
func HandlePolarDebug(polarClient *polar.Client, queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		log.Printf("[API] GET /subscription/debug - Polar debug request")

		// Check if Polar client is configured
		isConfigured := polarClient != nil && polarClient.IsConfigured()

		// Get plans from database
		plans, err := queries.ListActivePlans(c.Context())
		if err != nil {
			log.Printf("[API] GET /subscription/debug - ERROR: Failed to list plans: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to list plans")
		}

		// Format plan info
		type PlanInfo struct {
			Name         string `json:"name"`
			DisplayName  string `json:"display_name"`
			PolarPriceID string `json:"polar_price_id"`
			HasPriceID   bool   `json:"has_price_id"`
		}

		planInfos := make([]PlanInfo, 0, len(plans))
		for _, plan := range plans {
			planInfos = append(planInfos, PlanInfo{
				Name:         plan.Name,
				DisplayName:  plan.DisplayName,
				PolarPriceID: plan.PolarPriceID.String,
				HasPriceID:   plan.PolarPriceID.Valid && plan.PolarPriceID.String != "",
			})
		}

		// Try to fetch products from Polar if configured
		var polarProducts []map[string]interface{}
		var testCheckoutURL string
		var testCheckoutError string
		
		if isConfigured {
			products, err := polarClient.ListProducts(c.Context(), 100)
			if err != nil {
				log.Printf("[API] GET /subscription/debug - ERROR: Failed to list Polar products: %v", err)
			} else {
				for _, p := range products {
					polarProducts = append(polarProducts, map[string]interface{}{
						"id":   p.ID,
						"name": p.Name,
					})
				}
			}

			// Try to create a test checkout with the first plan that has a price ID
			for _, plan := range plans {
				if plan.PolarPriceID.Valid && plan.PolarPriceID.String != "" {
					testEmail := "test@example.com"
					session, err := polarClient.CreateCheckoutSession(
						c.Context(),
						plan.PolarPriceID.String,
						&testEmail,
						"https://example.com/success",
					)
					if err != nil {
						testCheckoutError = err.Error()
					} else if session != nil && session.URL != nil {
						testCheckoutURL = *session.URL
					}
					break
				}
			}
		}

		return c.JSON(fiber.Map{
			"polar_configured":         isConfigured,
			"polar_access_token_set":   os.Getenv("POLAR_ACCESS_TOKEN") != "",
			"polar_env":                os.Getenv("POLAR_ENV"),
			"dashboard_url":            os.Getenv("DASHBOARD_URL"),
			"plans":                    planInfos,
			"polar_products":           polarProducts,
			"test_checkout_url":        testCheckoutURL,
			"test_checkout_error":      testCheckoutError,
		})
	}
}

// HandleCreateCustomerPortal creates a Polar customer portal session
func HandleCreateCustomerPortal(queries *database.Queries, polarClient *polar.Client) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := c.Locals("user_id").(string)
		log.Printf("[API] POST /subscription/portal - User: %s", userID)

		// Get user details
		user, err := queries.GetUserByID(c.Context(), database.ToPgUUID(userID))
		if err != nil {
			log.Printf("[API] POST /subscription/portal - ERROR: Failed to fetch user %s: %v", userID, err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to fetch user")
		}

		// Check if user has a Polar customer ID
		if !user.PolarCustomerID.Valid || user.PolarCustomerID.String == "" {
			log.Printf("[API] POST /subscription/portal - ERROR: User %s has no Polar customer ID", userID)
			return fiber.NewError(fiber.StatusBadRequest, "No Polar customer found for this user")
		}

		log.Printf("[API] POST /subscription/portal - Polar Customer ID: %s", user.PolarCustomerID.String)

		// If Polar client is not configured, return error
		if polarClient == nil || !polarClient.IsConfigured() {
			return fiber.NewError(fiber.StatusServiceUnavailable, "Polar integration not configured")
		}

		// Create customer portal session
		portalSession, err := polarClient.CreateCustomerPortalSession(
			c.Context(),
			user.PolarCustomerID.String,
		)
		if err != nil {
			log.Printf("[Polar] Failed to create customer portal session: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to create customer portal session")
		}

		return c.JSON(fiber.Map{
			"portal_url": portalSession.CustomerPortalURL,
		})
	}
}

// HandlePolarWebhook handles webhook events from Polar
func HandlePolarWebhook(queries *database.Queries, emailService *email.Service, polarClient *polar.Client) fiber.Handler {
	return func(c *fiber.Ctx) error {
		log.Printf("[API] POST /webhooks/polar - Webhook received")

		// Get the signature from header
		signature := c.Get("Polar-Signature")
		if signature == "" {
			log.Printf("[API] POST /webhooks/polar - ERROR: Missing Polar-Signature header")
			return fiber.NewError(fiber.StatusUnauthorized, "Missing signature")
		}
		log.Printf("[API] POST /webhooks/polar - Signature present: %s...", signature[:20])

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

		// Use the webhook handler from the polar package if available
		if polarClient != nil && polarClient.IsConfigured() {
			handler := polar.NewWebhookHandler(polarClient, queries)
			if err := handler.HandleWebhook(c.Context(), event.Type, payload); err != nil {
				log.Printf("[Polar] Failed to process webhook: %v", err)
			}
		} else {
			// Fallback to legacy webhook handling
			log.Println("[Polar] SDK not configured, using legacy webhook handling")
		}

		// Store the event for audit trail
		var polarEventID string
		var userID string

		switch event.Type {
		case "subscription.created", "subscription.updated", "subscription.active", "subscription.trialing":
			var sub PolarSubscription
			if err := json.Unmarshal(event.Data, &sub); err != nil {
				log.Printf("[Polar] Failed to parse subscription: %v", err)
				return fiber.NewError(fiber.StatusBadRequest, "Invalid subscription data")
			}
			polarEventID = sub.ID
			if uid, ok := sub.Metadata["user_id"]; ok {
				userID = uid
			}

			// Update user's subscription (legacy handling)
			if userID != "" {
				if err := updateUserSubscription(queries, c, userID, sub); err != nil {
					log.Printf("[Polar] Failed to update user subscription: %v", err)
				} else {
					// Send welcome email after successful subscription or trial start
					if emailService != nil && emailService.IsEnabled() {
						go func() {
							// Get user details for email
							user, err := queries.GetUserByID(c.Context(), database.ToPgUUID(userID))
							if err != nil {
								log.Printf("[Polar] Failed to get user for welcome email: %v", err)
								return
							}

							planName := "Starter"
							if p, ok := sub.Metadata["plan"]; ok {
								planName = p
							}

							if err := emailService.SendWelcomeEmail(user.Email, user.Email, planName); err != nil {
								log.Printf("[Polar] Failed to send welcome email: %v", err)
							} else {
								log.Printf("[Polar] Welcome email sent to %s", user.Email)
							}
						}()
					}
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

	// Handle trial status
	status := sub.Status
	if sub.IsTrialing {
		status = "trialing"
	}

	params := database.UpdateUserSubscriptionParams{
		ID:                             database.ToPgUUID(userID),
		Plan:                           planName,
		PolarSubscriptionID:            database.ToPgText(sub.ID),
		SubscriptionStatus:             database.ToPgText(status),
		SubscriptionCurrentPeriodStart: database.ToPgTimestamptz(sub.CurrentPeriodStart),
		SubscriptionCurrentPeriodEnd:   database.ToPgTimestamptz(sub.CurrentPeriodEnd),
		SubscriptionCancelAtPeriodEnd:  database.ToPgBool(sub.CancelAtPeriodEnd),
		TrialEndsAt:                    database.ToPgTimestamptzPtr(sub.TrialEndsAt),
	}

	if err := queries.UpdateUserSubscription(c.Context(), params); err != nil {
		return fmt.Errorf("failed to update subscription: %w", err)
	}

	log.Printf("[Polar] Updated subscription for user %s to plan %s (status: %s, trial: %v)", userID, planName, status, sub.IsTrialing)
	return nil
}

// cancelUserSubscription marks a user's subscription as canceled
func cancelUserSubscription(queries *database.Queries, c *fiber.Ctx, userID string, sub PolarSubscription) error {
	params := database.UpdateUserSubscriptionParams{
		ID:                            database.ToPgUUID(userID),
		Plan:                          "starter", // Downgrade to starter
		PolarSubscriptionID:           database.ToPgText(sub.ID),
		SubscriptionStatus:            database.ToPgText("canceled"),
		SubscriptionCurrentPeriodEnd:  database.ToPgTimestamptz(sub.CurrentPeriodEnd),
		SubscriptionCancelAtPeriodEnd: database.ToPgBool(true),
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
		ID:                             database.ToPgUUID(userID),
		Plan:                           sub.Metadata["plan"],
		PolarSubscriptionID:            database.ToPgText(sub.ID),
		SubscriptionStatus:             database.ToPgText(sub.Status),
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

// HandleStartTrial starts a trial for a specific plan
func HandleStartTrial(queries *database.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		type Request struct {
			PlanName string `json:"plan_name"`
		}

		var req Request
		if err := c.BodyParser(&req); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
		}

		if req.PlanName == "" {
			return fiber.NewError(fiber.StatusBadRequest, "Plan name is required")
		}

		userID := c.Locals("user_id").(string)

		// Get user details
		user, err := queries.GetUserByID(c.Context(), database.ToPgUUID(userID))
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to fetch user")
		}

		// Check if user already has an active subscription or trial
		isTrialing := user.TrialEndsAt.Valid && user.TrialEndsAt.Time.After(time.Now())
		if user.SubscriptionStatus.String == "active" || isTrialing {
			return fiber.NewError(fiber.StatusBadRequest, "You already have an active subscription or trial")
		}

		// Get plan details
		plan, err := queries.GetPlanByName(c.Context(), req.PlanName)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid plan")
		}

		// Set trial to end in 14 days
		trialEndsAt := time.Now().Add(14 * 24 * time.Hour)

		// Update user with trial
		params := database.UpdateUserSubscriptionParams{
			ID:                 database.ToPgUUID(userID),
			Plan:               req.PlanName,
			SubscriptionStatus: database.ToPgText("trialing"),
			TrialEndsAt:        database.ToPgTimestamptz(trialEndsAt),
		}

		if err := queries.UpdateUserSubscription(c.Context(), params); err != nil {
			log.Printf("[Subscription] Failed to start trial for user %s: %v", userID, err)
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to start trial")
		}

		log.Printf("[Subscription] Started %s plan trial for user %s, ends at %v", req.PlanName, userID, trialEndsAt)

		return c.JSON(fiber.Map{
			"success":        true,
			"message":        fmt.Sprintf("Your %s trial has started!", plan.DisplayName),
			"plan":           req.PlanName,
			"plan_name":      plan.DisplayName,
			"trial_ends_at":  trialEndsAt,
			"days_remaining": 14,
		})
	}
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

		// Check if user has an active subscription or trial
		isTrialing := user.TrialEndsAt.Valid && user.TrialEndsAt.Time.After(time.Now())
		if user.SubscriptionStatus.String != "active" && !isTrialing {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":         "No active subscription",
				"message":       "You need an active subscription or trial to add servers.",
				"code":          "NO_SUBSCRIPTION",
				"subscribe_url": "/subscription",
			})
		}

		// Count current servers
		serverCount, err := queries.CountServersByUser(c.Context(), database.ToPgUUID(userID))
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to count servers")
		}

		// Check if limit reached
		if int32(serverCount) >= user.MaxServers {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":       "Server limit reached",
				"message":     fmt.Sprintf("Your %s plan allows up to %d servers. Please upgrade to add more.", user.Plan, user.MaxServers),
				"current":     serverCount,
				"limit":       user.MaxServers,
				"upgrade_url": "/subscription",
			})
		}

		return c.Next()
	}
}
