// Package polar provides Polar Payments integration for KernelEye
package polar

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/kerneleye/backend/internal/database"
	polargo "github.com/polarsource/polar-go"
	"github.com/polarsource/polar-go/models/components"
	"github.com/polarsource/polar-go/models/operations"
)

// Client wraps the Polar SDK client
type Client struct {
	client        *polargo.Polar
	webhookSecret string
}

// Config holds Polar configuration
type Config struct {
	AccessToken   string
	WebhookSecret string
}

// NewClient creates a new Polar client
func NewClient(cfg Config) *Client {
	if cfg.AccessToken == "" {
		cfg.AccessToken = os.Getenv("POLAR_ACCESS_TOKEN")
	}
	if cfg.WebhookSecret == "" {
		cfg.WebhookSecret = os.Getenv("POLAR_WEBHOOK_SECRET")
	}

	if cfg.AccessToken == "" {
		log.Println("[Polar] Warning: POLAR_ACCESS_TOKEN not set")
		return &Client{client: nil, webhookSecret: cfg.WebhookSecret}
	}

	// Configure Polar client
	// Uses production by default, set POLAR_ENV=sandbox for testing
	var client *polargo.Polar
	serverEnv := os.Getenv("POLAR_ENV")

	switch serverEnv {
	case "sandbox":
		client = polargo.New(
			polargo.WithServer("sandbox"),
			polargo.WithSecurity(cfg.AccessToken),
		)
	case "production", "":
		client = polargo.New(
			polargo.WithSecurity(cfg.AccessToken),
		)
	default:
		// If a custom URL is provided, use it directly
		client = polargo.New(
			polargo.WithServerURL(serverEnv),
			polargo.WithSecurity(cfg.AccessToken),
		)
	}

	log.Println("[Polar] Client initialized")

	return &Client{
		client:        client,
		webhookSecret: cfg.WebhookSecret,
	}
}

// IsConfigured returns true if the client has an access token configured
func (c *Client) IsConfigured() bool {
	return c.client != nil
}

// GetClient returns the underlying Polar SDK client
func (c *Client) GetClient() *polargo.Polar {
	return c.client
}

// CreateCustomer creates a new customer in Polar
func (c *Client) CreateCustomer(ctx context.Context, email, name string) (*components.Customer, error) {
	req := components.CustomerCreate{
		Email: email,
	}

	if name != "" {
		req.Name = polargo.Pointer(name)
	}

	res, err := c.client.Customers.Create(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create Polar customer: %w", err)
	}

	return res.Customer, nil
}

// GetCustomer retrieves a customer by ID
func (c *Client) GetCustomer(ctx context.Context, customerID string) (*components.Customer, error) {
	res, err := c.client.Customers.Get(ctx, customerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get Polar customer: %w", err)
	}
	return res.Customer, nil
}

// CreateCheckoutSession creates a new checkout session for a subscription
func (c *Client) CreateCheckoutSession(ctx context.Context, productID string, customerEmail *string, successURL string, metadata map[string]string) (checkout *components.Checkout, err error) {
	// Defer/recover to catch any panics from the SDK
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[Polar] PANIC in CreateCheckoutSession: %v", r)
			err = fmt.Errorf("polar SDK panic: %v", r)
			checkout = nil
		}
	}()

	// Safety check: ensure client is configured
	if c.client == nil {
		return nil, fmt.Errorf("polar client not configured: missing access token")
	}

	// Build the checkout create request (v0.12.0 uses Products list)
	createReq := components.CheckoutCreate{
		Products:   []string{productID},
		SuccessURL: &successURL,
	}

	if customerEmail != nil && *customerEmail != "" {
		createReq.CustomerEmail = customerEmail
	}

	// Add metadata for webhook identification
	if len(metadata) > 0 {
		createReq.Metadata = make(map[string]components.CheckoutCreateMetadata)
		for k, v := range metadata {
			createReq.Metadata[k] = components.CreateCheckoutCreateMetadataStr(v)
		}
	}

	log.Printf("[Polar] Creating checkout session - ProductID: %s, SuccessURL: %s, Metadata: %+v", productID, successURL, metadata)

	res, sdkErr := c.client.Checkouts.Create(ctx, createReq)
	if sdkErr != nil {
		return nil, fmt.Errorf("failed to create checkout session: %w", sdkErr)
	}

	// Handle nil response from SDK
	if res == nil {
		return nil, fmt.Errorf("polar SDK returned nil response")
	}

	// Handle nil Checkout in response
	if res.Checkout == nil {
		return nil, fmt.Errorf("polar SDK returned nil checkout session")
	}

	checkoutURL := res.Checkout.URL
	log.Printf("[Polar] Raw checkout URL: %s", checkoutURL)

	// Transform URL for sandbox environment if needed
	if os.Getenv("POLAR_ENV") == "sandbox" {
		checkoutURL = strings.Replace(checkoutURL, "https://polar.sh/", "https://sandbox.polar.sh/", 1)
		res.Checkout.URL = checkoutURL
		log.Printf("[Polar] Transformed sandbox URL: %s", checkoutURL)
	}

	return res.Checkout, nil
}

// CreateCheckoutSessionWithTrial creates a checkout session with a trial period
func (c *Client) CreateCheckoutSessionWithTrial(ctx context.Context, productID string, customerEmail *string, successURL string, trialDays int) (*components.Checkout, error) {
	// Safety check: ensure client is configured
	if c.client == nil {
		return nil, fmt.Errorf("polar client not configured: missing access token")
	}

	// Build the checkout create request (v0.12.0 uses Products list)
	createReq := components.CheckoutCreate{
		Products:   []string{productID},
		SuccessURL: &successURL,
	}

	if customerEmail != nil && *customerEmail != "" {
		createReq.CustomerEmail = customerEmail
	}

	// Note: Trial configuration is typically set at the product level in Polar
	res, err := c.client.Checkouts.Create(ctx, createReq)
	if err != nil {
		return nil, fmt.Errorf("failed to create checkout session with trial: %w", err)
	}

	// Handle nil response from SDK
	if res == nil {
		return nil, fmt.Errorf("polar SDK returned nil response")
	}

	return res.Checkout, nil
}

// GetCheckoutSession retrieves a checkout session by ID
func (c *Client) GetCheckoutSession(ctx context.Context, sessionID string) (*components.Checkout, error) {
	res, err := c.client.Checkouts.Get(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get checkout session: %w", err)
	}
	return res.Checkout, nil
}

// ListSubscriptions retrieves subscriptions for a customer
func (c *Client) ListSubscriptions(ctx context.Context, customerID string) ([]components.Subscription, error) {
	customerFilter := operations.CreateCustomerIDFilterStr(customerID)
	res, err := c.client.Subscriptions.List(ctx, operations.SubscriptionsListRequest{
		CustomerID: &customerFilter,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list subscriptions: %w", err)
	}

	if res.ListResourceSubscription != nil && res.ListResourceSubscription.Items != nil {
		return res.ListResourceSubscription.Items, nil
	}

	return nil, nil
}

// ListProducts retrieves all products from Polar
func (c *Client) ListProducts(ctx context.Context, limit int) ([]components.Product, error) {
	if limit <= 0 {
		limit = 100
	}

	res, err := c.client.Products.List(ctx, operations.ProductsListRequest{
		Limit: polargo.Pointer(int64(limit)),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list products: %w", err)
	}

	if res.ListResourceProduct != nil && res.ListResourceProduct.Items != nil {
		return res.ListResourceProduct.Items, nil
	}

	return nil, nil
}

// GetProduct retrieves a product by ID
func (c *Client) GetProduct(ctx context.Context, productID string) (*components.Product, error) {
	res, err := c.client.Products.Get(ctx, productID)
	if err != nil {
		return nil, fmt.Errorf("failed to get product: %w", err)
	}
	return res.Product, nil
}

// CreateCustomerPortalSession creates a customer portal session
func (c *Client) CreateCustomerPortalSession(ctx context.Context, customerID string) (*components.CustomerSession, error) {
	req := operations.CreateCustomerSessionsCreateCustomerSessionCreateCustomerSessionCustomerIDCreate(
		components.CustomerSessionCustomerIDCreate{
			CustomerID: customerID,
		},
	)

	res, err := c.client.CustomerSessions.Create(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create customer portal session: %w", err)
	}

	return res.CustomerSession, nil
}

// WebhookEvent represents a Polar webhook event
type WebhookEvent struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// SubscriptionData represents subscription data in webhooks
type SubscriptionData struct {
	ID                 string            `json:"id"`
	Status             string            `json:"status"`
	CustomerID         string            `json:"customer_id"`
	ProductID          string            `json:"product_id"`
	PriceID            string            `json:"price_id"`
	CurrentPeriodStart time.Time         `json:"current_period_start"`
	CurrentPeriodEnd   time.Time         `json:"current_period_end"`
	CancelAtPeriodEnd  bool              `json:"cancel_at_period_end"`
	Metadata           map[string]string `json:"metadata"`
	// Trial fields
	IsTrialing  bool       `json:"is_trialing,omitempty"`
	TrialEndsAt *time.Time `json:"trial_ends_at,omitempty"`
}

// CustomerData represents customer data in webhooks
type CustomerData struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// WebhookHandler handles Polar webhook events
type WebhookHandler struct {
	client  *Client
	queries *database.Queries
}

// NewWebhookHandler creates a new webhook handler
func NewWebhookHandler(client *Client, queries *database.Queries) *WebhookHandler {
	return &WebhookHandler{
		client:  client,
		queries: queries,
	}
}

// HandleWebhook processes incoming Polar webhook events
func (h *WebhookHandler) HandleWebhook(ctx context.Context, eventType string, payload []byte) error {
	log.Printf("[Polar] Processing webhook event: %s", eventType)

	switch eventType {
	case "subscription.created", "subscription.updated", "subscription.active":
		return h.handleSubscriptionCreatedOrUpdated(ctx, payload)
	case "subscription.canceled":
		return h.handleSubscriptionCanceled(ctx, payload)
	case "subscription.uncanceled":
		return h.handleSubscriptionUncanceled(ctx, payload)
	default:
		log.Printf("[Polar] Unhandled webhook event type: %s", eventType)
	}

	return nil
}

func (h *WebhookHandler) handleSubscriptionCreatedOrUpdated(ctx context.Context, payload []byte) error {
	var sub SubscriptionData
	if err := json.Unmarshal(payload, &sub); err != nil {
		return fmt.Errorf("failed to parse subscription data: %w", err)
	}

	userID := sub.Metadata["user_id"]
	if userID == "" {
		// No user_id in metadata - let legacy handler try customer ID lookup
		log.Printf("[Polar] No user_id in metadata, skipping SDK handler")
		return nil
	}

	planName := sub.Metadata["plan"]
	if planName == "" {
		planName = "starter"
	}

	// Determine status including trial
	status := sub.Status
	if sub.IsTrialing && sub.TrialEndsAt != nil {
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
	}

	if err := h.queries.UpdateUserSubscription(ctx, params); err != nil {
		return fmt.Errorf("failed to update user subscription: %w", err)
	}

	// Store trial information if applicable
	if sub.IsTrialing && sub.TrialEndsAt != nil {
		log.Printf("[Polar] User %s started trial, ends at %s", userID, sub.TrialEndsAt.Format(time.RFC3339))
	}

	log.Printf("[Polar] Updated subscription for user %s to plan %s (status: %s)", userID, planName, status)
	return nil
}

func (h *WebhookHandler) handleSubscriptionCanceled(ctx context.Context, payload []byte) error {
	var sub SubscriptionData
	if err := json.Unmarshal(payload, &sub); err != nil {
		return fmt.Errorf("failed to parse subscription cancellation: %w", err)
	}

	userID := sub.Metadata["user_id"]
	if userID == "" {
		// No user_id in metadata - let legacy handler try customer ID lookup
		log.Printf("[Polar] No user_id in metadata, skipping SDK handler")
		return nil
	}

	params := database.UpdateUserSubscriptionParams{
		ID:                            database.ToPgUUID(userID),
		Plan:                          "starter", // Downgrade to starter
		PolarSubscriptionID:           database.ToPgText(sub.ID),
		SubscriptionStatus:            database.ToPgText("canceled"),
		SubscriptionCurrentPeriodEnd:  database.ToPgTimestamptz(sub.CurrentPeriodEnd),
		SubscriptionCancelAtPeriodEnd: database.ToPgBool(true),
	}

	if err := h.queries.UpdateUserSubscription(ctx, params); err != nil {
		return fmt.Errorf("failed to cancel user subscription: %w", err)
	}

	log.Printf("[Polar] Canceled subscription for user %s", userID)
	return nil
}

func (h *WebhookHandler) handleSubscriptionUncanceled(ctx context.Context, payload []byte) error {
	var sub SubscriptionData
	if err := json.Unmarshal(payload, &sub); err != nil {
		return fmt.Errorf("failed to parse subscription uncancel: %w", err)
	}

	userID := sub.Metadata["user_id"]
	if userID == "" {
		// No user_id in metadata - let legacy handler try customer ID lookup
		log.Printf("[Polar] No user_id in metadata, skipping SDK handler")
		return nil
	}

	planName := sub.Metadata["plan"]
	if planName == "" {
		planName = "starter"
	}

	params := database.UpdateUserSubscriptionParams{
		ID:                             database.ToPgUUID(userID),
		Plan:                           planName,
		PolarSubscriptionID:            database.ToPgText(sub.ID),
		SubscriptionStatus:             database.ToPgText(sub.Status),
		SubscriptionCurrentPeriodStart: database.ToPgTimestamptz(sub.CurrentPeriodStart),
		SubscriptionCurrentPeriodEnd:   database.ToPgTimestamptz(sub.CurrentPeriodEnd),
		SubscriptionCancelAtPeriodEnd:  database.ToPgBool(false),
	}

	if err := h.queries.UpdateUserSubscription(ctx, params); err != nil {
		return fmt.Errorf("failed to uncancel user subscription: %w", err)
	}

	log.Printf("[Polar] Uncanceled subscription for user %s", userID)
	return nil
}
