// Package email provides email sending capabilities for user notifications
package email

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"time"
)

// Mailtrap API endpoints
const (
	mailtrapBaseURL = "https://send.api.mailtrap.io"
	mailtrapSendAPI = "/api/send"
)

// Service handles email sending via Mailtrap
type Service struct {
	apiToken   string
	fromEmail  string
	fromName   string
	httpClient *http.Client
	templates  map[string]*template.Template
}

// MailtrapEmail represents the email payload for Mailtrap API
type MailtrapEmail struct {
	From      MailtrapAddress   `json:"from"`
	To        []MailtrapAddress `json:"to"`
	Subject   string            `json:"subject"`
	HTML      string            `json:"html"`
	Text      string            `json:"text,omitempty"`
	Category  string            `json:"category,omitempty"`
}

// MailtrapAddress represents an email address
type MailtrapAddress struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

// NewService creates a new email service using Mailtrap
func NewService() *Service {
	apiToken := os.Getenv("MAILTRAP_API_TOKEN")
	if apiToken == "" {
		return nil // Email service disabled if no API token
	}

	fromEmail := os.Getenv("EMAIL_FROM")
	if fromEmail == "" {
		fromEmail = "noreply@kerneleye.cloud"
	}
	fromName := os.Getenv("EMAIL_FROM_NAME")
	if fromName == "" {
		fromName = "KernelEye"
	}

	return &Service{
		apiToken:  apiToken,
		fromEmail: fromEmail,
		fromName:  fromName,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		templates: make(map[string]*template.Template),
	}
}

// IsEnabled returns true if the email service is configured
func (s *Service) IsEnabled() bool {
	return s != nil && s.apiToken != ""
}

// sendEmail sends an email via Mailtrap API
func (s *Service) sendEmail(toEmail, toName, subject, htmlContent, category string) error {
	if !s.IsEnabled() {
		return fmt.Errorf("email service not configured")
	}

	email := MailtrapEmail{
		From: MailtrapAddress{
			Email: s.fromEmail,
			Name:  s.fromName,
		},
		To: []MailtrapAddress{
			{
				Email: toEmail,
				Name:  toName,
			},
		},
		Subject:  subject,
		HTML:     htmlContent,
		Text:     stripHTML(htmlContent),
		Category: category,
	}

	payload, err := json.Marshal(email)
	if err != nil {
		return fmt.Errorf("failed to marshal email: %w", err)
	}

	req, err := http.NewRequest("POST", mailtrapBaseURL+mailtrapSendAPI, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.apiToken)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var errResp map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil {
			return fmt.Errorf("mailtrap error: %v", errResp)
		}
		return fmt.Errorf("mailtrap error: status %d", resp.StatusCode)
	}

	return nil
}

// SendWelcomeEmail sends a welcome email with dashboard access after subscription
func (s *Service) SendWelcomeEmail(toEmail, toName, plan string) error {
	dashboardURL := os.Getenv("DASHBOARD_URL")
	if dashboardURL == "" {
		dashboardURL = "https://app.kerneleye.cloud"
	}

	subject := "Welcome to KernelEye - Your Dashboard Access"

	htmlContent := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Welcome to KernelEye</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #6366f1 0%%, #8b5cf6 100%%); padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }
        .header h1 { color: white; margin: 0; font-size: 28px; }
        .content { background: #f9fafb; padding: 30px; border-radius: 0 0 8px 8px; }
        .button { display: inline-block; background: #6366f1; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; margin: 20px 0; }
        .footer { text-align: center; margin-top: 30px; font-size: 12px; color: #6b7280; }
        .plan-badge { background: #dbeafe; color: #1e40af; padding: 4px 12px; border-radius: 12px; font-size: 14px; font-weight: 600; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Welcome to KernelEye</h1>
    </div>
    <div class="content">
        <p>Hi %s,</p>
        
        <p>Thank you for subscribing to KernelEye! Your account has been successfully created.</p>
        
        <p><strong>Plan:</strong> <span class="plan-badge">%s</span></p>
        
        <p>You can now access your dashboard and start monitoring your servers:</p>
        
        <center>
            <a href="%s" class="button">Access Dashboard</a>
        </center>
        
        <p>Or copy this link: <a href="%s">%s</a></p>
        
        <h3>Next Steps:</h3>
        <ol>
            <li>Log in to your dashboard</li>
            <li>Generate an API key for your first server</li>
            <li>Install the KernelEye agent on your Linux servers</li>
            <li>Start monitoring in real-time</li>
        </ol>
        
        <p>Need help? Reply to this email or contact us at support@kerneleye.cloud</p>
        
        <p>Best regards,<br>The KernelEye Team</p>
    </div>
    <div class="footer">
        <p>&copy; 2025 KernelEye. All rights reserved.</p>
        <p>You received this email because you subscribed to KernelEye.</p>
    </div>
</body>
</html>
`, toName, plan, dashboardURL, dashboardURL, dashboardURL)

	return s.sendEmail(toEmail, toName, subject, htmlContent, "welcome")
}

// SendPasswordResetEmail sends a password reset email
func (s *Service) SendPasswordResetEmail(toEmail, toName, resetToken string) error {
	dashboardURL := os.Getenv("DASHBOARD_URL")
	if dashboardURL == "" {
		dashboardURL = "https://app.kerneleye.cloud"
	}
	
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", dashboardURL, resetToken)
	subject := "Password Reset Request - KernelEye"

	htmlContent := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Password Reset</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #6366f1 0%%, #8b5cf6 100%%); padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }
        .header h1 { color: white; margin: 0; font-size: 24px; }
        .content { background: #f9fafb; padding: 30px; border-radius: 0 0 8px 8px; }
        .button { display: inline-block; background: #6366f1; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; margin: 20px 0; }
        .footer { text-align: center; margin-top: 30px; font-size: 12px; color: #6b7280; }
        .warning { background: #fef3c7; border-left: 4px solid #f59e0b; padding: 12px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Password Reset</h1>
    </div>
    <div class="content">
        <p>Hi %s,</p>
        
        <p>We received a request to reset your KernelEye password. Click the button below to reset it:</p>
        
        <center>
            <a href="%s" class="button">Reset Password</a>
        </center>
        
        <div class="warning">
            <strong>Note:</strong> This link will expire in 1 hour. If you didn't request this, please ignore this email.
        </div>
        
        <p>Or copy this link: <a href="%s">%s</a></p>
        
        <p>Best regards,<br>The KernelEye Team</p>
    </div>
    <div class="footer">
        <p>&copy; 2025 KernelEye. All rights reserved.</p>
    </div>
</body>
</html>
`, toName, resetURL, resetURL, resetURL)

	return s.sendEmail(toEmail, toName, subject, htmlContent, "password_reset")
}

// SendTrialEndingEmail sends a reminder when trial is about to end
func (s *Service) SendTrialEndingEmail(toEmail, toName string, daysLeft int) error {
	dashboardURL := os.Getenv("DASHBOARD_URL")
	if dashboardURL == "" {
		dashboardURL = "https://app.kerneleye.cloud"
	}
	
	billingURL := fmt.Sprintf("%s/billing", dashboardURL)
	subject := fmt.Sprintf("Your KernelEye Trial Ends in %d Days", daysLeft)

	htmlContent := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Trial Ending Soon</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #f59e0b 0%%, #d97706 100%%); padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }
        .header h1 { color: white; margin: 0; font-size: 24px; }
        .content { background: #f9fafb; padding: 30px; border-radius: 0 0 8px 8px; }
        .button { display: inline-block; background: #f59e0b; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; margin: 20px 0; }
        .footer { text-align: center; margin-top: 30px; font-size: 12px; color: #6b7280; }
        .alert { background: #fef3c7; border-left: 4px solid #f59e0b; padding: 12px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Trial Ending Soon</h1>
    </div>
    <div class="content">
        <p>Hi %s,</p>
        
        <div class="alert">
            Your KernelEye free trial ends in <strong>%d days</strong>.
        </div>
        
        <p>To continue monitoring your servers without interruption, please upgrade to a paid plan:</p>
        
        <center>
            <a href="%s" class="button">Upgrade Now</a>
        </center>
        
        <p><strong>Questions?</strong> Reply to this email or contact support@kerneleye.cloud</p>
        
        <p>Best regards,<br>The KernelEye Team</p>
    </div>
    <div class="footer">
        <p>&copy; 2025 KernelEye. All rights reserved.</p>
    </div>
</body>
</html>
`, toName, daysLeft, billingURL)

	return s.sendEmail(toEmail, toName, subject, htmlContent, "trial_reminder")
}

// stripHTML removes HTML tags for plain text version
func stripHTML(html string) string {
	var buf bytes.Buffer
	inTag := false
	for _, r := range html {
		switch r {
		case '<':
			inTag = true
		case '>':
			inTag = false
		default:
			if !inTag {
				buf.WriteRune(r)
			}
		}
	}
	return buf.String()
}
