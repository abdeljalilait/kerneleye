// Package analysis provides monthly reporting functionality
package analysis

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/kerneleye/backend/internal/database"
	"github.com/kerneleye/backend/internal/email"
)

// MonthlyReportManager handles generation and sending of monthly reports
type MonthlyReportManager struct {
	queries      *database.Queries
	emailService *email.Service
	stopChan     chan struct{}
	wg           sync.WaitGroup
}

// NewMonthlyReportManager creates a new monthly report manager
func NewMonthlyReportManager(queries *database.Queries, emailService *email.Service) *MonthlyReportManager {
	return &MonthlyReportManager{
		queries:      queries,
		emailService: emailService,
		stopChan:     make(chan struct{}),
	}
}

// Start begins the monthly report scheduler
func (m *MonthlyReportManager) Start(ctx context.Context) {
	m.wg.Add(1)
	go m.scheduleLoop(ctx)
	log.Println("[MonthlyReport] Started monthly report scheduler")
}

// Stop gracefully stops the monthly report manager
func (m *MonthlyReportManager) Stop() {
	close(m.stopChan)
	m.wg.Wait()
	log.Println("[MonthlyReport] Stopped")
}

// scheduleLoop checks daily if it's time to send monthly reports
func (m *MonthlyReportManager) scheduleLoop(ctx context.Context) {
	defer m.wg.Done()

	// Check once at startup
	m.checkAndSendReports(ctx)

	// Then check daily at midnight
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.checkAndSendReports(ctx)
		case <-ctx.Done():
			return
		case <-m.stopChan:
			return
		}
	}
}

// checkAndSendReports checks if today is the 1st of the month and sends reports
func (m *MonthlyReportManager) checkAndSendReports(ctx context.Context) {
	now := time.Now()
	// Send reports on the 1st of each month
	if now.Day() != 1 {
		return
	}

	// Get previous month for the report
	prevMonth := now.AddDate(0, -1, 0)
	startDate := time.Date(prevMonth.Year(), prevMonth.Month(), 1, 0, 0, 0, 0, time.UTC)
	endDate := startDate.AddDate(0, 1, 0).Add(-time.Second)

	log.Printf("[MonthlyReport] Generating reports for %s %d", prevMonth.Month(), prevMonth.Year())

	// Get all active users with email
	users, err := m.queries.ListUsersForReports(ctx)
	if err != nil {
		log.Printf("[MonthlyReport] Failed to list users: %v", err)
		return
	}

	for _, user := range users {
		// Check if user has email service enabled
		if user.Email == "" {
			continue
		}

		// Idempotency guard: skip if report was already sent this month.
		// This prevents duplicate emails when the server restarts on the 1st.
		alreadySent, err := m.queries.HasMonthlyReportBeenSent(ctx, user.ID, startDate)
		if err != nil {
			log.Printf("[MonthlyReport] Error checking sent status for %s: %v", user.Email, err)
			continue
		}
		if alreadySent {
			log.Printf("[MonthlyReport] Report for %s %d already sent to %s, skipping",
				prevMonth.Month(), prevMonth.Year(), user.Email)
			continue
		}

		// Generate report for this user
		report, err := m.generateUserReport(ctx, user.ID, startDate, endDate)
		if err != nil {
			log.Printf("[MonthlyReport] Failed to generate report for user %s: %v",
				database.FromPgUUID(user.ID), err)
			continue
		}

		// Send email
		if err := m.sendReportEmail(ctx, user.Email, user.Email, report, prevMonth); err != nil {
			log.Printf("[MonthlyReport] Failed to send report to %s: %v", user.Email, err)
			continue
		}

		// Record as sent so restarts cannot trigger a duplicate
		if err := m.queries.RecordMonthlyReportSent(ctx, user.ID, startDate); err != nil {
			log.Printf("[MonthlyReport] Warning: failed to record sent status for %s: %v", user.Email, err)
		}
	}
}

// UserReport contains monthly statistics for a user
type UserReport struct {
	TotalConnections   int64
	BlockedConnections int64
	ThreatConnections  int64
	UniqueThreatIPs    int64
	TopTargetedPorts   []PortStat
	TopBlockedIPs      []IPStat
	TopCountries       []CountryStat
	ServerCount        int32
}

// PortStat represents port targeting statistics
type PortStat struct {
	Port        int32
	ServiceName string
	Count       int64
}

// IPStat represents IP statistics
type IPStat struct {
	IPAddress string
	Country   string
	Count     int64
}

// CountryStat represents country statistics
type CountryStat struct {
	Country string
	Count   int64
}

// generateUserReport generates a monthly report for a specific user
func (m *MonthlyReportManager) generateUserReport(
	ctx context.Context,
	userID pgtype.UUID,
	startDate, endDate time.Time,
) (*UserReport, error) {
	report := &UserReport{}

	// Get server count
	serverCount, err := m.queries.CountServersByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to count servers: %w", err)
	}
	report.ServerCount = serverCount

	// Get total connections (traffic events)
	totalEvents, err := m.queries.GetMonthlyTrafficStats(ctx, database.GetMonthlyTrafficStatsParams{
		UserID:     userID,
		LastSeen:   database.ToPgTimestamptz(startDate),
		LastSeen_2: database.ToPgTimestamptz(endDate),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get traffic stats: %w", err)
	}
	report.TotalConnections = totalEvents

	// Get blocked connections
	blockedCount, err := m.queries.GetMonthlyBlockStats(ctx, database.GetMonthlyBlockStatsParams{
		UserID:      userID,
		BlockedAt:   database.ToPgTimestamptz(startDate),
		BlockedAt_2: database.ToPgTimestamptz(endDate),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get block stats: %w", err)
	}
	report.BlockedConnections = blockedCount

	// Get threat connections (non-normal threat levels)
	threatCount, err := m.queries.GetMonthlyThreatStats(ctx, database.GetMonthlyThreatStatsParams{
		UserID:     userID,
		LastSeen:   database.ToPgTimestamptz(startDate),
		LastSeen_2: database.ToPgTimestamptz(endDate),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get threat stats: %w", err)
	}
	report.ThreatConnections = threatCount

	// Get unique threat IPs
	uniqueThreats, err := m.queries.GetMonthlyUniqueThreatIPs(ctx, database.GetMonthlyUniqueThreatIPsParams{
		UserID:     userID,
		LastSeen:   database.ToPgTimestamptz(startDate),
		LastSeen_2: database.ToPgTimestamptz(endDate),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get unique threat IPs: %w", err)
	}
	report.UniqueThreatIPs = uniqueThreats

	// Get top targeted ports
	portStats, err := m.queries.GetMonthlyTopPorts(ctx, database.GetMonthlyTopPortsParams{
		UserID:     userID,
		LastSeen:   database.ToPgTimestamptz(startDate),
		LastSeen_2: database.ToPgTimestamptz(endDate),
	})
	if err == nil {
		for _, p := range portStats {
			report.TopTargetedPorts = append(report.TopTargetedPorts, PortStat{
				Port:        p.Port,
				ServiceName: fmt.Sprintf("%v", p.ServiceName),
				Count:       p.Count,
			})
		}
	}

	// Get top blocked IPs
	blockedIPs, err := m.queries.GetMonthlyTopBlockedIPs(ctx, database.GetMonthlyTopBlockedIPsParams{
		UserID:      userID,
		BlockedAt:   database.ToPgTimestamptz(startDate),
		BlockedAt_2: database.ToPgTimestamptz(endDate),
	})
	if err == nil {
		for _, ip := range blockedIPs {
			report.TopBlockedIPs = append(report.TopBlockedIPs, IPStat{
				IPAddress: ip.IpAddress.String(),
				Country:   fmt.Sprintf("%v", ip.Country),
				Count:     ip.Count,
			})
		}
	}

	// Get top countries
	countryStats, err := m.queries.GetMonthlyTopCountries(ctx, database.GetMonthlyTopCountriesParams{
		UserID:     userID,
		LastSeen:   database.ToPgTimestamptz(startDate),
		LastSeen_2: database.ToPgTimestamptz(endDate),
	})
	if err == nil {
		for _, c := range countryStats {
			report.TopCountries = append(report.TopCountries, CountryStat{
				Country: c.Country,
				Count:   c.Count,
			})
		}
	}

	return report, nil
}

// sendReportEmail sends the monthly report via email
func (m *MonthlyReportManager) sendReportEmail(
	ctx context.Context,
	toEmail, toName string,
	report *UserReport,
	month time.Time,
) error {
	if m.emailService == nil || !m.emailService.IsEnabled() {
		log.Printf("[MonthlyReport] Email service not enabled, skipping report for %s", toEmail)
		return nil
	}

	monthName := month.Format("January 2006")

	// Calculate percentages
	blockedPercent := float64(0)
	if report.TotalConnections > 0 {
		blockedPercent = float64(report.BlockedConnections) / float64(report.TotalConnections) * 100
	}

	// Build port list HTML
	portsHTML := ""
	for _, p := range report.TopTargetedPorts {
		portsHTML += fmt.Sprintf(`<tr>
			<td style="padding:8px;border-bottom:1px solid #e5e7eb;">Port %d (%s)</td>
			<td style="padding:8px;border-bottom:1px solid #e5e7eb;text-align:right;">%d</td>
		</tr>`, p.Port, p.ServiceName, p.Count)
	}

	// Build blocked IPs HTML
	blockedIPsHTML := ""
	for _, ip := range report.TopBlockedIPs {
		blockedIPsHTML += fmt.Sprintf(`<tr>
			<td style="padding:8px;border-bottom:1px solid #e5e7eb;">%s</td>
			<td style="padding:8px;border-bottom:1px solid #e5e7eb;">%s</td>
			<td style="padding:8px;border-bottom:1px solid #e5e7eb;text-align:right;">%d</td>
		</tr>`, ip.IPAddress, ip.Country, ip.Count)
	}

	subject := fmt.Sprintf("Your KernelEye Security Report - %s", monthName)

	htmlContent := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Monthly Security Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #6366f1 0%%, #8b5cf6 100%%); padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }
        .header h1 { color: white; margin: 0; font-size: 24px; }
        .header p { color: rgba(255,255,255,0.9); margin: 10px 0 0; }
        .content { background: #f9fafb; padding: 30px; border-radius: 0 0 8px 8px; }
        .stats-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; margin: 24px 0; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .stat-value { font-size: 32px; font-weight: 700; color: #6366f1; }
        .stat-label { font-size: 14px; color: #6b7280; margin-top: 4px; }
        .section { margin: 24px 0; }
        .section h3 { color: #1f2937; margin-bottom: 12px; }
        table { width: 100%%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; }
        th { background: #f3f4f6; padding: 12px; text-align: left; font-weight: 600; }
        .footer { text-align: center; margin-top: 30px; font-size: 12px; color: #6b7280; }
        .protected { color: #10b981; }
        .blocked { color: #ef4444; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ KernelEye Security Report</h1>
        <p>%s</p>
    </div>
    <div class="content">
        <p>Hi %s,</p>
        <p>Here's your monthly security summary for %d monitored server(s):</p>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">%s</div>
                <div class="stat-label">Total Connections</div>
            </div>
            <div class="stat-card">
                <div class="stat-value blocked">%s</div>
                <div class="stat-label">Blocked Attempts</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">%s</div>
                <div class="stat-label">Threats Detected</div>
            </div>
            <div class="stat-card">
                <div class="stat-value protected">%.1f%%</div>
                <div class="stat-label">Block Rate</div>
            </div>
        </div>

        <div class="section">
            <h3>🎯 Most Targeted Ports</h3>
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th style="text-align:right;">Attempts</th>
                    </tr>
                </thead>
                <tbody>
                    %s
                </tbody>
            </table>
        </div>

        <div class="section">
            <h3>🚫 Top Blocked IPs</h3>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Country</th>
                        <th style="text-align:right;">Blocks</th>
                    </tr>
                </thead>
                <tbody>
                    %s
                </tbody>
            </table>
        </div>

        <p style="margin-top: 24px; padding: 16px; background: #dbeafe; border-radius: 8px;">
            <strong>💡 Tip:</strong> Review your blocked IPs and whitelist any false positives in your dashboard.
        </p>

        <center>
            <a href="https://app.kerneleye.net/dashboard" style="display: inline-block; background: #6366f1; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; margin: 20px 0;">View Full Dashboard</a>
        </center>
    </div>
    <div class="footer">
        <p>&copy; 2025 KernelEye. All rights reserved.</p>
        <p>You're receiving this because you have security monitoring enabled.</p>
    </div>
</body>
</html>
`, monthName, toName, report.ServerCount,
		formatNumber(report.TotalConnections),
		formatNumber(report.BlockedConnections),
		formatNumber(report.ThreatConnections),
		blockedPercent,
		portsHTML, blockedIPsHTML)

	return m.emailService.SendMonthlyReport(toEmail, toName, subject, htmlContent)
}

func formatNumber(n int64) string {
	if n >= 1000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	}
	if n >= 1000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	}
	return fmt.Sprintf("%d", n)
}
