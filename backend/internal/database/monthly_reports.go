package database

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

// HasMonthlyReportBeenSent returns true if a monthly report has already been
// sent to this user for the given month. reportMonth should be the first day
// of the month being reported (e.g. 2026-02-01).
func (q *Queries) HasMonthlyReportBeenSent(ctx context.Context, userID pgtype.UUID, reportMonth time.Time) (bool, error) {
	const sql = `
		SELECT EXISTS (
			SELECT 1 FROM monthly_reports_sent
			WHERE user_id = $1
			  AND report_month = $2::date
		)
	`
	// Truncate to the first of the month to normalise the key
	month := time.Date(reportMonth.Year(), reportMonth.Month(), 1, 0, 0, 0, 0, time.UTC)

	var exists bool
	err := q.db.QueryRow(ctx, sql, userID, month).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// RecordMonthlyReportSent marks that a monthly report was sent to this user.
// Uses INSERT … ON CONFLICT DO NOTHING so calling it twice is safe.
func (q *Queries) RecordMonthlyReportSent(ctx context.Context, userID pgtype.UUID, reportMonth time.Time) error {
	const sql = `
		INSERT INTO monthly_reports_sent (user_id, report_month)
		VALUES ($1, $2::date)
		ON CONFLICT (user_id, report_month) DO NOTHING
	`
	month := time.Date(reportMonth.Year(), reportMonth.Month(), 1, 0, 0, 0, 0, time.UTC)

	_, err := q.db.Exec(ctx, sql, userID, month)
	return err
}
