-- Migration 024: Track sent monthly reports to prevent duplicate sends on restart
--
-- The monthly report scheduler calls checkAndSendReports() at startup (to catch
-- missed months) AND via a daily ticker. Without tracking, restarting the server
-- on the 1st of the month re-sends every user's report.

CREATE TABLE IF NOT EXISTS monthly_reports_sent (
    id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    report_month DATE         NOT NULL,  -- first day of the reported month (e.g. 2026-02-01)
    sent_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),

    UNIQUE (user_id, report_month)
);

CREATE INDEX IF NOT EXISTS idx_monthly_reports_sent_user_month
    ON monthly_reports_sent (user_id, report_month);
