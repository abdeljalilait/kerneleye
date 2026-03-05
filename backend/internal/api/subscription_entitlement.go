package api

import (
	"strings"
	"time"

	"github.com/kerneleye/backend/internal/database"
)

// normalizeSubscriptionStatus keeps users active until current period end
// when cancellation is scheduled at period end.
func normalizeSubscriptionStatus(status string, isTrialing bool, cancelAtPeriodEnd bool, currentPeriodEnd time.Time, now time.Time) string {
	if isTrialing {
		return "trialing"
	}

	normalized := strings.TrimSpace(status)
	if normalized == "" {
		normalized = "inactive"
	}

	if normalized == "canceled" && cancelAtPeriodEnd && currentPeriodEnd.After(now) {
		return "active"
	}

	return normalized
}

// hasSubscriptionEntitlement determines whether the user still has subscription access.
func hasSubscriptionEntitlement(user database.User, now time.Time) bool {
	isTrialing := user.TrialEndsAt.Valid && user.TrialEndsAt.Time.After(now)
	if isTrialing {
		return true
	}

	status := strings.TrimSpace(user.SubscriptionStatus.String)
	if status == "active" || status == "trialing" {
		return true
	}

	return user.SubscriptionCancelAtPeriodEnd.Bool &&
		user.SubscriptionCurrentPeriodEnd.Valid &&
		user.SubscriptionCurrentPeriodEnd.Time.After(now)
}
