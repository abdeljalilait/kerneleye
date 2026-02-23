# Setting Up 7-Day Free Trial with Polar

This guide explains how to configure a 7-day free trial that requires users to add their credit card.

## Overview

With Polar, you can set up trial periods that require payment information upfront. This ensures:
- Users are serious about trying the product
- Seamless transition to paid subscription after trial
- Reduced churn from "ghost" trials

## Step 1: Configure Products in Polar Dashboard

### Option A: Via Polar Dashboard

1. Log in to your [Polar Dashboard](https://polar.sh)
2. Go to **Products** → **Create Product**
3. Fill in product details:
   - Name: "Starter Plan"
   - Description: "Up to 10 servers with 7-day free trial"
4. Under **Pricing**, click **Add Price**
   - Type: Recurring
   - Amount: $49.00
   - Currency: USD
   - Billing Interval: Month
5. Expand **Advanced Settings**
6. Set **Trial Period**: 7 days
7. Enable **Require payment method for trial**
8. Save the product

Repeat for Professional and Enterprise plans.

### Option B: Via API

```bash
# Create Starter Plan with 7-day trial
curl -X POST https://api.polar.sh/api/v1/products \
  -H "Authorization: Bearer $POLAR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Starter Plan",
    "description": "Up to 10 servers with 7-day free trial",
    "prices": [{
      "amount_type": "fixed",
      "price_amount": 4900,
      "price_currency": "usd",
      "recurring_interval": "month"
    }],
    "subscription_settings": {
      "trial_period_days": 7,
      "payment_required_for_trial": true
    }
  }'
```

## Step 2: Get Product/Price IDs

After creating products, get their IDs:

```bash
# List all products
curl https://api.polar.sh/api/v1/products \
  -H "Authorization: Bearer $POLAR_ACCESS_TOKEN"
```

Response will include:
```json
{
  "items": [{
    "id": "prod_xxx",
    "name": "Starter Plan",
    "prices": [{
      "id": "price_xxx",
      "price_amount": 4900
    }]
  }]
}
```

## Step 3: Update Environment Variables

Add these to your `.env` file:

```bash
# Polar Product/Price IDs
POLAR_PRODUCT_ID_STARTER=prod_xxx
POLAR_PRICE_ID_STARTER=price_xxx
POLAR_PRODUCT_ID_PRO=prod_yyy
POLAR_PRICE_ID_PRO=price_yyy
```

## Step 4: Update Database Plans

Insert plans with Polar IDs into your database:

```sql
INSERT INTO subscription_plans (
    name, display_name, description, price_cents, currency, 
    billing_interval, max_servers, data_retention_days,
    polar_product_id, polar_price_id, is_active
) VALUES 
('starter', 'Starter', 'Up to 10 servers', 4900, 'usd', 'month', 10, 7, 'prod_xxx', 'price_xxx', true),
('pro', 'Professional', 'Up to 50 servers', 14900, 'usd', 'month', 50, 90, 'prod_yyy', 'price_yyy', true);
```

## Step 5: Webhook Events for Trials

The backend handles these trial-related webhook events:

### 1. `subscription.trialing`
Triggered when a user starts a trial.

**Actions:**
- Set `subscription_status = 'trialing'`
- Set `trial_ends_at` to trial end date
- Send welcome email with trial info

### 2. `subscription.active`
Triggered when trial ends and subscription becomes active (paid).

**Actions:**
- Set `subscription_status = 'active'`
- Clear trial flag

### 3. `subscription.canceled`
Triggered when user cancels during trial or subscription ends.

**Actions:**
- Downgrade to free plan
- Set `subscription_status = 'canceled'`

### 4. `invoice.payment_failed`
Triggered when payment fails after trial ends.

**Actions:**
- Grace period handling
- Email notification to user
- Potential downgrade if not resolved

## Step 6: Dashboard UI for Trial Status

The dashboard subscription page shows trial status:

```typescript
// From useQueries.ts
interface SubscriptionStatus {
  plan: string
  status: 'trialing' | 'active' | 'canceled' | 'past_due'
  trial_ends_at?: string
  is_trialing: boolean
  // ... other fields
}
```

Display trial banner in UI:
```tsx
{status.is_trialing && (
  <Alert
    message={`Your trial ends on ${new Date(status.trial_ends_at!).toLocaleDateString()}`}
    type="info"
    showIcon
  />
)}
```

## Step 7: Trial Expiration Handling

### Backend Middleware
Check trial status on API requests:

```go
func CheckTrialMiddleware(queries *database.Queries) fiber.Handler {
    return func(c *fiber.Ctx) error {
        userID := c.Locals("user_id").(string)
        
        user, err := queries.GetUserByID(c.Context(), database.ToPgUUID(userID))
        if err != nil {
            return err
        }
        
        // Check if trial has expired
        if user.TrialEndsAt.Valid && user.TrialEndsAt.Time.Before(time.Now()) {
            if user.SubscriptionStatus.String == "trialing" {
                // Trial expired, downgrade to free
                return c.Status(402).JSON(fiber.Map{
                    "error": "Trial expired",
                    "message": "Please upgrade to continue using premium features",
                    "upgrade_url": "/subscription",
                })
            }
        }
        
        return c.Next()
    }
}
```

### Frontend Handling
Show upgrade modal when trial expires:

```tsx
useEffect(() => {
  if (status?.is_trialing && status?.trial_ends_at) {
    const daysLeft = Math.ceil(
      (new Date(status.trial_ends_at).getTime() - Date.now()) / (1000 * 60 * 60 * 24)
    )
    
    if (daysLeft <= 3 && daysLeft > 0) {
      // Show trial ending soon warning
      notification.warning({
        message: `Trial ends in ${daysLeft} days`,
        description: 'Add a payment method to continue using all features',
        duration: 0,
      })
    }
  }
}, [status])
```

## User Flow with Trial

1. **Sign Up**: User signs up via GitHub/Google OAuth
2. **Choose Plan**: User selects a plan on subscription page
3. **Checkout**: Redirected to Polar checkout
4. **Add Card**: User enters credit card (not charged yet)
5. **Trial Starts**: 7-day trial begins immediately
6. **Usage**: Full access to all plan features
7. **Day 7**: First charge if not canceled
8. **Receipt**: Email invoice sent

## Testing Trials

### Test Mode
Use Polar's test mode to simulate trials:

```bash
# Use test API key
POLAR_ACCESS_TOKEN=polar_test_xxx

# Use test price IDs
POLAR_PRICE_ID_STARTER=price_test_xxx
```

### Test Cards
Use Polar test cards:
- **Success**: `4242 4242 4242 4242`
- **Decline**: `4000 0000 0000 0002`
- **Require auth**: `4000 0025 0000 3155`

### Accelerate Time
For testing trial end:
1. Create subscription with trial
2. In Polar dashboard, find subscription
3. Click **End Trial Early**
4. Verify payment succeeds/fails as expected

## Monitoring Trials

Track trial metrics:

```sql
-- Active trials
SELECT COUNT(*) FROM users 
WHERE subscription_status = 'trialing' 
  AND trial_ends_at > NOW();

-- Trial conversion rate (trials that became paid)
SELECT 
  COUNT(CASE WHEN subscription_status = 'active' THEN 1 END) * 100.0 / COUNT(*) 
  AS conversion_rate
FROM users 
WHERE trial_ends_at IS NOT NULL 
  AND trial_ends_at < NOW();

-- Trials expiring in next 24 hours
SELECT email, trial_ends_at FROM users 
WHERE subscription_status = 'trialing' 
  AND trial_ends_at BETWEEN NOW() AND NOW() + INTERVAL '24 hours';
```

## Email Notifications

Send emails at key trial moments:

1. **Trial Started**: Welcome + trial info
2. **Day 3**: Usage tips and feature highlights
3. **Day 6**: "Trial ends tomorrow" reminder
4. **Day 7 (Success)**: Welcome to paid plan + invoice
5. **Day 7 (Failed)**: Payment failed, update card
6. **Canceled**: Sorry to see you go + feedback request

## Troubleshooting

### Issue: Trial not showing in checkout
**Solution**: Verify product has `trial_period_days` set in Polar

### Issue: Webhook not receiving trial events
**Solution**: Check webhook endpoint registered for `subscription.trialing` event type

### Issue: Trial end date not saved
**Solution**: Ensure `trial_ends_at` field is in UpdateUserSubscription query params

### Issue: User charged immediately
**Solution**: Verify `payment_required_for_trial: true` and trial days > 0

## Best Practices

1. **Clear Communication**: Tell users when trial ends and what they'll be charged
2. **Easy Cancellation**: Make it simple to cancel during trial
3. **Value Demonstration**: Help users see value in first 7 days
4. **Grace Period**: Offer 3-day grace period after failed payment
5. **Feedback Collection**: Ask why users cancel during trial
6. **Win-back Campaign**: Email users after trial cancellation with discount offers

## Support

For Polar-specific issues:
- Docs: https://docs.polar.sh
- Support: support@polar.sh
- API Reference: https://api.polar.sh/docs

For KernelEye integration issues:
- Check webhook logs: `docker logs kerneleye-backend`
- Verify environment variables are set
- Check database has correct Polar price IDs
