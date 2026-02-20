import { useEffect, useState, useCallback } from 'react';
import { useRouter, useSearch } from '@tanstack/react-router';
import { Card, Button, Typography, Tag, Spin, Alert, Divider, Row, Col, Statistic, Grid, Space, Modal } from 'antd';
import { Check, ArrowLeft, CreditCard, ExternalLink, Crown, Server, Database, Sparkles } from 'lucide-react';
import { useSubscriptionPlans, useSubscriptionStatus, useCreateCheckout, useCreateCustomerPortal } from '../hooks/useQueries';

// Polar embedded checkout - loaded via CDN
declare global {
  interface Window {
    PolarEmbedCheckout?: {
      create: (options: {
        checkoutUrl: string;
        onSuccess: () => void;
        onClose?: () => void;
        target?: string;
        theme?: 'light' | 'dark';
      }) => { close: () => void };
    };
  }
}

const { Title, Text, Paragraph } = Typography;

interface Plan {
  id: string;
  name: string;
  display_name: string;
  description: string;
  price_cents: number;
  currency: string;
  billing_interval: string;
  max_servers: number;
  data_retention_days: number;
  features: Record<string, any>;
  is_default: boolean;
  polar_price_id?: string;
}

const Subscription = () => {
  const screens = Grid.useBreakpoint();
  const router = useRouter();
  const search = useSearch({ from: '/subscription' });
  const [selectedPlan, setSelectedPlan] = useState<string | null>(null);
  const [checkoutError, setCheckoutError] = useState<string | null>(null);
  const [isCheckoutOpen, setIsCheckoutOpen] = useState(false);

  // Helper to calculate days left in trial
  const getTrialDaysLeft = (trialEndsAt?: string): number | null => {
    if (!trialEndsAt) return null;
    const daysLeft = Math.ceil(
      (new Date(trialEndsAt).getTime() - Date.now()) / (1000 * 60 * 60 * 24)
    );
    return daysLeft > 0 ? daysLeft : 0;
  };

  const { data: plans, isLoading: plansLoading } = useSubscriptionPlans();
  const { data: status, isLoading: statusLoading } = useSubscriptionStatus();
  const checkoutMutation = useCreateCheckout();
  const portalMutation = useCreateCustomerPortal();

  // Load Polar checkout script
  useEffect(() => {
    const existingScript = document.getElementById('polar-checkout-script');
    if (!existingScript) {
      const script = document.createElement('script');
      script.id = 'polar-checkout-script';
      script.src = 'https://cdn.jsdelivr.net/npm/@polar-sh/checkout@latest/dist/embed.global.js';
      script.async = true;
      script.dataset.autoInit = 'false';
      document.body.appendChild(script);
    }
  }, []);

  // Handle plan selection from URL query param
  useEffect(() => {
    const planParam = (search as any)?.plan;
    if (planParam && plans) {
      const plan = plans.find((p: Plan) => p.name === planParam);
      if (plan && !isCheckoutOpen) {
        handleSelectPlan(plan);
      }
    }
  }, [search, plans, isCheckoutOpen]);

  const handleCheckoutSuccess = useCallback(() => {
    setIsCheckoutOpen(false);
    // Navigate to success page
    router.navigate({ to: '/subscription/success' });
  }, [router]);

  const handleCheckoutClose = useCallback(() => {
    setIsCheckoutOpen(false);
  }, []);

  const openEmbeddedCheckout = useCallback((url: string) => {
    if (!window.PolarEmbedCheckout) {
      // Fallback to redirect if script not loaded yet
      window.location.href = url;
      return;
    }

    setIsCheckoutOpen(true);

    window.PolarEmbedCheckout.create({
      checkoutUrl: url,
      onSuccess: handleCheckoutSuccess,
      onClose: handleCheckoutClose,
      theme: document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light',
    });
  }, [handleCheckoutSuccess, handleCheckoutClose]);

  const handleSelectPlan = async (plan: Plan) => {
    console.log('[Checkout] Selecting plan:', plan.name, '-> normalized:', plan.name.toLowerCase());
    setSelectedPlan(plan.name);
    setCheckoutError(null);

    try {
      // Pass embed_origin for embedded checkout support
      const embedOrigin = window.location.origin;
      console.log('[Checkout] Sending request with planName:', plan.name.toLowerCase(), 'embedOrigin:', embedOrigin);
      
      const data = await checkoutMutation.mutateAsync({
        planName: plan.name.toLowerCase(),
        embedOrigin,
      });
      
      console.log('[Checkout] Response:', data);
      
      if (data.checkout_url) {
        // Check if embedded checkout is supported and use it
        if (data.embedded || window.PolarEmbedCheckout) {
          openEmbeddedCheckout(data.checkout_url);
        } else {
          // Fallback to redirect
          window.location.href = data.checkout_url;
        }
      } else {
        setCheckoutError('No checkout URL received. Please try again.');
      }
    } catch (error: any) {
      console.error('[Checkout] Error:', error);
      console.error('[Checkout] Response data:', error?.response?.data);
      setCheckoutError(error?.response?.data?.error || 'Failed to create checkout session. Please try again.');
    }
  };

  const handleManageSubscription = async () => {
    try {
      const data = await portalMutation.mutateAsync();
      if (data.portal_url) {
        window.open(data.portal_url, '_blank');
      }
    } catch (error: any) {
      console.error('Failed to create customer portal:', error);
    }
  };

  const formatPrice = (cents: number, currency: string) => {
    const amount = cents / 100;
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: currency.toUpperCase(),
    }).format(amount);
  };

  if (plansLoading || statusLoading) {
    return (
      <div style={{ padding: 48, textAlign: 'center' }}>
        <Spin size="large" />
        <Text style={{ display: 'block', marginTop: 16, color: 'var(--text-secondary)' }}>
          Loading subscription details...
        </Text>
      </div>
    );
  }

  return (
    <div style={{ padding: '24px 48px', maxWidth: 1200, margin: '0 auto' }}>
      {/* Header */}
      <div style={{ marginBottom: 32 }}>
        <Button 
          icon={<ArrowLeft size={16} />} 
          type="text" 
          onClick={() => router.navigate({ to: '/dashboard' })}
          style={{ marginBottom: 16 }}
        >
          Back to Dashboard
        </Button>
        <Title level={2} style={{ margin: 0, color: 'var(--text-primary)' }}>
          {status?.plan === 'none' ? 'Choose Your Plan' : 'Subscription & Billing'}
        </Title>
        <Text style={{ color: 'var(--text-secondary)' }}>
          {status?.plan === 'none' 
            ? 'Start your 7-day free trial or subscribe to a plan to add servers' 
            : 'Manage your KernelEye subscription and billing details'}
        </Text>
      </div>

      {/* Current Status */}
      {status && (
        <Card 
          style={{ 
            marginBottom: 32, 
            background: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
          }}
        >
          <Row gutter={[32, 24]} align="middle">
            <Col xs={24} md={8}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                <div 
                  style={{
                    width: 56,
                    height: 56,
                    borderRadius: 12,
                    background: status.plan === 'none' 
                      ? 'linear-gradient(135deg, #6b7280, #9ca3af)' 
                      : 'linear-gradient(135deg, #6366f1, #8b5cf6)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  <Crown size={28} color="white" />
                </div>
                <div>
                  <Text style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Current Plan</Text>
                  <Title level={4} style={{ margin: 0, color: 'var(--text-primary)' }}>
                    {status.plan_display_name}
                  </Title>
                  <Tag color={status.is_trialing ? 'gold' : status.status === 'active' ? 'green' : status.plan === 'none' ? 'red' : 'default'}>
                    {status.is_trialing ? 'Trial' : status.status === 'inactive' ? 'No Active Plan' : status.status}
                  </Tag>
                </div>
              </div>
            </Col>
            <Col xs={24} md={10}>
              <Row gutter={16}>
                <Col span={12}>
                  <Statistic
                    title={<Text style={{ color: 'var(--text-secondary)' }}>Servers</Text>}
                    value={status.plan === 'none' ? '0' : `${status.current_servers} / ${status.max_servers}`}
                    prefix={<Server size={16} style={{ marginRight: 8 }} />}
                    valueStyle={{ color: 'var(--text-primary)', fontSize: 18 }}
                  />
                </Col>
                <Col span={12}>
                  <Statistic
                    title={<Text style={{ color: 'var(--text-secondary)' }}>Data Retention</Text>}
                    value={status.plan === 'none' ? '-' : `${status.data_retention_days} days`}
                    prefix={<Database size={16} style={{ marginRight: 8 }} />}
                    valueStyle={{ color: 'var(--text-primary)', fontSize: 18 }}
                  />
                </Col>
              </Row>
            </Col>
            <Col xs={24} md={6} style={{ textAlign: 'right' }}>
              {status.plan !== 'none' && (
                <Button
                  icon={<ExternalLink size={16} />}
                  onClick={handleManageSubscription}
                  loading={portalMutation.isPending}
                >
                  Manage Subscription
                </Button>
              )}
            </Col>
          </Row>

          {status.plan === 'none' && (
            <Alert
              message="Start Your Free Trial"
              description="Choose a plan below to start your 7-day free trial. Your credit card will be charged only after the trial ends. Cancel anytime."
              type="info"
              showIcon
              icon={<Sparkles size={16} />}
              style={{ marginTop: 16, background: 'rgba(99, 102, 241, 0.1)', border: '1px solid rgba(99, 102, 241, 0.3)' }}
            />
          )}

          {status.is_trialing && status.trial_ends_at && (
            (() => {
              const daysLeft = getTrialDaysLeft(status.trial_ends_at);
              return (
                <Alert
                  message={daysLeft && daysLeft <= 3 
                    ? `Your free trial ends in ${daysLeft} day${daysLeft !== 1 ? 's' : ''}` 
                    : `Your free trial ends on ${new Date(status.trial_ends_at).toLocaleDateString()}`}
                  description="Add a payment method before your trial ends to continue using all features without interruption."
                  type={daysLeft && daysLeft <= 3 ? "warning" : "info"}
                  showIcon
                  style={{ marginTop: 16 }}
                />
              );
            })()
          )}

          {!status.is_trialing && status.cancel_at_period_end && (
            <Alert
              message="Your subscription will cancel at the end of the current period"
              type="warning"
              showIcon
              style={{ marginTop: 16 }}
            />
          )}
        </Card>
      )}

      {/* Error Alert */}
      {checkoutError && (
        <Alert
          message={checkoutError}
          type="error"
          showIcon
          closable
          onClose={() => setCheckoutError(null)}
          style={{ marginBottom: 24 }}
        />
      )}

      {/* Plans */}
      <Title level={4} style={{ marginBottom: 24, color: 'var(--text-primary)' }}>
        Available Plans
      </Title>

      <Row gutter={[24, 24]}>
        {plans?.map((plan: Plan) => {
          const isCurrentPlan = status?.plan === plan.name && status?.plan !== 'none';
          const isProcessing = selectedPlan === plan.name && checkoutMutation.isPending;

          return (
            <Col xs={24} md={8} key={plan.id}>
              <Card
                style={{
                  height: '100%',
                  background: 'var(--bg-card)',
                  border: isCurrentPlan ? '2px solid #6366f1' : '1px solid var(--border-subtle)',
                  position: 'relative',
                }}
                bodyStyle={{ height: '100%', display: 'flex', flexDirection: 'column' }}
              >
                {isCurrentPlan && (
                  <Tag 
                    color={status?.is_trialing ? "gold" : "geekblue"}
                    style={{ position: 'absolute', top: 16, right: 16 }}
                  >
                    {status?.is_trialing ? "In Trial" : "Current Plan"}
                  </Tag>
                )}

                <div style={{ flex: 1 }}>
                  <Title level={4} style={{ margin: 0, marginBottom: 8, color: 'var(--text-primary)' }}>
                    {plan.display_name}
                  </Title>
                  <Paragraph style={{ color: 'var(--text-secondary)', minHeight: 44 }}>
                    {plan.description}
                  </Paragraph>

                  <div style={{ margin: '24px 0' }}>
                    <Text style={{ fontSize: 32, fontWeight: 700, color: 'var(--text-primary)' }}>
                      {formatPrice(plan.price_cents, plan.currency)}
                    </Text>
                    <Text style={{ color: 'var(--text-secondary)' }}>
                      /{plan.billing_interval}
                    </Text>
                  </div>

                  <Divider style={{ borderColor: 'var(--border-subtle)' }} />

                  <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
                    <li style={{ marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
                      <Check size={16} style={{ color: '#10b981' }} />
                      <Text style={{ color: 'var(--text-secondary)' }}>
                        Up to {plan.max_servers} servers
                      </Text>
                    </li>
                    <li style={{ marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
                      <Check size={16} style={{ color: '#10b981' }} />
                      <Text style={{ color: 'var(--text-secondary)' }}>
                        {plan.data_retention_days} days data retention
                      </Text>
                    </li>
                    {plan.features && Object.entries(plan.features).map(([key, value]) => (
                      <li key={key} style={{ marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
                        <Check size={16} style={{ color: '#10b981' }} />
                        <Text style={{ color: 'var(--text-secondary)' }}>
                          {typeof value === 'string' ? value : key}
                        </Text>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Show trial button for new users, subscribe button for others */}
                {status?.plan === 'none' ? (
                  <Space direction="vertical" style={{ width: '100%', marginTop: 24 }} size={8}>
                    <Button
                      type="primary"
                      size="large"
                      block
                      loading={selectedPlan === plan.name && checkoutMutation.isPending}
                      onClick={() => handleSelectPlan(plan)}
                      icon={<Sparkles size={16} />}
                    >
                      {selectedPlan === plan.name && checkoutMutation.isPending ? 'Loading Checkout...' : 'Start 7-Day Free Trial'}
                    </Button>
                    <Text style={{ fontSize: 11, color: 'var(--text-tertiary)', textAlign: 'center', display: 'block' }}>
                      Credit card required. Cancel anytime during trial.
                    </Text>
                  </Space>
                ) : (
                  <Button
                    type={isCurrentPlan ? 'default' : 'primary'}
                    size="large"
                    block
                    style={{ marginTop: 24 }}
                    disabled={isCurrentPlan || isProcessing}
                    loading={isProcessing}
                    onClick={() => handleSelectPlan(plan)}
                    icon={isCurrentPlan ? <Check size={16} /> : <CreditCard size={16} />}
                  >
                    {isCurrentPlan ? 'Current Plan' : isProcessing ? 'Processing...' : 'Subscribe'}
                  </Button>
                )}
              </Card>
            </Col>
          );
        })}
      </Row>

      {/* Enterprise CTA */}
      <Card
        style={{
          marginTop: 32,
          background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.1), rgba(139, 92, 246, 0.1))',
          border: '1px solid rgba(99, 102, 241, 0.3)',
        }}
      >
        <Row align="middle" justify="space-between">
          <Col xs={24} md={16}>
            <Title level={4} style={{ margin: 0, marginBottom: 8, color: 'var(--text-primary)' }}>
              Need a custom enterprise solution?
            </Title>
            <Text style={{ color: 'var(--text-secondary)' }}>
              Contact our sales team for unlimited servers, dedicated support, and custom integrations.
            </Text>
          </Col>
          <Col xs={24} md={8} style={{ textAlign: 'right', marginTop: screens.md ? 0 : 16 }}>
            <Button 
              type="primary" 
              size="large"
              icon={<ExternalLink size={16} />}
              onClick={() => window.open('mailto:sales@kerneleye.cloud', '_blank')}
            >
              Contact Sales
            </Button>
          </Col>
        </Row>
      </Card>
    </div>
  );
};

export default Subscription;
