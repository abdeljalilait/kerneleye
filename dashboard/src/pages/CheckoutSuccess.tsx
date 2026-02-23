import { useEffect, useState } from 'react';
import { useRouter } from '@tanstack/react-router';
import { Card, Button, Typography, Spin, Result } from 'antd';
import { CheckCircle, ArrowRight, RefreshCw } from 'lucide-react';
import { useSubscriptionStatus } from '../hooks/useQueries';

const { Title, Text, Paragraph } = Typography;

const CheckoutSuccess = () => {
  const router = useRouter();
  const { data: status, isLoading, refetch } = useSubscriptionStatus();
  const [checkCount, setCheckCount] = useState(0);

  // Poll for subscription status updates
  useEffect(() => {
    if (status?.plan !== 'none' && status?.status === 'active') {
      // Subscription is active, stop polling
      return;
    }

    const interval = setInterval(() => {
      refetch();
      setCheckCount((prev) => prev + 1);
    }, 3000);

    // Stop polling after 30 seconds
    const timeout = setTimeout(() => {
      clearInterval(interval);
    }, 30000);

    return () => {
      clearInterval(interval);
      clearTimeout(timeout);
    };
  }, [status, refetch]);

  const isActive = status?.plan !== 'none' && status?.status === 'active';

  return (
    <div style={{ padding: '48px 24px', maxWidth: 600, margin: '0 auto' }}>
      <Card
        style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          textAlign: 'center',
        }}
      >
        {isLoading ? (
          <div style={{ padding: 48 }}>
            <Spin size="large" />
            <Text style={{ display: 'block', marginTop: 24, color: 'var(--text-secondary)' }}>
              Verifying your subscription...
            </Text>
          </div>
        ) : isActive ? (
          <Result
            icon={<CheckCircle size={64} style={{ color: '#10b981' }} />}
            title={<Title level={3} style={{ color: 'var(--text-primary)' }}>Welcome to KernelEye!</Title>}
            subTitle={
              <div style={{ color: 'var(--text-secondary)' }}>
                <Paragraph>
                  Your subscription to <strong>{status?.plan_display_name}</strong> is now active.
                </Paragraph>
                {status?.is_trialing && status?.trial_ends_at && (
                  <Paragraph>
                    Your 7-day free trial ends on{' '}
                    <strong>{new Date(status.trial_ends_at).toLocaleDateString()}</strong>.
                  </Paragraph>
                )}
                <Paragraph>
                  You can now add servers and start monitoring your infrastructure.
                </Paragraph>
              </div>
            }
            extra={[
              <Button
                key="dashboard"
                type="primary"
                size="large"
                icon={<ArrowRight size={16} />}
                onClick={() => router.navigate({ to: '/dashboard' })}
              >
                Go to Dashboard
              </Button>,
              <Button
                key="servers"
                size="large"
                onClick={() => router.navigate({ to: '/dashboard/servers' })}
              >
                Add Your First Server
              </Button>,
            ]}
          />
        ) : (
          <Result
            status="info"
            icon={<RefreshCw size={64} style={{ color: '#6366f1' }} />}
            title={<Title level={3} style={{ color: 'var(--text-primary)' }}>Processing Your Subscription</Title>}
            subTitle={
              <div style={{ color: 'var(--text-secondary)' }}>
                <Paragraph>
                  We're still processing your subscription. This usually takes a few moments.
                </Paragraph>
                <Paragraph>
                  Check count: {checkCount}/10
                </Paragraph>
                {checkCount >= 10 && (
                  <Paragraph style={{ color: '#f59e0b' }}>
                    Taking longer than expected? Please contact support if your subscription
                    doesn't appear within a few minutes.
                  </Paragraph>
                )}
              </div>
            }
            extra={[
              <Button
                key="refresh"
                type="primary"
                icon={<RefreshCw size={16} />}
                onClick={() => refetch()}
                loading={isLoading}
              >
                Check Again
              </Button>,
              <Button
                key="dashboard"
                onClick={() => router.navigate({ to: '/dashboard' })}
              >
                Back to Dashboard
              </Button>,
            ]}
          />
        )}
      </Card>
    </div>
  );
};

export default CheckoutSuccess;
