import { useEffect, useState } from 'react';
import { Button, Modal, Spin, Typography } from 'antd';
import { PolarEmbedCheckout } from '@polar-sh/checkout/embed';
import { CreditCard, CheckCircle } from 'lucide-react';

const { Text, Title } = Typography;

interface EmbeddedCheckoutProps {
  checkoutUrl: string;
  planName: string;
  isOpen: boolean;
  onClose: () => void;
  onSuccess?: () => void;
}

export default function EmbeddedCheckout({
  checkoutUrl,
  planName,
  isOpen,
  onClose,
  onSuccess,
}: EmbeddedCheckoutProps) {
  const [checkoutInstance, setCheckoutInstance] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState<'loading' | 'ready' | 'success'>('loading');

  useEffect(() => {
    if (isOpen && checkoutUrl) {
      setLoading(true);
      setStatus('loading');
      
      // Small delay to ensure modal is rendered
      setTimeout(() => {
        openEmbeddedCheckout();
      }, 100);
    }

    return () => {
      if (checkoutInstance) {
        checkoutInstance.close();
      }
    };
  }, [isOpen, checkoutUrl]);

  const openEmbeddedCheckout = async () => {
    try {
      const checkout = await PolarEmbedCheckout.create(checkoutUrl, {
        theme: 'dark',
        onLoaded: () => {
          console.log('[Polar] Checkout loaded');
          setLoading(false);
          setStatus('ready');
        },
      });

      setCheckoutInstance(checkout);

      // Listen for success
      checkout.addEventListener('success', (event: any) => {
        console.log('[Polar] Checkout success', event.detail);
        setStatus('success');
        
        // Call success callback after a short delay to show success state
        setTimeout(() => {
          if (onSuccess) onSuccess();
        }, 2000);
      });

      // Listen for close
      checkout.addEventListener('close', () => {
        console.log('[Polar] Checkout closed');
        onClose();
      });

      // Listen for confirmed (payment processing)
      checkout.addEventListener('confirmed', () => {
        console.log('[Polar] Order confirmed, processing payment');
      });
    } catch (error) {
      console.error('[Polar] Failed to open checkout', error);
      setLoading(false);
      // Fall back to redirect
      window.location.href = checkoutUrl;
    }
  };

  const handleClose = () => {
    if (checkoutInstance) {
      checkoutInstance.close();
    }
    onClose();
  };

  return (
    <Modal
      open={isOpen}
      onCancel={handleClose}
      footer={null}
      width={600}
      closable={status !== 'success'}
      maskClosable={status !== 'success'}
      styles={{
        body: { 
          padding: 0, 
          height: status === 'success' ? 'auto' : '600px',
          minHeight: status === 'success' ? '200px' : '600px',
        },
        mask: { backdropFilter: 'blur(4px)' },
      }}
      style={{
        borderRadius: '16px',
        overflow: 'hidden',
      }}
    >
      {status === 'success' ? (
        <div style={{ 
          padding: 48, 
          textAlign: 'center',
          background: 'linear-gradient(135deg, rgba(16, 185, 129, 0.1), rgba(16, 185, 129, 0.05))',
        }}>
          <div style={{
            width: 80,
            height: 80,
            borderRadius: '50%',
            background: 'linear-gradient(135deg, #10b981, #059669)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 24px',
            boxShadow: '0 8px 30px rgba(16, 185, 129, 0.3)',
          }}>
            <CheckCircle size={40} color="white" />
          </div>
          <Title level={3} style={{ margin: 0, marginBottom: 8, color: 'var(--text-primary)' }}>
            Payment Successful!
          </Title>
          <Text style={{ color: 'var(--text-secondary)', fontSize: 16 }}>
            Your {planName} subscription is now active.
          </Text>
          <Text style={{ color: 'var(--text-tertiary)', fontSize: 14, display: 'block', marginTop: 8 }}>
            Redirecting to dashboard...
          </Text>
        </div>
      ) : (
        <div style={{ position: 'relative', width: '100%', height: '100%' }}>
          {loading && (
            <div style={{
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              background: 'var(--bg-card)',
              zIndex: 10,
            }}>
              <Spin size="large" />
              <Text style={{ marginTop: 16, color: 'var(--text-secondary)' }}>
                Loading checkout...
              </Text>
            </div>
          )}
          {/* The embedded checkout will be injected here by Polar */}
        </div>
      )}
    </Modal>
  );
}
