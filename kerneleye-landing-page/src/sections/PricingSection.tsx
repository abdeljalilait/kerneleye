import { useState } from 'react';
import { motion } from 'framer-motion';
import { Check, Loader2 } from 'lucide-react';
import { Reveal } from '../components/Reveal';

interface Plan {
  name: string;
  description: string;
  price: string;
  period: string;
  features: string[];
  cta: string;
  featured: boolean;
  polarPriceId?: string;
}

const plans: Plan[] = [
  {
    name: 'Starter',
    description: 'For small teams getting started',
    price: '$49',
    period: '/month',
    features: [
      'Up to 10 servers',
      'Real-time monitoring',
      'Email alerts',
      '7-day data retention',
      'Community support',
    ],
    cta: 'Start free trial',
    featured: false,
    polarPriceId: 'price_starter', // Replace with actual Polar price ID
  },
  {
    name: 'Professional',
    description: 'For growing security teams',
    price: '$149',
    period: '/month',
    features: [
      'Up to 50 servers',
      'Advanced threat detection',
      'Slack/PagerDuty alerts',
      '90-day data retention',
      'Priority support',
      'API access',
      'Custom rules',
    ],
    cta: 'Start free trial',
    featured: true,
    polarPriceId: 'price_pro', // Replace with actual Polar price ID
  },
  {
    name: 'Enterprise',
    description: 'For large organizations',
    price: 'Custom',
    period: '',
    features: [
      'Unlimited servers',
      'ML-powered analytics',
      '24/7 phone support',
      '1-year data retention',
      'Dedicated engineer',
      'SSO & audit logs',
      'Custom integrations',
      'SLA guarantee',
    ],
    cta: 'Contact sales',
    featured: false,
  },
];

// Polar checkout configuration
const POLAR_CHECKOUT_URL = 'https://polar.sh/checkout/';
const POLAR_ORG = 'kerneleye'; // Your Polar organization slug

const PricingSection = () => {
  const [loadingPlan, setLoadingPlan] = useState<string | null>(null);

  const handleCheckout = async (plan: Plan) => {
    if (plan.name === 'Enterprise') {
      // Scroll to contact section for enterprise
      document.getElementById('contact')?.scrollIntoView({ behavior: 'smooth' });
      return;
    }

    if (!plan.polarPriceId) {
      console.error('No price ID configured for plan:', plan.name);
      return;
    }

    setLoadingPlan(plan.name);

    try {
      // Call backend to create checkout session
      const response = await fetch('/api/v1/subscription/checkout', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          plan_name: plan.name.toLowerCase(),
          price_id: plan.polarPriceId,
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to create checkout session');
      }

      const data = await response.json();

      // Redirect to Polar checkout
      if (data.checkout_url) {
        window.location.href = data.checkout_url;
      } else {
        // Fallback to direct Polar checkout
        const checkoutUrl = `${POLAR_CHECKOUT_URL}${plan.polarPriceId}?organization=${POLAR_ORG}`;
        window.location.href = checkoutUrl;
      }
    } catch (error) {
      console.error('Checkout error:', error);
      // Fallback to direct Polar checkout on error
      const checkoutUrl = `${POLAR_CHECKOUT_URL}${plan.polarPriceId}?organization=${POLAR_ORG}`;
      window.location.href = checkoutUrl;
    } finally {
      setLoadingPlan(null);
    }
  };

  return (
    <section id="pricing" className="section bg-section pricing-bg">
      {/* Background Overlay */}
      <div className="bg-overlay-light" />
      
      <div className="container bg-content">
        <div className="text-center max-w-2xl mx-auto mb-xl">
          <Reveal>
            <span className="badge badge-primary mb-md">Pricing</span>
          </Reveal>
          <Reveal delay={0.1}>
            <h2 className="heading-2 mb-md">
              Simple, <span className="text-gradient">transparent</span> pricing
            </h2>
          </Reveal>
          <Reveal delay={0.2}>
            <p className="text-body text-large">
              Start free for 14 days. No credit card required.
            </p>
          </Reveal>
        </div>

        <div className="grid-3">
          {plans.map((plan, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: '-50px' }}
              transition={{ 
                delay: i * 0.1, 
                duration: 0.5,
                ease: [0.25, 0.46, 0.45, 0.94] as const
              }}
            >
              <motion.div 
                className={plan.featured ? 'pricing-card pricing-card-featured' : 'pricing-card'}
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  height: '100%',
                }}
                whileHover={{ 
                  y: plan.featured ? -12 : -8,
                }}
                transition={{ type: 'spring', stiffness: 300, damping: 20 }}
              >
                <div>
                  <h3 className="heading-3">{plan.name}</h3>
                  <p className="text-body mt-sm" style={{ fontSize: 'var(--text-sm)' }}>{plan.description}</p>
                  
                  <motion.div 
                    style={{ margin: '1.5rem 0' }}
                    initial={{ opacity: 0, scale: 0.9 }}
                    whileInView={{ opacity: 1, scale: 1 }}
                    viewport={{ once: true }}
                    transition={{ delay: 0.3 + i * 0.1, duration: 0.4 }}
                  >
                    <span className="pricing-price">{plan.price}</span>
                    <span className="pricing-period">{plan.period}</span>
                  </motion.div>
                </div>

                <ul 
                  style={{
                    listStyle: 'none',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.75rem',
                    marginBottom: '2rem',
                    flex: 1,
                  }}
                >
                  {plan.features.map((feature, j) => (
                    <motion.li 
                      key={j} 
                      style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}
                      initial={{ opacity: 0, x: -10 }}
                      whileInView={{ opacity: 1, x: 0 }}
                      viewport={{ once: true }}
                      transition={{ delay: 0.4 + j * 0.05 }}
                    >
                      <div 
                        style={{
                          width: '20px',
                          height: '20px',
                          borderRadius: '50%',
                          background: plan.featured ? 'rgba(0, 212, 255, 0.1)' : 'var(--color-bg-elevated)',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          border: plan.featured ? '1px solid rgba(0, 212, 255, 0.3)' : '1px solid var(--color-border)',
                        }}
                      >
                        <Check size={12} style={{ color: plan.featured ? 'var(--color-primary)' : 'var(--color-text-secondary)' }} />
                      </div>
                      <span className="text-body" style={{ fontSize: 'var(--text-sm)' }}>{feature}</span>
                    </motion.li>
                  ))}
                </ul>

                <motion.button
                  onClick={() => handleCheckout(plan)}
                  disabled={loadingPlan === plan.name}
                  className={plan.featured ? 'btn btn-primary' : 'btn btn-outline'}
                  style={{ 
                    width: '100%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '0.5rem',
                  }}
                  whileHover={{ scale: 1.03 }}
                  whileTap={{ scale: 0.98 }}
                >
                  {loadingPlan === plan.name ? (
                    <>
                      <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} />
                      Loading...
                    </>
                  ) : (
                    plan.cta
                  )}
                </motion.button>
              </motion.div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default PricingSection;
