import { useState } from 'react';
import { motion } from 'framer-motion';
import { Check, Loader2, ArrowRight } from 'lucide-react';
import { Reveal } from '../components/Reveal';

interface Plan {
  name: string;
  description: string;
  price: string;
  period: string;
  features: string[];
  cta: string;
  featured: boolean;
  planName: string;
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
    cta: 'Get started',
    featured: false,
    planName: 'starter',
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
    cta: 'Get started',
    featured: true,
    planName: 'pro',
  },
];

// Dashboard URL - update this to your actual dashboard URL
const DASHBOARD_URL = import.meta.env.VITE_DASHBOARD_URL || 'https://app.kerneleye.net';

const PricingSection = () => {
  const [loadingPlan, setLoadingPlan] = useState<string | null>(null);

  const handleCheckout = async (plan: Plan) => {
    setLoadingPlan(plan.name);

    // Redirect to dashboard for authenticated checkout
    // The dashboard will handle login and then proceed to checkout
    const checkoutUrl = `${DASHBOARD_URL}/subscription/checkout?plan=${plan.planName}`;
    
    // Small delay to show loading state
    setTimeout(() => {
      window.location.href = checkoutUrl;
    }, 300);
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
              Sign up free with GitHub or Google. Start monitoring in minutes.
            </p>
          </Reveal>
        </div>

        <div className="grid-2" style={{ maxWidth: '800px', margin: '0 auto' }}>
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
                    <>
                      {plan.cta}
                      <ArrowRight size={16} />
                    </>
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
