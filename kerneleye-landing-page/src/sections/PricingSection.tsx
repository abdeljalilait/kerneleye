import { motion } from 'framer-motion';
import { Check, ExternalLink } from 'lucide-react';
import { Reveal } from '../components/Reveal';

const DASHBOARD_URL = import.meta.env.VITE_DASHBOARD_URL || 'https://app.kerneleye.net';

const features = [
  'Unlimited monitored servers',
  'Real-time eBPF monitoring',
  'Threat detection and alerts',
  'XDP and ipset remediation',
  'Reports, analytics, and live traffic views',
  'Run on your own infrastructure',
];

const PricingSection = () => {
  return (
    <section id="pricing" className="section bg-section pricing-bg">
      <div className="bg-overlay-light" />

      <div className="container bg-content">
        <div className="text-center max-w-2xl mx-auto mb-xl">
          <Reveal>
            <span className="badge badge-primary mb-md">Self-hosted</span>
          </Reveal>
          <Reveal delay={0.1}>
            <h2 className="heading-2 mb-md">
              Free to run on <span className="text-gradient">your infrastructure</span>
            </h2>
          </Reveal>
        </div>

        <div style={{ maxWidth: '520px', margin: '0 auto' }}>
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: '-50px' }}
            transition={{ duration: 0.5, ease: [0.25, 0.46, 0.45, 0.94] as const }}
          >
            <motion.div
              className="pricing-card pricing-card-featured"
              style={{ display: 'flex', flexDirection: 'column', height: '100%' }}
              whileHover={{ y: -10 }}
              transition={{ type: 'spring', stiffness: 300, damping: 20 }}
            >
              <div>
                <h3 className="heading-3">Self-hosted</h3>
                <p className="text-body mt-sm" style={{ fontSize: 'var(--text-sm)' }}>
                  Full KernelEye monitoring for teams that operate their own stack.
                </p>

                <motion.div
                  style={{ margin: '1.5rem 0' }}
                  initial={{ opacity: 0, scale: 0.9 }}
                  whileInView={{ opacity: 1, scale: 1 }}
                  viewport={{ once: true }}
                  transition={{ delay: 0.2, duration: 0.4 }}
                >
                  <span className="pricing-price">$0</span>
                  <span className="pricing-period"> forever</span>
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
                {features.map((feature, index) => (
                  <motion.li
                    key={feature}
                    style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}
                    initial={{ opacity: 0, x: -10 }}
                    whileInView={{ opacity: 1, x: 0 }}
                    viewport={{ once: true }}
                    transition={{ delay: 0.25 + index * 0.05 }}
                  >
                    <div
                      style={{
                        width: '20px',
                        height: '20px',
                        borderRadius: '50%',
                        background: 'rgba(0, 212, 255, 0.1)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        border: '1px solid rgba(0, 212, 255, 0.3)',
                      }}
                    >
                      <Check size={12} style={{ color: 'var(--color-primary)' }} />
                    </div>
                    <span className="text-body" style={{ fontSize: 'var(--text-sm)' }}>{feature}</span>
                  </motion.li>
                ))}
              </ul>

              <motion.a
                href={DASHBOARD_URL}
                className="btn btn-primary"
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
                Open dashboard
                <ExternalLink size={16} />
              </motion.a>
            </motion.div>
          </motion.div>
        </div>
      </div>
    </section>
  );
};

export default PricingSection;
