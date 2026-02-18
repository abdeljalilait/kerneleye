import { motion } from 'framer-motion';
import { Eye, BarChart3, Shield, ChevronRight } from 'lucide-react';
import { Reveal } from '../components/Reveal';

const steps = [
  {
    number: '01',
    icon: Eye,
    title: 'Observe',
    description: 'eBPF probes capture system calls, network flows, and process events with zero overhead.',
    color: 'linear-gradient(135deg, #00d4ff 0%, #0099cc 100%)',
    glowColor: 'rgba(0, 212, 255, 0.3)',
  },
  {
    number: '02',
    icon: BarChart3,
    title: 'Analyze',
    description: 'Real-time scoring with threat intelligence, GeoIP, and behavioral analytics.',
    color: 'linear-gradient(135deg, #ff3864 0%, #ff6b8a 100%)',
    glowColor: 'rgba(255, 56, 100, 0.3)',
  },
  {
    number: '03',
    icon: Shield,
    title: 'Protect',
    description: 'XDP blocks malicious traffic at the earliest point—before it reaches your application.',
    color: 'linear-gradient(135deg, #00d9a3 0%, #00b386 100%)',
    glowColor: 'rgba(0, 217, 163, 0.3)',
  },
];

const HowItWorksSection = () => {
  return (
    <section id="how-it-works" className="section bg-section how-it-works-bg">
      {/* Background Overlay */}
      <div className="bg-overlay" />
      
      <div className="container bg-content">
        <div className="grid-2" style={{ alignItems: 'center', gap: '4rem' }}>
          <div>
            <Reveal>
              <span className="badge badge-primary mb-md">How it works</span>
            </Reveal>
            
            <Reveal delay={0.1}>
              <h2 className="heading-2 mb-md">
                Three steps to{' '}
                <span className="text-gradient">complete security</span>
              </h2>
            </Reveal>
            
            <Reveal delay={0.2}>
              <p className="text-body text-large mb-lg">
                KernelEye deploys in minutes and starts protecting your infrastructure 
                immediately. No agents to manage, no configuration files to edit.
              </p>
            </Reveal>
            
            <Reveal delay={0.3}>
              <motion.a 
                href="#contact" 
                className="btn btn-primary"
                whileHover={{ scale: 1.03 }}
                whileTap={{ scale: 0.98 }}
              >
                Get started
                <ChevronRight size={18} />
              </motion.a>
            </Reveal>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {steps.map((step, i) => (
              <motion.div 
                key={i}
                initial={{ opacity: 0, x: 30 }}
                whileInView={{ opacity: 1, x: 0 }}
                viewport={{ once: true, margin: '-50px' }}
                transition={{ 
                  delay: i * 0.15, 
                  duration: 0.5,
                  ease: [0.25, 0.46, 0.45, 0.94] as const
                }}
              >
                <motion.div 
                  className="card-glass"
                  style={{
                    display: 'flex',
                    gap: '1.25rem',
                    padding: '1.5rem',
                  }}
                  whileHover={{ 
                    scale: 1.02,
                    x: 8,
                    boxShadow: `0 10px 40px ${step.glowColor}`,
                  }}
                  transition={{ type: 'spring', stiffness: 400, damping: 25 }}
                >
                  <motion.div 
                    style={{
                      width: '3.5rem',
                      height: '3.5rem',
                      minWidth: '3.5rem',
                      borderRadius: 'var(--radius-lg)',
                      background: step.color,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      color: 'white',
                      boxShadow: `0 8px 24px ${step.glowColor}`,
                    }}
                    whileHover={{ rotate: 360 }}
                    transition={{ duration: 0.6, ease: 'easeInOut' }}
                  >
                    <step.icon size={22} />
                  </motion.div>
                  <div style={{ minWidth: 0 }}>
                    <span 
                      style={{
                        fontSize: 'var(--text-xs)',
                        fontWeight: 700,
                        color: 'var(--color-text-muted)',
                        textTransform: 'uppercase',
                        letterSpacing: '0.08em',
                      }}
                    >
                      Step {step.number}
                    </span>
                    <h3 className="heading-3 mt-sm" style={{ fontSize: 'var(--text-xl)' }}>
                      {step.title}
                    </h3>
                    <p className="text-body mt-sm">{step.description}</p>
                  </div>
                </motion.div>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
};

export default HowItWorksSection;
