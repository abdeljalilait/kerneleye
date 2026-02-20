import { motion } from 'framer-motion';
import { ArrowRight, Activity, Shield } from 'lucide-react';
import { GlowPulse } from '../components/Reveal';

const HeroSection = () => {
  // Animation variants
  const containerVariants = {
    hidden: {},
    visible: {
      transition: {
        staggerChildren: 0.1,
        delayChildren: 0.2,
      },
    },
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 30 },
    visible: {
      opacity: 1,
      y: 0,
      transition: {
        duration: 0.6,
        ease: [0.25, 0.46, 0.45, 0.94] as const,
      },
    },
  };

  return (
    <section className="hero">
      {/* Background Image */}
      <div className="hero-bg" />
      <motion.div 
        className="hero-overlay"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 1 }}
      />
      
      {/* Animated Glow Orbs */}
      <motion.div
        style={{
          position: 'absolute',
          width: '600px',
          height: '600px',
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(0, 212, 255, 0.12) 0%, transparent 70%)',
          top: '10%',
          right: '-10%',
          filter: 'blur(60px)',
          zIndex: 1,
        }}
        animate={{
          scale: [1, 1.15, 1],
          opacity: [0.4, 0.7, 0.4],
        }}
        transition={{
          duration: 10,
          repeat: Infinity,
          ease: 'easeInOut',
        }}
      />
      
      <div className="container">
        <div className="hero-grid">
          <motion.div 
            className="hero-content"
            variants={containerVariants}
            initial="hidden"
            animate="visible"
          >
            <motion.div variants={itemVariants}>
              <div className="hero-badge">
                <Activity size={14} />
                <span>Real-time Monitoring</span>
              </div>
            </motion.div>
            
            <motion.h1 
              className="heading-1 hero-title"
              variants={itemVariants}
            >
              See the threat.
              <br />
              <span className="text-gradient text-glow">Block it instantly.</span>
            </motion.h1>
            
            <motion.p 
              className="hero-description"
              variants={itemVariants}
            >
              Kernel-level visibility and protection for Linux servers. 
              eBPF-powered monitoring with sub-50µs overhead.
            </motion.p>
            
            <motion.div 
              className="hero-actions"
              variants={itemVariants}
            >
              <GlowPulse color="primary">
                <motion.a 
                  href="https://app.kerneleye.cloud" 
                  className="btn btn-primary"
                  whileHover={{ scale: 1.03 }}
                  whileTap={{ scale: 0.98 }}
                >
                  Get started free
                  <ArrowRight size={18} />
                </motion.a>
              </GlowPulse>
              <motion.a 
                href="#pricing" 
                className="btn btn-secondary"
                whileHover={{ scale: 1.03 }}
                whileTap={{ scale: 0.98 }}
              >
                View pricing
              </motion.a>
            </motion.div>

            <motion.p 
              className="text-small" 
              style={{ marginTop: '1rem', color: 'var(--color-text-muted)' }}
              variants={itemVariants}
            >
              Free signup with GitHub or Google. No credit card required.
            </motion.p>


          </motion.div>

          {/* Dashboard Preview - Simplified Animation */}
          <motion.div 
            className="hero-visual"
            initial={{ opacity: 0, x: 40 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ 
              delay: 0.4, 
              duration: 0.8, 
              ease: [0.25, 0.46, 0.45, 0.94] as const 
            }}
          >
            <motion.div 
              className="hero-card"
              animate={{ 
                y: [0, -8, 0],
              }}
              transition={{
                duration: 5,
                repeat: Infinity,
                ease: 'easeInOut',
              }}
            >
              {/* Header */}
              <div style={{ 
                display: 'flex', 
                alignItems: 'center', 
                justifyContent: 'space-between',
                marginBottom: '1.25rem',
                paddingBottom: '1rem',
                borderBottom: '1px solid var(--color-border)'
              }}>
                <div>
                  <div className="text-small" style={{ marginBottom: '0.25rem' }}>Active Threats Blocked</div>
                  <motion.div 
                    style={{ fontSize: '1.75rem', fontWeight: 800, color: 'var(--color-accent)' }}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 0.8, duration: 0.5 }}
                  >
                    2,847
                  </motion.div>
                </div>
                <motion.div 
                  style={{
                    width: '48px',
                    height: '48px',
                    borderRadius: '50%',
                    background: 'linear-gradient(135deg, rgba(255, 56, 100, 0.2) 0%, rgba(255, 56, 100, 0.1) 100%)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: 'var(--color-accent)',
                    border: '1px solid rgba(255, 56, 100, 0.3)',
                  }}
                  animate={{
                    boxShadow: [
                      '0 0 0 0 rgba(255, 56, 100, 0.4)',
                      '0 0 0 12px rgba(255, 56, 100, 0)',
                    ],
                  }}
                  transition={{
                    duration: 2,
                    repeat: Infinity,
                    ease: 'easeOut',
                  }}
                >
                  <Shield size={24} />
                </motion.div>
              </div>

              {/* Activity List */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.625rem' }}>
                {[
                  { ip: '192.168.1.45', port: '443', status: 'BLOCKED', time: '2s ago', color: '#ff3864' },
                  { ip: '10.0.0.23', port: '22', status: 'BLOCKED', time: '5s ago', color: '#ff3864' },
                  { ip: '172.16.0.5', port: '8080', status: 'ALLOWED', time: '12s ago', color: '#00d9a3' },
                  { ip: '192.168.2.12', port: '3389', status: 'ALERT', time: '18s ago', color: '#ffb800' },
                ].map((item, i) => (
                  <motion.div 
                    key={i} 
                    style={{ 
                      display: 'flex', 
                      alignItems: 'center', 
                      gap: '0.75rem',
                      padding: '0.625rem',
                      background: 'rgba(255,255,255,0.02)',
                      borderRadius: 'var(--radius-md)',
                    }}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.9 + i * 0.08, duration: 0.3 }}
                    whileHover={{ 
                      background: 'rgba(255,255,255,0.05)',
                      transition: { duration: 0.15 }
                    }}
                  >
                    <span className="text-small" style={{ width: '90px', fontFamily: 'monospace', color: 'var(--color-text-secondary)' }}>
                      {item.ip}
                    </span>
                    <span className="text-small" style={{ width: '45px', color: 'var(--color-text-muted)' }}>
                      :{item.port}
                    </span>
                    <span 
                      className="text-small" 
                      style={{ 
                        flex: 1,
                        fontWeight: 600,
                        color: item.color,
                        textAlign: 'right'
                      }}
                    >
                      {item.status}
                    </span>
                    <span className="text-small" style={{ width: '50px', textAlign: 'right', color: 'var(--color-text-muted)' }}>
                      {item.time}
                    </span>
                  </motion.div>
                ))}
              </div>

              {/* Stats */}
              <div 
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(3, 1fr)',
                  gap: '0.75rem',
                  marginTop: '1.25rem',
                  paddingTop: '1.25rem',
                  borderTop: '1px solid var(--color-border)',
                }}
              >
                {[
                  { value: '99.9%', label: 'Uptime' },
                  { value: '<50µs', label: 'Latency' },
                  { value: '24/7', label: 'Monitoring' },
                ].map((stat, i) => (
                  <motion.div 
                    key={i} 
                    className="text-center"
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 1.3 + i * 0.1, duration: 0.3 }}
                  >
                    <div className="stat-value">{stat.value}</div>
                    <div className="stat-label">{stat.label}</div>
                  </motion.div>
                ))}
              </div>
            </motion.div>
          </motion.div>
        </div>
      </div>
    </section>
  );
};

export default HeroSection;
