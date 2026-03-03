import { motion } from 'framer-motion';
import { ArrowRight, Activity } from 'lucide-react';
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
                  href="https://app.kerneleye.net" 
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

          </motion.div>


        </div>
      </div>
    </section>
  );
};

export default HeroSection;
