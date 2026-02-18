import { motion } from 'framer-motion';
import { Eye, Shield, Zap, Lock, Globe, Activity } from 'lucide-react';
import { Reveal, StaggerContainer, StaggerItem } from '../components/Reveal';

const features = [
  {
    icon: Eye,
    title: 'Complete Visibility',
    description: 'See every connection, process, and syscall in real-time with eBPF-powered monitoring that sees everything.',
  },
  {
    icon: Shield,
    title: 'Active Protection',
    description: 'Block threats at the kernel level before they reach userspace or cause any damage to your systems.',
  },
  {
    icon: Zap,
    title: 'Lightning Fast',
    description: 'Sub-50 microsecond overhead means zero impact on your application performance while staying protected.',
  },
  {
    icon: Lock,
    title: 'Zero Trust',
    description: 'Implement least-privilege access with granular control over every network flow and system call.',
  },
  {
    icon: Globe,
    title: 'Global Intelligence',
    description: 'Enrich traffic with GeoIP data and threat intelligence feeds updated in real-time.',
  },
  {
    icon: Activity,
    title: 'Smart Analytics',
    description: 'ML-powered anomaly detection identifies threats without waiting for signature updates.',
  },
];

const FeaturesSection = () => {
  return (
    <section id="features" className="section bg-section features-bg">
      {/* Background Overlay */}
      <div className="bg-overlay" />
      
      <div className="container bg-content">
        <div className="text-center max-w-2xl mx-auto mb-xl">
          <Reveal>
            <motion.span 
              className="badge badge-primary mb-md"
              whileHover={{ scale: 1.05 }}
              transition={{ type: 'spring', stiffness: 400 }}
            >
              <Eye size={14} />
              Features
            </motion.span>
          </Reveal>
          
          <Reveal delay={0.1}>
            <h2 className="heading-2 mb-md">
              Everything you need for{' '}
              <span className="text-gradient">kernel security</span>
            </h2>
          </Reveal>
          
          <Reveal delay={0.2}>
            <p className="text-body text-large">
              A complete security platform that gives you visibility, control, 
              and protection at the lowest level of your infrastructure.
            </p>
          </Reveal>
        </div>

        <StaggerContainer staggerDelay={0.1} className="grid-3">
          {features.map((feature, i) => (
            <StaggerItem key={i}>
              <motion.div 
                className="feature-card"
                whileHover={{ 
                  y: -10, 
                  boxShadow: '0 20px 60px rgba(0, 212, 255, 0.15)',
                  borderColor: 'rgba(0, 212, 255, 0.3)',
                }}
                transition={{ type: 'spring', stiffness: 300, damping: 20 }}
              >
                <motion.div 
                  className="feature-icon"
                  whileHover={{ 
                    rotate: [0, -10, 10, 0],
                    scale: 1.1,
                  }}
                  transition={{ duration: 0.5 }}
                >
                  <feature.icon size={22} />
                </motion.div>
                <h3 className="heading-3 mb-sm">{feature.title}</h3>
                <p className="text-body">{feature.description}</p>
              </motion.div>
            </StaggerItem>
          ))}
        </StaggerContainer>
      </div>
    </section>
  );
};

export default FeaturesSection;
