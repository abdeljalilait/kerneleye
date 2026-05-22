import { motion } from 'framer-motion';
import { Mail } from 'lucide-react';
import { Reveal } from '../components/Reveal';

const contactInfo = [
  { icon: Mail, label: 'Email', value: 'contact@kerneleye.net' },
];

const ContactSection = () => {
  const containerVariants = {
    hidden: {},
    visible: {
      transition: {
        staggerChildren: 0.15,
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
        ease: [0.16, 1, 0.3, 1] as const,
      },
    },
  };

  return (
    <section id="contact" className="section bg-section contact-bg">
      {/* Background Overlay */}
      <div className="bg-overlay" />
      
      <div className="container bg-content">
        <div style={{ maxWidth: '600px', margin: '0 auto' }}>
          <Reveal>
            <span className="badge badge-primary mb-md">Contact</span>
          </Reveal>
          
          <Reveal delay={0.1}>
            <h2 className="heading-2 mb-md">
              Ready to secure your{' '}
              <span className="text-gradient">infrastructure?</span>
            </h2>
          </Reveal>
          
          <Reveal delay={0.2}>
            <p className="text-body text-large mb-lg">
              Get in touch with our team to learn more about KernelEye 
              or schedule a personalized demo.
            </p>
          </Reveal>

          <motion.div 
            style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}
            variants={containerVariants}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true, margin: '-50px' }}
          >
            {contactInfo.map((item, i) => (
              <motion.div 
                key={i}
                style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}
                variants={itemVariants}
                whileHover={{ x: 10 }}
                transition={{ type: 'spring', stiffness: 300 }}
              >
                <motion.div 
                  style={{
                    width: '3rem',
                    height: '3rem',
                    borderRadius: 'var(--radius-lg)',
                    background: 'linear-gradient(135deg, rgba(0, 212, 255, 0.1) 0%, rgba(0, 212, 255, 0.05) 100%)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: 'var(--color-primary)',
                    border: '1px solid rgba(0, 212, 255, 0.15)',
                  }}
                  whileHover={{ 
                    scale: 1.1,
                    rotate: 10,
                    boxShadow: '0 0 20px rgba(0, 212, 255, 0.3)',
                  }}
                  transition={{ type: 'spring', stiffness: 400 }}
                >
                  <item.icon size={20} />
                </motion.div>
                <div>
                  <div className="text-small">{item.label}</div>
                  <div style={{ fontWeight: 500, color: 'var(--color-text)' }}>{item.value}</div>
                </div>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </div>
    </section>
  );
};

export default ContactSection;
