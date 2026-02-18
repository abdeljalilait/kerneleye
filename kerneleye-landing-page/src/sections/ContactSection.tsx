import { motion } from 'framer-motion';
import { Mail, MapPin, Phone, Send } from 'lucide-react';
import { Reveal } from '../components/Reveal';

const contactInfo = [
  { icon: Mail, label: 'Email', value: 'hello@kerneleye.io' },
  { icon: Phone, label: 'Phone', value: '+1 (555) 123-4567' },
  { icon: MapPin, label: 'Office', value: 'San Francisco, CA' },
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
        <div className="grid-2" style={{ alignItems: 'center', gap: '3rem' }}>
          <div>
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

          <Reveal direction="scale" delay={0.3}>
            <motion.div 
              className="card-glass" 
              style={{ padding: '2rem' }}
              whileHover={{ 
                boxShadow: '0 20px 60px rgba(0, 212, 255, 0.1)',
              }}
              transition={{ duration: 0.3 }}
            >
              <h3 className="heading-3 mb-lg">Get started</h3>
              <form style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                {[
                  { label: 'Full name', type: 'text', placeholder: 'John Doe' },
                  { label: 'Work email', type: 'email', placeholder: 'john@company.com' },
                  { label: 'Company', type: 'text', placeholder: 'Acme Inc.' },
                ].map((field, i) => (
                  <motion.div
                    key={i}
                    initial={{ opacity: 0, x: 20 }}
                    whileInView={{ opacity: 1, x: 0 }}
                    viewport={{ once: true }}
                    transition={{ delay: 0.4 + i * 0.1 }}
                  >
                    <label 
                      className="text-small" 
                      style={{ display: 'block', marginBottom: '0.375rem', fontWeight: 500 }}
                    >
                      {field.label}
                    </label>
                    <motion.input
                      type={field.type}
                      placeholder={field.placeholder}
                      style={{
                        width: '100%',
                        padding: '0.75rem 1rem',
                        borderRadius: 'var(--radius-lg)',
                        border: '1px solid var(--color-border)',
                        fontSize: '16px',
                        fontFamily: 'inherit',
                        minHeight: '44px',
                        background: 'var(--color-bg-elevated)',
                        color: 'var(--color-text)',
                        outline: 'none',
                      }}
                      whileFocus={{ 
                        borderColor: '#00d4ff',
                        boxShadow: '0 0 0 3px rgba(0, 212, 255, 0.1)',
                      }}
                      transition={{ duration: 0.2 }}
                    />
                  </motion.div>
                ))}

                <motion.div
                  initial={{ opacity: 0, x: 20 }}
                  whileInView={{ opacity: 1, x: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: 0.7 }}
                >
                  <label 
                    className="text-small" 
                    style={{ display: 'block', marginBottom: '0.375rem', fontWeight: 500 }}
                  >
                    Message
                  </label>
                  <motion.textarea
                    rows={3}
                    placeholder="Tell us about your infrastructure..."
                    style={{
                      width: '100%',
                      padding: '0.75rem 1rem',
                      borderRadius: 'var(--radius-lg)',
                      border: '1px solid var(--color-border)',
                      fontSize: '16px',
                      fontFamily: 'inherit',
                      resize: 'vertical',
                      minHeight: '100px',
                      background: 'var(--color-bg-elevated)',
                      color: 'var(--color-text)',
                      outline: 'none',
                    }}
                    whileFocus={{ 
                      borderColor: '#00d4ff',
                      boxShadow: '0 0 0 3px rgba(0, 212, 255, 0.1)',
                    }}
                    transition={{ duration: 0.2 }}
                  />
                </motion.div>

                <motion.button 
                  type="submit" 
                  className="btn btn-primary" 
                  style={{ width: '100%', marginTop: '0.5rem' }}
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: 0.8 }}
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                >
                  <motion.span
                    animate={{ x: [0, 5, 0] }}
                    transition={{ duration: 1.5, repeat: Infinity }}
                    style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem' }}
                  >
                    <Send size={18} />
                    Send message
                  </motion.span>
                </motion.button>
              </form>
            </motion.div>
          </Reveal>
        </div>
      </div>
    </section>
  );
};

export default ContactSection;
