import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Menu, X } from 'lucide-react';
import { Link } from 'react-router-dom';

interface NavigationProps {
  onHomeClick?: () => void;
}

const Navigation = ({ onHomeClick }: NavigationProps) => {
  const [isScrolled, setIsScrolled] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 50);
    };
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const navLinks = [
    { label: 'Features', href: '#features' },
    { label: 'How it works', href: '#how-it-works' },
    { label: 'Pricing', href: '#pricing' },
    { label: 'Contact', href: '#contact' },
  ];

  return (
    <>
      <motion.nav 
        className="nav"
        style={{
          background: isScrolled ? 'rgba(10, 12, 16, 0.95)' : 'rgba(10, 12, 16, 0.8)',
          borderBottomColor: isScrolled ? 'var(--color-border)' : 'transparent',
        }}
        initial={{ y: -100 }}
        animate={{ y: 0 }}
        transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
      >
        <div className="container nav-container">
          <motion.button 
            onClick={onHomeClick} 
            className="nav-logo"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
          >
            <Link to="/">
              <img 
                src="/logo_kerneleye_dark.png" 
                alt="KernelEye" 
                style={{ height: 48, width: 'auto' }}
              />
            </Link>
          </motion.button>

          <div className="nav-links">
            {navLinks.map((link, i) => (
              <motion.a 
                key={link.label} 
                href={link.href} 
                className="nav-link"
                initial={{ opacity: 0, y: -20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1 + i * 0.1 }}
                whileHover={{ 
                  color: '#00d4ff',
                  y: -2,
                }}
              >
                {link.label}
              </motion.a>
            ))}
          </div>

          <motion.button 
            className="mobile-menu-btn"
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
            whileHover={{ scale: 1.1 }}
            whileTap={{ scale: 0.9 }}
          >
            <AnimatePresence mode="wait">
              {isMobileMenuOpen ? (
                <motion.div
                  key="close"
                  initial={{ rotate: -90, opacity: 0 }}
                  animate={{ rotate: 0, opacity: 1 }}
                  exit={{ rotate: 90, opacity: 0 }}
                  transition={{ duration: 0.2 }}
                >
                  <X size={24} />
                </motion.div>
              ) : (
                <motion.div
                  key="menu"
                  initial={{ rotate: 90, opacity: 0 }}
                  animate={{ rotate: 0, opacity: 1 }}
                  exit={{ rotate: -90, opacity: 0 }}
                  transition={{ duration: 0.2 }}
                >
                  <Menu size={24} />
                </motion.div>
              )}
            </AnimatePresence>
          </motion.button>
        </div>
      </motion.nav>

      {/* Mobile Menu */}
      <AnimatePresence>
        {isMobileMenuOpen && (
          <motion.div 
            style={{
              position: 'fixed',
              inset: 0,
              top: '3.5rem',
              background: 'var(--color-bg)',
              zIndex: 999,
              padding: '1.5rem',
              overflowY: 'auto',
              borderTop: '1px solid var(--color-border)',
            }}
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.3 }}
          >
            <motion.div 
              style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}
              initial="hidden"
              animate="visible"
              variants={{
                hidden: {},
                visible: {
                  transition: {
                    staggerChildren: 0.1,
                  },
                },
              }}
            >
              {navLinks.map((link) => (
                <motion.a
                  key={link.label}
                  href={link.href}
                  onClick={() => setIsMobileMenuOpen(false)}
                  style={{
                    padding: '1rem',
                    fontSize: 'var(--text-lg)',
                    fontWeight: 500,
                    borderRadius: 'var(--radius-lg)',
                    color: 'var(--color-text)',
                  }}
                  variants={{
                    hidden: { opacity: 0, x: -20 },
                    visible: { opacity: 1, x: 0 },
                  }}
                  whileHover={{ 
                    background: 'var(--color-bg-elevated)',
                    color: '#00d4ff',
                    x: 10,
                  }}
                  transition={{ type: 'spring', stiffness: 300 }}
                >
                  {link.label}
                </motion.a>
              ))}
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
};

export default Navigation;
