const Footer = () => {
  const currentYear = new Date().getFullYear();

  return (
    <footer className="footer">
      <div className="container">
        <div className="footer-grid">
          <div className="footer-brand">
            <div className="nav-logo" style={{ marginBottom: '1rem' }}>
              <img 
                src="/logo_kerneleye_dark.png" 
                alt="KernelEye" 
                style={{ height: 36, width: 'auto' }}
              />
            </div>
            <p className="text-body" style={{ fontSize: 'var(--text-sm)' }}>
              Real-time kernel security for Linux servers. See everything, block threats, sleep better.
            </p>
          </div>

          <div>
            <h4 className="footer-title">Product</h4>
            <ul className="footer-links">
              <li><a href="#features" className="footer-link">Features</a></li>
              <li><a href="#pricing" className="footer-link">Pricing</a></li>
              <li><a href="#" className="footer-link">Changelog</a></li>
              <li><a href="#" className="footer-link">Documentation</a></li>
            </ul>
          </div>

          <div>
            <h4 className="footer-title">Company</h4>
            <ul className="footer-links">
              <li><a href="#" className="footer-link">About</a></li>
              <li><a href="#" className="footer-link">Blog</a></li>
              <li><a href="#" className="footer-link">Careers</a></li>
              <li><a href="#contact" className="footer-link">Contact</a></li>
            </ul>
          </div>

          <div>
            <h4 className="footer-title">Legal</h4>
            <ul className="footer-links">
              <li><a href="#" className="footer-link">Privacy</a></li>
              <li><a href="#" className="footer-link">Terms</a></li>
              <li><a href="#" className="footer-link">Security</a></li>
              <li><a href="#" className="footer-link">Cookies</a></li>
            </ul>
          </div>
        </div>

        <div className="footer-bottom">
          <p className="text-small">© {currentYear} KernelEye. All rights reserved.</p>
          <div style={{ display: 'flex', gap: '1.5rem' }}>
            <a href="#" className="footer-link">Twitter</a>
            <a href="#" className="footer-link">GitHub</a>
            <a href="#" className="footer-link">LinkedIn</a>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
