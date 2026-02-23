const Terms = () => {
  return (
    <div style={{ minHeight: '100vh', padding: '6rem 2rem 4rem', background: 'var(--color-bg)' }}>
      <div style={{ maxWidth: 800, margin: '0 auto' }}>
        <h1 style={{ fontSize: '2.5rem', fontWeight: 700, marginBottom: '1rem', color: 'var(--color-text)' }}>
          Terms of Service
        </h1>
        <p style={{ color: 'var(--color-text-muted)', marginBottom: '3rem' }}>
          Last updated: February 2026
        </p>

        <div style={{ color: 'var(--color-text-secondary)', lineHeight: 1.8, display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <section>
            <h2 style={{ fontSize: '1.5rem', fontWeight: 600, marginBottom: '1rem', color: 'var(--color-text)' }}>
              1. Acceptance of Terms
            </h2>
            <p>
              By accessing and using KernelEye, you accept and agree to be bound by the terms and provision of this agreement. If you do not agree to abide by these terms, please do not use this service.
            </p>
          </section>

          <section>
            <h2 style={{ fontSize: '1.5rem', fontWeight: 600, marginBottom: '1rem', color: 'var(--color-text)' }}>
              2. Description of Service
            </h2>
            <p>
              KernelEye provides real-time kernel security monitoring and threat detection for Linux servers. The service includes server monitoring, threat analysis, alerting, and reporting features.
            </p>
          </section>

          <section>
            <h2 style={{ fontSize: '1.5rem', fontWeight: 600, marginBottom: '1rem', color: 'var(--color-text)' }}>
              3. User Accounts
            </h2>
            <p>
              You are responsible for maintaining the confidentiality of your account credentials. You agree to accept responsibility for all activities that occur under your account. KernelEye reserves the right to suspend or terminate accounts that violate these terms.
            </p>
          </section>

          <section>
            <h2 style={{ fontSize: '1.5rem', fontWeight: 600, marginBottom: '1rem', color: 'var(--color-text)' }}>
              4. Acceptable Use
            </h2>
            <p>
              You agree not to use the service to:
            </p>
            <ul style={{ marginLeft: '1.5rem', marginTop: '0.5rem' }}>
              <li>Violate any applicable laws or regulations</li>
              <li>Attempt to gain unauthorized access to any systems</li>
              <li>Interfere with or disrupt the service</li>
              <li>Transmit malicious code or harmful content</li>
            </ul>
          </section>

          <section>
            <h2 style={{ fontSize: '1.5rem', fontWeight: 600, marginBottom: '1rem', color: 'var(--color-text)' }}>
              5. Intellectual Property
            </h2>
            <p>
              All content, features, and functionality of KernelEye are owned by us and are protected by international copyright, trademark, patent, trade secret, and other intellectual property laws.
            </p>
          </section>

          <section>
            <h2 style={{ fontSize: '1.5rem', fontWeight: 600, marginBottom: '1rem', color: 'var(--color-text)' }}>
              6. Limitation of Liability
            </h2>
            <p>
              KernelEye shall not be liable for any indirect, incidental, special, consequential, or punitive damages resulting from your use of or inability to use the service.
            </p>
          </section>

          <section>
            <h2 style={{ fontSize: '1.5rem', fontWeight: 600, marginBottom: '1rem', color: 'var(--color-text)' }}>
              7. Changes to Terms
            </h2>
            <p>
              We reserve the right to modify these terms at any time. Your continued use of KernelEye after any changes indicates your acceptance of the new terms.
            </p>
          </section>

          <section>
            <h2 style={{ fontSize: '1.5rem', fontWeight: 600, marginBottom: '1rem', color: 'var(--color-text)' }}>
              8. Contact Us
            </h2>
            <p>
              If you have any questions about these Terms of Service, please contact us at support@kerneleye.com
            </p>
          </section>
        </div>
      </div>
    </div>
  );
};

export default Terms;
