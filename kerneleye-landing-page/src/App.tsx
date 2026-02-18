import { Helmet } from 'react-helmet-async';
import Navigation from './sections/Navigation';
import HeroSection from './sections/HeroSection';
import FeaturesSection from './sections/FeaturesSection';
import HowItWorksSection from './sections/HowItWorksSection';
import PricingSection from './sections/PricingSection';
import ContactSection from './sections/ContactSection';
import Footer from './sections/Footer';
import { homeSEO, organizationSchema, softwareApplicationSchema } from './seo';

function App() {
  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <>
      <Helmet>
        {/* Primary Meta Tags */}
        <title>{homeSEO.title}</title>
        <meta name="description" content={homeSEO.description} />
        <meta name="keywords" content={homeSEO.keywords.join(', ')} />
        <link rel="canonical" href={homeSEO.canonical} />
        
        {/* Open Graph / Facebook */}
        <meta property="og:type" content="website" />
        <meta property="og:url" content={homeSEO.canonical} />
        <meta property="og:title" content={homeSEO.title} />
        <meta property="og:description" content={homeSEO.description} />
        <meta property="og:image" content={homeSEO.ogImage} />
        <meta property="og:site_name" content="KernelEye" />
        
        {/* Twitter */}
        <meta name="twitter:card" content="summary_large_image" />
        <meta name="twitter:url" content={homeSEO.canonical} />
        <meta name="twitter:title" content={homeSEO.title} />
        <meta name="twitter:description" content={homeSEO.description} />
        <meta name="twitter:image" content={homeSEO.ogImage} />
        
        {/* Structured Data - Organization */}
        <script type="application/ld+json">
          {JSON.stringify(organizationSchema)}
        </script>
        
        {/* Structured Data - Software Application */}
        <script type="application/ld+json">
          {JSON.stringify(softwareApplicationSchema)}
        </script>
      </Helmet>

      <div style={{ minHeight: '100vh' }}>
        <Navigation onHomeClick={scrollToTop} />
        <main>
          <HeroSection />
          <FeaturesSection />
          <HowItWorksSection />
          <PricingSection />
          <ContactSection />
        </main>
        <Footer />
      </div>
    </>
  );
}

export default App;
