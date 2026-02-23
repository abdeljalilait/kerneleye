/**
 * SEO Configuration for KernelEye
 * Export SEO metadata for all pages
 */

export interface SEOConfig {
  title: string;
  description: string;
  keywords: string[];
  ogImage?: string;
  canonical?: string;
  noIndex?: boolean;
}

// Base site config
export const siteConfig = {
  name: 'KernelEye',
  url: 'https://kerneleye.net',
  logo: 'https://kerneleye.net/logo.png',
  twitter: '@kerneleye',
};

// Home page SEO
export const homeSEO: SEOConfig = {
  title: 'KernelEye - Real-time Kernel Security for Linux Servers',
  description:
    'Kernel-level visibility and threat detection for Linux servers. eBPF-powered monitoring with millisecond response times. See everything, block threats instantly.',
  keywords: [
    'kernel security',
    'linux security',
    'ebpf',
    'xdp',
    'real-time monitoring',
    'threat detection',
    'server security',
    'linux kernel',
    'network security',
    'intrusion detection',
  ],
  ogImage: 'https://kerneleye.net/og-image.png',
  canonical: 'https://kerneleye.net/',
};

// Features page SEO
export const featuresSEO: SEOConfig = {
  title: 'Features - KernelEye Security Platform',
  description:
    'Complete kernel security with real-time visibility, active protection, lightning-fast performance, zero trust architecture, and smart analytics.',
  keywords: [
    'kernel security features',
    'ebpf monitoring',
    'real-time protection',
    'zero trust security',
    'network analytics',
    'threat intelligence',
  ],
  ogImage: 'https://kerneleye.net/og-features.png',
  canonical: 'https://kerneleye.net/features',
};

// Pricing page SEO
export const pricingSEO: SEOConfig = {
  title: 'Pricing - KernelEye Security Plans',
  description: 'Simple, transparent pricing for kernel security. Start free for 14 days. Plans for teams of all sizes.',
  keywords: [
    'kernel security pricing',
    'linux security cost',
    'ebpf pricing',
    'security software pricing',
    'enterprise security',
  ],
  ogImage: 'https://kerneleye.net/og-pricing.png',
  canonical: 'https://kerneleye.net/pricing',
};

// Contact page SEO
export const contactSEO: SEOConfig = {
  title: 'Contact - Get in Touch with KernelEye',
  description:
    'Contact the KernelEye team for sales inquiries, support, or to schedule a demo. Secure your infrastructure today.',
  keywords: ['contact kernel security', 'linux security sales', 'security demo', 'kernel security support'],
  ogImage: 'https://kerneleye.net/og-contact.png',
  canonical: 'https://kerneleye.net/contact',
};

// Default/fallback SEO
export const defaultSEO: SEOConfig = {
  title: 'KernelEye - Kernel Security Platform',
  description: 'Real-time kernel security monitoring and threat detection for Linux servers.',
  keywords: ['kernel security', 'linux', 'ebpf', 'monitoring'],
  ogImage: 'https://kerneleye.net/og-image.png',
};

// Generate meta tags helper
export function generateMetaTags(config: SEOConfig) {
  return {
    title: config.title,
    meta: [
      { name: 'description', content: config.description },
      { name: 'keywords', content: config.keywords.join(', ') },

      // Open Graph
      { property: 'og:title', content: config.title },
      { property: 'og:description', content: config.description },
      { property: 'og:type', content: 'website' },
      { property: 'og:site_name', content: siteConfig.name },
      ...(config.ogImage ? [{ property: 'og:image', content: config.ogImage }] : []),
      ...(config.canonical ? [{ property: 'og:url', content: config.canonical }] : []),

      // Twitter
      { name: 'twitter:card', content: 'summary_large_image' },
      { name: 'twitter:site', content: siteConfig.twitter },
      { name: 'twitter:title', content: config.title },
      { name: 'twitter:description', content: config.description },
      ...(config.ogImage ? [{ name: 'twitter:image', content: config.ogImage }] : []),

      // Robots
      ...(config.noIndex ? [{ name: 'robots', content: 'noindex, nofollow' }] : []),
    ],
    links: [...(config.canonical ? [{ rel: 'canonical', href: config.canonical }] : [])],
  };
}

// JSON-LD structured data helpers
export const organizationSchema = {
  '@context': 'https://schema.org',
  '@type': 'Organization',
  name: siteConfig.name,
  url: siteConfig.url,
  logo: siteConfig.logo,
  sameAs: ['https://twitter.com/kerneleye', 'https://github.com/kerneleye', 'https://linkedin.com/company/kerneleye'],
};

export const softwareApplicationSchema = {
  '@context': 'https://schema.org',
  '@type': 'SoftwareApplication',
  name: siteConfig.name,
  applicationCategory: 'SecurityApplication',
  operatingSystem: 'Linux',
  offers: {
    '@type': 'Offer',
    price: '49.00',
    priceCurrency: 'USD',
  },
  aggregateRating: {
    '@type': 'AggregateRating',
    ratingValue: '4.8',
    ratingCount: '127',
  },
};

// Export all SEO configs as default object
const seo = {
  site: siteConfig,
  home: homeSEO,
  features: featuresSEO,
  pricing: pricingSEO,
  contact: contactSEO,
  default: defaultSEO,
  generateMetaTags,
  organizationSchema,
  softwareApplicationSchema,
};

export default seo;
