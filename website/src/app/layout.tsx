import type { Metadata } from 'next';
import './globals.css';
import ClientLayout from '@/components/ClientLayout';
import { buildSearchIndex } from '@/lib/search';

const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? '';
const baseUrl = `https://eterna2.github.io${basePath}`;

export const metadata: Metadata = {
  metadataBase: new URL(baseUrl),
  title: {
    template: '%s | Kest',
    default: 'Kest | Key Trust',
  },
  description: 'Zero Trust execution lineage for AI agentic workflows. Cryptographically signed audit trails via Merkle DAG Passports and policy-as-code enforcement (OPA/Cedar).',
  keywords: [
    'Zero Trust',
    'AI Lineage',
    'Cryptographic Identity',
    'SPIFFE',
    'SPIRE',
    'OPA',
    'Cedar',
    'Merkle DAG',
    'Audit Trails',
    'AI Safety',
  ],
  authors: [{ name: 'Kest Team' }],
  creator: 'Kest Team',
  publisher: 'eterna2',
  formatDetection: {
    email: false,
    address: false,
    telephone: false,
  },
  alternates: {
    canonical: '/',
  },
  openGraph: {
    title: 'Kest | Key Trust',
    description: 'Verified Lineage for AI. Cryptographic identity and policy-as-code for agentic workflows.',
    url: baseUrl,
    siteName: 'Kest',
    locale: 'en_US',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Kest | Key Trust',
    description: 'Verified Lineage for AI. Cryptographic identity and policy-as-code for agentic workflows.',
    creator: '@eterna2',
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      'max-video-preview': -1,
      'max-image-preview': 'large',
      'max-snippet': -1,
    },
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <head>
        {/* Preconnect to Google Fonts as per Stitch screens */}
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
      </head>
      <body>
        <ClientLayout searchItems={buildSearchIndex()}>{children}</ClientLayout>
      </body>
    </html>
  );
}
