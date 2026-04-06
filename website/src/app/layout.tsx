import type { Metadata } from 'next';
import './globals.css';
import ClientLayout from '@/components/ClientLayout';
import { buildSearchIndex } from '@/lib/search';

export const metadata: Metadata = {
  metadataBase: new URL('https://eterna2.github.io/kest'),
  title: 'Kest | Key Trust',
  description: 'Key Trust. Verified Lineage for AI.',
  alternates: {
    canonical: './',
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
