import type { MetadataRoute } from 'next';

export const dynamic = 'force-static';

export default function manifest(): MetadataRoute.Manifest {
  const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? '';
  return {
    name: 'Kest | Key Trust',
    short_name: 'Kest',
    description: 'Key Trust. Verified Lineage for AI.',
    start_url: `${basePath}/`,
    display: 'standalone',
    background_color: '#0c1324',
    theme_color: '#c3c0ff',
    icons: [
      {
        src: `${basePath}/favicon.ico`,
        sizes: 'any',
        type: 'image/x-icon',
      },
      {
        src: `${basePath}/icon.png`,
        sizes: '512x512',
        type: 'image/png',
      },
      {
        src: `${basePath}/apple-icon.png`,
        sizes: '512x512',
        type: 'image/png',
      },
    ],
  };
}
