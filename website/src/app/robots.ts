export const dynamic = 'force-static';

export default function robots() {
  const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? '';
  return {
    rules: {
      userAgent: '*',
      allow: '/',
    },
    sitemap: `https://eterna2.github.io${basePath}/sitemap.xml`,
  };
}
