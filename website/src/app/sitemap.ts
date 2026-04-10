import { getAllPosts } from '@/lib/mdx';
import type { MetadataRoute } from 'next';

export const dynamic = 'force-static';

export default function sitemap(): MetadataRoute.Sitemap {
  const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? '';
  const baseUrl = `https://eterna2.github.io${basePath}`;

  // Static routes
  const staticRoutes = [
    '',
    '/team',
    '/changelog',
    '/quickstart',
    '/concepts',
    '/developers',
    '/developers/api',
    '/developers/policy',
    '/developers/guide',
  ].map((route) => ({
    url: `${baseUrl}${route}`,
    lastModified: new Date(),
    changeFrequency: 'monthly' as const,
    priority: route === '' ? 1 : 0.8,
  }));

  // Concepts routes
  const conceptCategories = ['design', 'compliance', 'infra', 'examples'];
  const conceptRoutes = conceptCategories.flatMap((category) =>
    getAllPosts(category).map((post) => ({
      url: `${baseUrl}/concepts/${category}/${post.slug}`,
      lastModified: new Date(),
      changeFrequency: 'weekly' as const,
      priority: 0.7,
    }))
  );

  // Developer routes
  const developerGuides = getAllPosts('developer').map((post) => ({
    url: `${baseUrl}/developers/guide/${post.slug}`,
    lastModified: new Date(),
    changeFrequency: 'weekly' as const,
    priority: 0.7,
  }));

  const developerPolicies = getAllPosts('policies').map((post) => ({
    url: `${baseUrl}/developers/policy/${post.slug}`,
    lastModified: new Date(),
    changeFrequency: 'weekly' as const,
    priority: 0.6,
  }));

  const developerApi = getAllPosts('reference').map((post) => ({
    url: `${baseUrl}/developers/api/${post.slug}`,
    lastModified: new Date(),
    changeFrequency: 'weekly' as const,
    priority: 0.6,
  }));

  return [
    ...staticRoutes,
    ...conceptRoutes,
    ...developerGuides,
    ...developerPolicies,
    ...developerApi,
  ];
}
