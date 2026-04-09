import { getAllPosts } from './mdx';
import type { SearchItem } from '@/components/GlobalSearch';

/**
 * Builds a search index from all content sources.
 * Called server-side at build time so it's available for both
 * TopNavBar and the developer portal search.
 */
export function buildSearchIndex(): SearchItem[] {
  const guides = getAllPosts('developer');
  const reference = getAllPosts('reference');
  const policies = getAllPosts('policies');
  const designPosts = getAllPosts('design');
  const infraPosts = getAllPosts('infra');
  const compliancePosts = getAllPosts('compliance');

  return [
    ...guides.map(g => ({ title: g.meta.title, description: g.meta.description || '', slug: g.slug, href: `/developers/guide/${g.slug}`, category: 'Guide' })),
    ...reference.map(r => ({ title: r.meta.title, description: r.meta.description || '', slug: r.slug, href: `/developers/api/${r.slug}`, category: 'API Spec' })),
    ...policies.map(p => ({ title: p.meta.title, description: p.meta.description || '', slug: p.slug, href: `/developers/policy/${p.slug}`, category: 'Policy' })),
    ...designPosts.map(p => ({ title: p.meta.title, description: p.meta.description || '', slug: p.slug, href: `/concepts/design/${p.slug}`, category: 'Architecture' })),
    ...infraPosts.map(p => ({ title: p.meta.title, description: p.meta.description || '', slug: p.slug, href: `/concepts/infra/${p.slug}`, category: 'Infrastructure' })),
    ...compliancePosts.map(p => ({ title: p.meta.title, description: p.meta.description || '', slug: p.slug, href: `/concepts/compliance/${p.slug}`, category: 'Assurance' })),
    { title: 'The Clowder', description: 'Meet the team of 13 cats and 2 humans building Kest.', slug: 'team', href: '/team', category: 'Team' },
    { title: 'Bibi', description: 'Lead Cat, Protocol Architect, and Head of Treats.', slug: 'bibi', href: '/team', category: 'Team' },
    { title: 'Doidoi', description: 'Operations & Treat Logistics.', slug: 'doidoi', href: '/team', category: 'Team' },
  ];
}
