import { visit } from 'unist-util-visit';
import type { Plugin } from 'unified';
import type { Link } from 'mdast';

/**
 * Remark plugin that rewrites markdown links (e.g. `getting_started.md`,
 * `../design/merkle_dag.md`) to the correct website routes.
 *
 * Content directory → Website route mapping:
 *   content/design/*        → /blog/design/{slug}
 *   content/infra/*         → /blog/infra/{slug}
 *   content/compliance/*    → /blog/compliance/{slug}
 *   content/examples/*      → /blog/examples/{slug}
 *   content/developer/*     → /developers/guide/{slug}
 *   content/reference/*     → /developers/api/{slug}
 *   content/policies/*      → /developers/policy/{slug}
 *
 * This keeps the .md links valid for raw GitHub viewing while
 * automatically resolving them to the correct website paths.
 */

const DIR_TO_ROUTE: Record<string, string> = {
  design: '/blog/design',
  infra: '/blog/infra',
  compliance: '/blog/compliance',
  examples: '/blog/examples',
  developer: '/developers/guide',
  reference: '/developers/api',
  policies: '/developers/policy',
};

interface RemarkRewriteLinksOptions {
  /** The content directory of the current file (e.g. 'developer', 'design') */
  currentDir?: string;
}

const remarkRewriteLinks: Plugin<[RemarkRewriteLinksOptions?]> = (options = {}) => {
  const { currentDir } = options;

  return (tree) => {
    visit(tree, 'link', (node: Link) => {
      const url = node.url;

      // Skip external links, anchors, and already-absolute website paths
      if (!url || url.startsWith('http') || url.startsWith('#') || (url.startsWith('/') && !url.endsWith('.md'))) {
        return;
      }

      // Skip image references
      if (/\.(png|jpg|jpeg|gif|svg|webp)$/i.test(url)) {
        return;
      }

      // Parse the link: could be "getting_started.md", "../design/merkle_dag.md",
      // or "../design/merkle_dag.md#section"
      const [pathPart, hash] = url.split('#');
      const hashSuffix = hash ? `#${hash}` : '';

      // Remove .md extension
      const cleaned = pathPart.replace(/\.md$/, '');

      // Split into segments to determine the target directory
      const segments = cleaned.split('/').filter(Boolean);

      // Remove leading '..' segments
      const nonRelativeSegments = segments.filter(s => s !== '..');

      let targetDir: string;
      let slug: string;

      if (nonRelativeSegments.length >= 2) {
        // Link like "../design/merkle_dag" or "design/merkle_dag"
        targetDir = nonRelativeSegments[nonRelativeSegments.length - 2];
        slug = nonRelativeSegments[nonRelativeSegments.length - 1];
      } else if (nonRelativeSegments.length === 1) {
        // Link like "getting_started.md" — relative to current directory
        targetDir = currentDir || '';
        slug = nonRelativeSegments[0];
      } else {
        return; // Can't resolve
      }

      // Skip README slugs — these are typically index pages
      if (slug === 'README') {
        const routeBase = DIR_TO_ROUTE[targetDir];
        if (routeBase) {
          // Point to the parent section
          const parentRoute = routeBase.split('/').slice(0, -1).join('/') || '/';
          node.url = `${parentRoute}${hashSuffix}`;
        }
        return;
      }

      const routeBase = DIR_TO_ROUTE[targetDir];
      if (routeBase) {
        node.url = `${routeBase}/${slug}${hashSuffix}`;
      }
    });
  };
};

export default remarkRewriteLinks;
