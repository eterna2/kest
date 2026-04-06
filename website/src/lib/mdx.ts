import fs from 'fs';
import path from 'path';
import matter from 'gray-matter';
import { compileMDX } from 'next-mdx-remote/rsc';
import rehypePrettyCode from 'rehype-pretty-code';
import rehypeSlug from 'rehype-slug';
import remarkGfm from 'remark-gfm';
import remarkRewriteLinks from './remark-rewrite-links';

const CONTENT_PATH = path.join(process.cwd(), 'content');

export function getFiles(dir: string) {
  const fullPath = path.join(CONTENT_PATH, dir);
  if (!fs.existsSync(fullPath)) return [];
  return fs.readdirSync(fullPath).filter((f) => f.endsWith('.md'));
}

export function getPost(dir: string, slug: string) {
  const p = path.join(CONTENT_PATH, dir, `${slug}.md`);
  if (!fs.existsSync(p)) return null;
  const raw = fs.readFileSync(p, 'utf8');
  const { data, content } = matter(raw);
  
  const title = data.title || content.match(/^#\s+(.+)$/m)?.[1] || slug.replace(/_/g, ' ');
  const desc = data.description || content.split('\n').find((l: string) => l.trim() && !l.startsWith('#'))?.substring(0, 160) || '';
  
  // Strip the leading H1 from content since page components render it
  // separately from meta.title. This prevents duplicate headings.
  const strippedContent = content.replace(/^#\s+.+\n+/, '');

  return { meta: { ...data, title, description: desc }, content: strippedContent, slug, dir };
}

export function getAllPosts(dir: string) {
  return getFiles(dir).map((file) => {
    const slug = file.replace(/\.md$/, '');
    const { data, content } = matter(
      fs.readFileSync(path.join(CONTENT_PATH, dir, file), 'utf8')
    );
    const title = data.title || content.match(/^#\s+(.+)$/m)?.[1] || slug.replace(/_/g, ' ');
    const desc = data.description || content.split('\n').find((l: string) => l.trim() && !l.startsWith('#'))?.substring(0, 160) || '';
    return { meta: { ...data, title, description: desc }, slug };
  });
}

/**
 * Compiles markdown content to React elements using next-mdx-remote/rsc
 * with syntax highlighting via rehype-pretty-code (shiki) and
 * heading anchors via rehype-slug.
 *
 * @param source - The raw markdown string.
 * @param components - Optional MDX component overrides.
 * @param currentDir - The content directory of the source file (e.g. 'developer', 'design').
 *                     Used by remarkRewriteLinks to resolve relative .md links.
 *
 * Per DESIGN.md §5 Code Blocks:
 * - surface-container-lowest background
 * - Glass header bar with language label
 * - No border
 */
export async function compileContent(
  source: string,
  components?: Record<string, React.ComponentType<any>>,
  currentDir?: string,
) {
  const { content, frontmatter } = await compileMDX({
    source,
    options: {
      mdxOptions: {
        remarkPlugins: [
          remarkGfm,
          [remarkRewriteLinks, { currentDir }],
        ],
        rehypePlugins: [
          rehypeSlug,
          [
            rehypePrettyCode,
            {
              theme: 'github-dark-dimmed',
              keepBackground: false,
              defaultLang: 'plaintext',
            },
          ],
        ],
      },
      parseFrontmatter: true,
    },
    components,
  });

  return { content, frontmatter };
}
