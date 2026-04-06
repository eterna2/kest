import fs from 'fs';
import path from 'path';
import matter from 'gray-matter';
import { compileMDX } from 'next-mdx-remote/rsc';
import rehypePrettyCode from 'rehype-pretty-code';
import rehypeSlug from 'rehype-slug';
import remarkGfm from 'remark-gfm';

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
  
  return { meta: { ...data, title, description: desc }, content, slug };
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
 * Per DESIGN.md §5 Code Blocks:
 * - surface-container-lowest background
 * - Glass header bar with language label
 * - No border
 */
export async function compileContent(source: string, components?: Record<string, React.ComponentType<any>>) {
  const { content, frontmatter } = await compileMDX({
    source,
    options: {
      mdxOptions: {
        remarkPlugins: [remarkGfm],
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
