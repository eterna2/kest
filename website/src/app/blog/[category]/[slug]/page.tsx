import { getPost, getAllPosts } from '@/lib/mdx';
import { notFound } from 'next/navigation';
import MarkdownContent from '@/components/MarkdownContent';
import PageNavigation from '@/components/PageNavigation';
import Link from 'next/link';

export const dynamic = 'force-static';

const BLOG_DIRS = ['design', 'compliance', 'infra', 'examples'] as const;

export async function generateStaticParams() {
  const params: { category: string; slug: string }[] = [];
  for (const category of BLOG_DIRS) {
    const posts = getAllPosts(category); // returns clean (prefix-stripped) slugs
    for (const post of posts) {
      params.push({ category, slug: post.slug });
    }
  }
  return params;
}

export default async function BlogPostPage({
  params,
}: {
  params: Promise<{ category: string; slug: string }>;
}) {
  const { category, slug } = await params;
  const post = getPost(category, slug);
  if (!post) notFound();

  // Build ordered list of all posts in this category for prev/next
  const allInCategory = getAllPosts(category);
  const currentIndex = allInCategory.findIndex((p) => p.slug === slug);
  const prev = currentIndex > 0 ? allInCategory[currentIndex - 1] : null;
  const next =
    currentIndex < allInCategory.length - 1 ? allInCategory[currentIndex + 1] : null;

  return (
    <div style={{ maxWidth: '800px', padding: '4rem 2rem' }}>
      <div
        style={{
          display: 'flex',
          gap: '0.75rem',
          alignItems: 'center',
          marginBottom: '2rem',
          opacity: 0.5,
          fontSize: '0.8rem',
        }}
      >
        <Link
          href="/blog"
          style={{
            textTransform: 'uppercase',
            letterSpacing: '0.1em',
            color: 'inherit',
            textDecoration: 'none',
          }}
        >
          Journal
        </Link>
        <span>/</span>
        <span style={{ color: 'var(--primary)', fontWeight: 600 }}>
          {category.toUpperCase()}
        </span>
      </div>
      <h1 style={{ fontSize: '3rem', lineHeight: 1.1, marginBottom: '2rem' }}>
        {post!.meta.title}
      </h1>
      <div
        style={{
          display: 'flex',
          gap: '1rem',
          alignItems: 'center',
          marginBottom: '4rem',
          opacity: 0.6,
          fontSize: '0.9rem',
        }}
      >
        <span className="chip">{category}</span>
        <div
          style={{
            width: '4px',
            height: '4px',
            borderRadius: '50%',
            backgroundColor: 'var(--primary)',
          }}
        />
        <span>Ref: KST-{slug}</span>
      </div>
      <MarkdownContent content={post!.content} currentDir={category} />
      <PageNavigation
        prev={prev ? { slug: prev.slug, title: prev.meta.title } : null}
        next={next ? { slug: next.slug, title: next.meta.title } : null}
        basePath={`/blog/${category}`}
      />
    </div>
  );
}
