import { getPost, getAllPosts } from '@/lib/mdx';
import MarkdownContent from '@/components/MarkdownContent';
import CodeSidebar from '@/components/CodeSidebar';
import PageNavigation from '@/components/PageNavigation';
import { notFound } from 'next/navigation';
import Link from 'next/link';
import { TerminalSquare } from 'lucide-react';

export function generateStaticParams() {
  return getAllPosts('reference').map((p) => ({ slug: p.slug }));
}

export default async function APIPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const post = getPost('reference', slug);

  if (!post) {
    return notFound();
  }

  const allPosts = getAllPosts('reference');
  const currentIndex = allPosts.findIndex((p) => p.slug === slug);
  const prev = currentIndex > 0 ? allPosts[currentIndex - 1] : null;
  const next = currentIndex < allPosts.length - 1 ? allPosts[currentIndex + 1] : null;

  const meta = post.meta as any;
  const sidebarTitle = meta.sidebarTitle || `${slug}.py`;
  const sidebarCode = meta.sidebarCode || `// No specification available for ${slug}`;

  return (
    <div className="detail-layout">
      <article className="md-body">
        <div style={{ marginBottom: '3rem' }}>
          <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', marginBottom: '1.5rem', fontSize: '0.8rem', opacity: 0.5 }}>
            <Link href="/developers" style={{ color: 'inherit' }}>Portal</Link>
            <span>/</span>
            <Link href="/developers/api" style={{ color: 'inherit' }}>API Spec</Link>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1rem' }}>
             <TerminalSquare size={32} style={{ color: 'var(--primary)' }} />
             <h1 style={{ margin: 0 }}>{post.meta.title}</h1>
          </div>
          <p style={{ fontSize: '1.2rem', color: 'var(--on-surface-variant)', lineHeight: 1.6 }}>{post.meta.description}</p>
        </div>
        <MarkdownContent content={post.content} currentDir="reference" suppressFirstH1 />
        <PageNavigation
          prev={prev ? { slug: prev.slug, title: prev.meta.title } : null}
          next={next ? { slug: next.slug, title: next.meta.title } : null}
          basePath="/developers/api"
        />
      </article>

      <CodeSidebar title={sidebarTitle}>
        <pre style={{ margin: 0, padding: 0, backgroundColor: 'transparent' }}>
          <code style={{ fontSize: '0.75rem', color: 'var(--primary)', opacity: 0.8 }}>
            {sidebarCode}
          </code>
        </pre>
      </CodeSidebar>
    </div>
  );
}
