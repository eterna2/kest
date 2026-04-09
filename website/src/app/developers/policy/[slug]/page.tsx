import { getPost, getAllPosts } from '@/lib/mdx';
import MarkdownContent from '@/components/MarkdownContent';
import CodeSidebar from '@/components/CodeSidebar';
import PageNavigation from '@/components/PageNavigation';
import { notFound } from 'next/navigation';
import Link from 'next/link';

export function generateStaticParams() {
  return getAllPosts('policies').map((p) => ({ slug: p.slug }));
}

export default async function PolicyPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const post = getPost('policies', slug);

  if (!post) {
    return notFound();
  }

  const allPosts = getAllPosts('policies');
  const currentIndex = allPosts.findIndex((p) => p.slug === slug);
  const prev = currentIndex > 0 ? allPosts[currentIndex - 1] : null;
  const next = currentIndex < allPosts.length - 1 ? allPosts[currentIndex + 1] : null;

  const meta = post.meta as any;
  const sidebarTitle = meta.sidebarTitle || `${slug}.rego`;
  const sidebarCode = meta.sidebarCode || `package kest.authz

import rego.v1

default allow := false

# Swarm-level attestation
allow if {
  input.identity.type == "kest_agent"
  input.action == "swarm_init"
}`;

  return (
    <div className="detail-layout">
      <article className="md-body">
        <div style={{ marginBottom: '3rem' }}>
          <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', marginBottom: '1.5rem', fontSize: '0.8rem', opacity: 0.5 }}>
            <Link href="/developers" style={{ color: 'inherit' }}>Portal</Link>
            <span>/</span>
            <Link href="/developers/policy" style={{ color: 'inherit' }}>Policy Library</Link>
          </div>
          <h1 style={{ margin: 0 }}>{post.meta.title}</h1>
          <p style={{ fontSize: '1.1rem', color: 'var(--on-surface-variant)', lineHeight: 1.6, margin: '1rem 0 0' }}>{post.meta.description}</p>
        </div>
        
        <MarkdownContent content={post.content} currentDir="policies" suppressFirstH1 />
        <PageNavigation
          prev={prev ? { slug: prev.slug, title: prev.meta.title } : null}
          next={next ? { slug: next.slug, title: next.meta.title } : null}
          basePath="/developers/policy"
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

