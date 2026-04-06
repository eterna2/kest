import Link from 'next/link';
import { BookOpen, ArrowRight } from 'lucide-react';
import { getAllPosts } from '@/lib/mdx';

export default function GuidesIndexPage() {
  const guides = getAllPosts('developer');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '3rem' }}>
      {/* Header */}
      <div>
        <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', marginBottom: '1.5rem', fontSize: '0.8rem', opacity: 0.5 }}>
          <Link href="/developers" style={{ color: 'inherit' }}>Portal</Link>
          <span>/</span>
          <span style={{ color: 'var(--primary)' }}>Guides</span>
        </div>
        <h1 style={{ fontSize: '2.5rem', margin: '0 0 1rem', fontFamily: 'var(--font-display)' }}>
          Developer <span className="gradient-text">Guides</span>
        </h1>
        <p style={{ fontSize: '1.1rem', color: 'var(--on-surface-variant)', maxWidth: '600px', lineHeight: 1.6 }}>
          Step-by-step tutorials for integrating cryptographic identity, policy enforcement, and verifiable telemetry into your applications.
        </p>
      </div>

      {/* Guides Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '1.5rem' }}>
        {guides.map((guide) => (
          <Link
            key={guide.slug}
            href={`/developers/guide/${guide.slug}`}
            className="kest-glow"
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: '1rem',
              padding: '2rem',
              backgroundColor: 'var(--surface-container)',
              borderRadius: 'var(--radius-lg)',
              textDecoration: 'none',
              transition: 'all 0.2s',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <BookOpen size={18} style={{ color: 'var(--primary)', opacity: 0.7 }} />
              <h3 style={{ margin: 0, fontSize: '1.1rem', color: 'var(--on-surface)', fontFamily: 'var(--font-display)' }}>
                {guide.meta.title}
              </h3>
            </div>
            <p style={{ margin: 0, fontSize: '0.85rem', color: 'var(--on-surface-variant)', opacity: 0.6, lineHeight: 1.5, flex: 1 }}>
              {guide.meta.description}
            </p>
            <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--primary)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              Read guide <ArrowRight size={12} />
            </span>
          </Link>
        ))}
      </div>
    </div>
  );
}
