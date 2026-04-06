import Link from 'next/link';
import { Terminal, ArrowRight } from 'lucide-react';
import { getAllPosts } from '@/lib/mdx';

export default function APIIndexPage() {
  const reference = getAllPosts('reference');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '3rem' }}>
      {/* Header */}
      <div>
        <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', marginBottom: '1.5rem', fontSize: '0.8rem', opacity: 0.5 }}>
          <Link href="/developers" style={{ color: 'inherit' }}>Portal</Link>
          <span>/</span>
          <span style={{ color: 'var(--primary)' }}>API Specification</span>
        </div>
        <h1 style={{ fontSize: '2.5rem', margin: '0 0 1rem', fontFamily: 'var(--font-display)' }}>
          API <span className="gradient-text">Specification</span>
        </h1>
        <p style={{ fontSize: '1.1rem', color: 'var(--on-surface-variant)', maxWidth: '600px', lineHeight: 1.6 }}>
          Language-agnostic interface definitions for every core module, controller, and cryptographic primitive.
        </p>
      </div>

      {/* API Modules */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        {reference.map((ref) => (
          <Link
            key={ref.slug}
            href={`/developers/api/${ref.slug}`}
            className="kest-glow"
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '1.5rem 2rem',
              backgroundColor: 'var(--surface-container)',
              borderRadius: 'var(--radius-lg)',
              textDecoration: 'none',
              transition: 'all 0.2s',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
              <Terminal size={18} style={{ color: 'var(--primary)', opacity: 0.7 }} />
              <div>
                <h3 style={{ margin: 0, fontSize: '1rem', color: 'var(--on-surface)', fontFamily: 'var(--font-display)' }}>
                  {ref.meta.title}
                </h3>
                <p style={{ margin: '0.25rem 0 0', fontSize: '0.8rem', color: 'var(--on-surface-variant)', opacity: 0.5 }}>
                  {ref.meta.description}
                </p>
              </div>
            </div>
            <ArrowRight size={16} style={{ color: 'var(--on-surface-variant)', opacity: 0.3 }} />
          </Link>
        ))}
      </div>
    </div>
  );
}
