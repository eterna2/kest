import Link from 'next/link';
import { Shield, ArrowRight } from 'lucide-react';
import { getAllPosts } from '@/lib/mdx';

export default function PolicyIndexPage() {
  const policies = getAllPosts('policies');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '3rem' }}>
      {/* Header */}
      <div>
        <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', marginBottom: '1.5rem', fontSize: '0.8rem', opacity: 0.5 }}>
          <Link href="/developers" style={{ color: 'inherit' }}>Portal</Link>
          <span>/</span>
          <span style={{ color: 'var(--primary)' }}>Policy Library</span>
        </div>
        <h1 style={{ fontSize: '2.5rem', margin: '0 0 1rem', fontFamily: 'var(--font-display)' }}>
          Policy <span className="gradient-text">Library</span>
        </h1>
        <p style={{ fontSize: '1.1rem', color: 'var(--on-surface-variant)', maxWidth: '600px', lineHeight: 1.6 }}>
          Production-ready OPA (Rego) and Cedar policies for authorization, compliance, and trust evaluation.
        </p>
      </div>

      {/* Policies */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '1.5rem' }}>
        {policies.map((policy) => (
          <Link
            key={policy.slug}
            href={`/developers/policy/${policy.slug}`}
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
              <Shield size={18} style={{ color: 'var(--primary)', opacity: 0.7 }} />
              <h3 style={{ margin: 0, fontSize: '1.1rem', color: 'var(--on-surface)', fontFamily: 'var(--font-display)' }}>
                {policy.meta.title}
              </h3>
            </div>
            <p style={{ margin: 0, fontSize: '0.85rem', color: 'var(--on-surface-variant)', opacity: 0.6, lineHeight: 1.5, flex: 1 }}>
              {policy.meta.description}
            </p>
            <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--primary)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              View policy <ArrowRight size={12} />
            </span>
          </Link>
        ))}
      </div>
    </div>
  );
}
