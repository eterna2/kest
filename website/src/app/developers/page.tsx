import Link from 'next/link';
import { Book, Terminal, Shield, ArrowRight } from 'lucide-react';
import { getAllPosts } from '@/lib/mdx';
import GlobalSearch from '@/components/GlobalSearch';
import { buildSearchIndex } from '@/lib/search';

export default function DevelopersPage() {
  const guides = getAllPosts('developer');
  const policies = getAllPosts('policies');
  const reference = getAllPosts('reference');

  // Build search index from all content
  const searchItems = buildSearchIndex();

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '5rem' }}>
      {/* Hero */}
      <section>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
          <div style={{ padding: '0.4rem 0.8rem', backgroundColor: 'var(--primary)', color: 'var(--on-primary)', borderRadius: 'var(--radius-full)', fontSize: '0.625rem', fontWeight: 800, letterSpacing: '0.1em' }}>
            PORTAL v0.3.0
          </div>
        </div>
        <h1 style={{ fontSize: '3.5rem', margin: 0, fontFamily: 'var(--font-display)' }}>Developer <span className="gradient-text">Portal</span></h1>
        <p style={{ fontSize: '1.25rem', color: 'var(--on-surface-variant)', maxWidth: '600px', marginTop: '1rem', lineHeight: 1.6 }}>
          Guides, API specifications, and policy libraries for integrating cryptographic identity
          and verifiable telemetry into your AI workflows.
        </p>
      </section>

      {/* Primary Navigation Sections */}
      <section style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '2rem' }}>
         {/* Guides */}
         <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', backgroundColor: 'var(--surface-container-low)', padding: '2.5rem', borderRadius: 'var(--radius-xl)' }}>
            <div style={{ color: 'var(--primary)', display: 'flex', alignItems: 'center', gap: '1rem' }}>
               <Book size={28} />
               <h2 style={{ fontSize: '1.5rem', margin: 0, fontFamily: 'var(--font-display)' }}>Developer Guide</h2>
            </div>
            <p style={{ fontSize: '0.875rem', opacity: 0.6, margin: 0 }}>From initial handshake to complex swarm orchestration. Learn the Kest way.</p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginTop: '0.5rem' }}>
               {guides.slice(0, 4).map(guide => (
                 <Link key={guide.slug} href={`/developers/guide/${guide.slug}`} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.75rem 0', borderBottom: '1px solid rgba(195,192,255,0.05)', color: 'var(--on-surface)', textDecoration: 'none', fontSize: '0.9rem' }}>
                    <span>{guide.meta.title}</span>
                    <ArrowRight size={14} style={{ opacity: 0.3 }} />
                 </Link>
               ))}
               <Link href="/developers/guide" style={{ color: 'var(--primary)', fontWeight: 700, fontSize: '0.8rem', marginTop: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                 View all {guides.length} guides <ArrowRight size={12} />
               </Link>
            </div>
         </div>

         {/* API Reference */}
         <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', backgroundColor: 'var(--surface-container-low)', padding: '2.5rem', borderRadius: 'var(--radius-xl)' }}>
            <div style={{ color: 'var(--primary)', display: 'flex', alignItems: 'center', gap: '1rem' }}>
               <Terminal size={28} />
               <h2 style={{ fontSize: '1.5rem', margin: 0, fontFamily: 'var(--font-display)' }}>API Specification</h2>
            </div>
            <p style={{ fontSize: '0.875rem', opacity: 0.6, margin: 0 }}>Language-agnostic interfaces for core controllers, identity providers, and hash engines.</p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginTop: '0.5rem' }}>
               {reference.slice(0, 4).map(ref => (
                 <Link key={ref.slug} href={`/developers/api/${ref.slug}`} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.75rem 0', borderBottom: '1px solid rgba(195,192,255,0.05)', color: 'var(--on-surface)', textDecoration: 'none', fontSize: '0.9rem' }}>
                    <span>{ref.meta.title}</span>
                    <ArrowRight size={14} style={{ opacity: 0.3 }} />
                 </Link>
               ))}
               <Link href="/developers/api" style={{ color: 'var(--primary)', fontWeight: 700, fontSize: '0.8rem', marginTop: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                 View all {reference.length} specs <ArrowRight size={12} />
               </Link>
            </div>
         </div>

         {/* Trust & Policies */}
         <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', backgroundColor: 'var(--surface-container-low)', padding: '2.5rem', borderRadius: 'var(--radius-xl)' }}>
            <div style={{ color: 'var(--primary)', display: 'flex', alignItems: 'center', gap: '1rem' }}>
               <Shield size={28} />
               <h2 style={{ fontSize: '1.5rem', margin: 0, fontFamily: 'var(--font-display)' }}>Policy Library</h2>
            </div>
            <p style={{ fontSize: '0.875rem', opacity: 0.6, margin: 0 }}>Out-of-the-box OPA and Cedar policies for common security and compliance patterns.</p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginTop: '0.5rem' }}>
               {policies.slice(0, 4).map(policy => (
                 <Link key={policy.slug} href={`/developers/policy/${policy.slug}`} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.75rem 0', borderBottom: '1px solid rgba(195,192,255,0.05)', color: 'var(--on-surface)', textDecoration: 'none', fontSize: '0.9rem' }}>
                    <span>{policy.meta.title}</span>
                    <ArrowRight size={14} style={{ opacity: 0.3 }} />
                 </Link>
               ))}
               <Link href="/developers/policy" style={{ color: 'var(--primary)', fontWeight: 700, fontSize: '0.8rem', marginTop: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                 View all {policies.length} policies <ArrowRight size={12} />
               </Link>
            </div>
         </div>
      </section>

      {/* Search */}
      <section style={{ textAlign: 'center', padding: '3rem 0' }}>
         <h3 style={{ fontSize: '1.5rem', marginBottom: '2rem', fontFamily: 'var(--font-display)' }}>Looking for something specific?</h3>
         <GlobalSearch items={searchItems} placeholder="Search guides, API specs, policies…" />
      </section>
    </div>
  );
}
