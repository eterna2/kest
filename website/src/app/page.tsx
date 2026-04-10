import Link from 'next/link';
import { Terminal, Code, Shield, BookOpen, ArrowRight } from 'lucide-react';
import ThemedHeroImage from '@/components/ThemedHeroImage';
import BentoCard from '@/components/BentoCard';
import SketchyHighlight from '@/components/SketchyHighlight';
import { getAllPosts } from '@/lib/mdx';

export default function Home() {
  // Pull real guide data instead of hardcoded content
  const guides = getAllPosts('developer').slice(0, 4);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '5rem' }}>

      {/* ═══════════════════════════════════════════════
          HERO SECTION
          DESIGN.MD §3: display-md headline + label-md uppercase sub-header
          ═══════════════════════════════════════════════ */}
      <section style={{ 
        display: 'grid', 
        gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', 
        gap: '4rem', 
        alignItems: 'center',
        paddingTop: '2rem'
      }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Label-md sub-header in primary (DESIGN.MD §3 Hierarchy Rule) */}
          <span style={{ 
            fontSize: '0.75rem', 
            fontWeight: 800, 
            letterSpacing: '0.2em', 
            color: 'var(--primary)', 
            textTransform: 'uppercase',
            position: 'relative',
            zIndex: 1
          }}>
            <SketchyHighlight type="underline" color="var(--primary)" strokeWidth={2} animationDuration={800}>
              Zero Trust Execution Lineage
            </SketchyHighlight>
          </span>

          {/* Display-md headline */}
          <h1 style={{ fontSize: 'clamp(2.5rem, 5vw, 4rem)', lineHeight: 1.05, margin: 0, fontFamily: 'var(--font-display)', position: 'relative', zIndex: 1 }}>
            <SketchyHighlight type="highlight" color="var(--secondary-container)" animationDuration={1000}>
              <span className="gradient-text">Key Trust.</span>
            </SketchyHighlight><br />
            Verified Lineage for AI.
          </h1>

          <p style={{ fontSize: '1.125rem', color: 'var(--on-surface-variant)', maxWidth: '480px', lineHeight: 1.7 }}>
            Zero Trust execution lineage for AI agentic workflows. Cryptographically signed audit trails via Merkle DAG Passports and policy-as-code enforcement (OPA/Cedar).
          </p>

          <div style={{ display: 'flex', gap: '1rem', marginTop: '0.5rem' }}>
            <Link href="/developers/guide/getting_started" className="btn-premium" style={{ textDecoration: 'none' }}>
              Get Started
            </Link>
            <Link href="/developers" className="btn-secondary" style={{ textDecoration: 'none' }}>
              Read the Spec
            </Link>
          </div>
        </div>
        
        <ThemedHeroImage />
      </section>

      {/* ═══════════════════════════════════════════════
          LATEST SIGNAL — Version Banner
          ═══════════════════════════════════════════════ */}
      <section style={{ 
        backgroundColor: 'var(--surface-container-high)', 
        borderRadius: 'var(--radius-xl)', 
        padding: '2.5rem 3rem',
        display: 'flex',
        flexWrap: 'wrap',
        justifyContent: 'space-between',
        alignItems: 'center',
        gap: '2rem'
      }}>
        <div style={{ display: 'flex', gap: '1.5rem', alignItems: 'center' }}>
           <div style={{ 
             width: '48px', 
             height: '48px', 
             borderRadius: 'var(--radius-md)', 
             background: 'linear-gradient(135deg, var(--primary-container), var(--primary))',
             display: 'flex', 
             alignItems: 'center', 
             justifyContent: 'center',
             color: '#ffffff'
           }}>
             <Shield size={24} />
           </div>
           <div>
             <span style={{ fontSize: '0.625rem', fontWeight: 800, letterSpacing: '0.1em', color: 'var(--primary)', textTransform: 'uppercase' }}>
               Latest Signal
             </span>
             <h2 style={{ fontSize: '1.15rem', margin: '0.25rem 0', fontFamily: 'var(--font-display)' }}>Kest v0.3.0 — Cryptographic Lineage</h2>
             <p style={{ fontSize: '0.85rem', color: 'var(--on-surface-variant)', margin: 0, opacity: 0.6 }}>
               SPIFFE identity, OPA/Cedar policy evaluation, and Merkle DAG audit trails.
             </p>
           </div>
        </div>
        <div style={{ display: 'flex', gap: '1rem' }}>
          <Link href="/changelog" className="btn-secondary" style={{ fontSize: '0.8rem', textDecoration: 'none' }}>View Changelog</Link>
          <Link href="/developers/guide/getting_started" className="btn-premium" style={{ padding: '0.5rem 1.5rem', fontSize: '0.8rem', textDecoration: 'none' }}>Get Started</Link>
        </div>
      </section>

      {/* ═══════════════════════════════════════════════
          BENTO GRID — Core Sections
          DESIGN.MD §2: Tonal shifting, no direct borders
          ═══════════════════════════════════════════════ */}
      <section style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '2rem' }}>
        <BentoCard 
          tag="Developer Guide"
          title="Getting Started"
          description="Secure your first Python microservice with cryptographic identity and verifiable execution in under 10 minutes."
          href="/developers/guide/getting_started"
          icon={<Terminal size={24} />}
        />
        <BentoCard 
          tag="Architecture"
          title="Design Specification"
          description="Deep-dive into the Secret Zero problem, Merkle DAG lineage, ABAC policy enforcement, and edge case handling."
          href="/concepts/design/overview"
          icon={<Code size={24} />}
        />
      </section>

      {/* ═══════════════════════════════════════════════
          GUIDES + CONCEPTS — Real Data
          ═══════════════════════════════════════════════ */}
      <section style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '4rem' }}>
        {/* Top Guides — dynamically pulled from content */}
        <div>
          <div style={{ marginBottom: '2.5rem' }}>
            <span style={{ fontSize: '0.65rem', fontWeight: 800, letterSpacing: '0.15em', color: 'var(--primary)', textTransform: 'uppercase' }}>
              Documentation
            </span>
            <h3 style={{ fontSize: '1.5rem', margin: '0.5rem 0 0', fontFamily: 'var(--font-display)' }}>Technical Guides</h3>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
             {guides.map((guide) => (
                <Link key={guide.slug} href={`/developers/guide/${guide.slug}`} style={{ 
                  display: 'flex', 
                  alignItems: 'center', 
                  justifyContent: 'space-between',
                  padding: '1.25rem 1.5rem',
                  backgroundColor: 'var(--surface-container)',
                  borderRadius: 'var(--radius-lg)',
                  textDecoration: 'none',
                  transition: 'all 0.2s'
                }} className="kest-glow">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <BookOpen size={18} style={{ color: 'var(--primary)', opacity: 0.7 }} />
                    <span style={{ fontWeight: 600, color: 'var(--on-surface)', fontSize: '0.95rem' }}>{guide.meta.title}</span>
                  </div>
                  <ArrowRight size={16} style={{ color: 'var(--on-surface-variant)', opacity: 0.3 }} />
                </Link>
             ))}
             <Link href="/developers" style={{ 
               fontSize: '0.8rem', 
               color: 'var(--primary)', 
               fontWeight: 600, 
               marginTop: '0.5rem',
               display: 'flex',
               alignItems: 'center',
               gap: '0.5rem'
             }}>
               View all {getAllPosts('developer').length} guides <ArrowRight size={14} />
             </Link>
          </div>
        </div>

        {/* Core Concepts */}
        <div>
          <div style={{ marginBottom: '2.5rem' }}>
            <span style={{ fontSize: '0.65rem', fontWeight: 800, letterSpacing: '0.15em', color: 'var(--primary)', textTransform: 'uppercase' }}>
              Architecture
            </span>
            <h3 style={{ fontSize: '1.5rem', margin: '0.5rem 0 0', fontFamily: 'var(--font-display)' }}>Core Concepts</h3>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
             {[
               { title: 'Workload Identity (SPIFFE)', desc: 'Replace static API keys with dynamically rotated X509-SVIDs.', href: '/concepts/infra/spire' },
               { title: 'Cryptographic Lineage', desc: 'Merkle DAGs over OpenTelemetry baggage. Every hop is signed via JWS.', href: '/concepts/design/merkle_dag' },
               { title: 'Policy as Code (OPA/Cedar)', desc: 'Continuous authorization using ABAC policies at every hop.', href: '/concepts/design/abac_policy' },
             ].map((concept) => (
                <Link key={concept.href} href={concept.href} style={{ textDecoration: 'none' }}>
                  <div style={{ position: 'relative', paddingLeft: '1.5rem' }}>
                    <div style={{ 
                      position: 'absolute', 
                      left: 0, 
                      top: '0.35rem', 
                      width: '6px', 
                      height: '6px', 
                      borderRadius: '50%', 
                      backgroundColor: 'var(--primary)',
                      boxShadow: '0 0 8px var(--primary)'
                    }} />
                    <p style={{ margin: '0 0 0.25rem', fontWeight: 600, color: 'var(--on-surface)', fontSize: '0.95rem' }}>{concept.title}</p>
                    <p style={{ margin: 0, fontSize: '0.825rem', color: 'var(--on-surface-variant)', opacity: 0.6, lineHeight: 1.5 }}>{concept.desc}</p>
                  </div>
                </Link>
             ))}
          </div>
        </div>
      </section>
    </div>
  );
}
