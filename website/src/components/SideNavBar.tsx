'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Info, BookOpen, Layers, Terminal, ExternalLink } from 'lucide-react';

export default function SideNavBar() {
  const pathname = usePathname();

  const navItems = [
    { label: 'Introduction', href: '/', icon: Info },
    { label: 'Journal', href: '/blog', icon: BookOpen },
    { label: 'Portal', href: '/developers', icon: Terminal },
    { label: 'Collective', href: '/team', icon: Layers },
  ];

  return (
    <aside className="hidden lg:flex" style={{
      position: 'fixed',
      left: 0,
      top: '64px',
      width: '256px',
      height: 'calc(100vh - 64px)',
      flexDirection: 'column',
      padding: '2rem 0',
      /* Glass Rule (DESIGN.md §2) — sidebars MUST use glassmorphism */
      backgroundColor: 'rgba(12, 19, 36, 0.4)',
      backdropFilter: 'blur(20px)',
      WebkitBackdropFilter: 'blur(20px)',
      /* No-Line Rule (DESIGN.md §2) — tonal shift, not explicit border.
         Using ghost fallback since glass alone doesn't clearly separate. */
      borderRight: '1px solid var(--outline-variant-ghost)',
      zIndex: 90
    }}>
      <div style={{ padding: '0 2rem', marginBottom: '2.5rem' }}>
        <h3 style={{ fontSize: '1.1rem', fontWeight: 700, margin: 0, color: 'var(--on-surface)', fontFamily: 'var(--font-display)' }}>Documentation</h3>
        <p style={{ fontSize: '0.6rem', color: 'var(--primary)', letterSpacing: '0.1em', textTransform: 'uppercase', marginTop: '0.25rem', opacity: 0.6 }}>
          v0.3.0
        </p>
      </div>

      <nav style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
        {navItems.map((item) => {
          const isActive = pathname === item.href;
          return (
            <Link 
              key={item.href} 
              href={item.href} 
              className={isActive ? 'active-pill' : ''}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.75rem',
                padding: '0.625rem 2rem',
                fontSize: '0.875rem',
                color: isActive ? 'var(--primary)' : 'var(--on-surface-variant)',
                transition: 'all 0.2s ease',
                textDecoration: 'none'
              }}
            >
              <item.icon size={18} />
              <span>{item.label}</span>
            </Link>
          );
        })}
      </nav>

      <div style={{ marginTop: 'auto', padding: '0 1.5rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
         <Link href="/developers/guide/getting_started" className="btn-secondary" style={{ width: '100%', fontSize: '0.7rem', padding: '0.75rem', letterSpacing: '0.1em', textTransform: 'uppercase', fontWeight: 700, textAlign: 'center', textDecoration: 'none' }}>
            Get Started
         </Link>
         
         <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginTop: '1rem' }}>
            <a href="https://github.com/eterna2/kest/issues" target="_blank" rel="noreferrer" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.758rem', color: 'rgba(220, 225, 251, 0.4)', textDecoration: 'none' }}>
              <ExternalLink size={14} /> <span>Support</span>
            </a>
            <a href="https://github.com/eterna2/kest/discussions" target="_blank" rel="noreferrer" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.758rem', color: 'rgba(220, 225, 251, 0.4)', textDecoration: 'none' }}>
              <ExternalLink size={14} /> <span>Feedback</span>
            </a>
         </div>
      </div>
    </aside>
  );
}
