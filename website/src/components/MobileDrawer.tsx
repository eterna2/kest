'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { X, Info, BookOpen, Terminal, Layers } from 'lucide-react';

export default function MobileDrawer({ isOpen, onClose }: { isOpen: boolean, onClose: () => void }) {
  const pathname = usePathname();

  const navItems = [
    { label: 'Introduction', href: '/', icon: Info },
    { label: 'Journal', href: '/blog', icon: BookOpen },
    { label: 'Portal', href: '/developers', icon: Terminal },
    { label: 'Collective', href: '/team', icon: Layers },
  ];

  if (!isOpen) return null;

  return (
    <>
      {/* Backdrop */}
      <div 
        onClick={onClose}
        style={{
          position: 'fixed',
          inset: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.5)',
          backdropFilter: 'blur(4px)',
          zIndex: 140
        }}
      />
      
      {/* Drawer — Glass Rule (DESIGN.md §2) */}
      <aside style={{
        position: 'fixed',
        top: 0,
        left: 0,
        bottom: 0,
        width: '280px',
        /* Glass styling per DESIGN.md §2 */
        backgroundColor: 'rgba(12, 19, 36, 0.85)',
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
        /* Ghost border fallback (DESIGN.md §4) */
        borderRight: '1px solid var(--outline-variant-ghost)',
        zIndex: 150,
        padding: '2rem 0',
        display: 'flex',
        flexDirection: 'column',
        /* Deep Space Shadow (DESIGN.md §4) */
        boxShadow: 'var(--shadow-l4)',
        animation: 'slideIn 0.3s ease-out'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0 2rem', marginBottom: '2rem', alignItems: 'center' }}>
          <div>
            <h3 style={{ fontSize: '1.25rem', fontWeight: 800, margin: 0, color: 'var(--on-surface)', fontFamily: 'var(--font-display)' }}>
              <span className="gradient-text">Kest</span>
            </h3>
            <p style={{ fontSize: '0.675rem', color: 'var(--primary)', letterSpacing: '0.2em', textTransform: 'uppercase', fontStyle: 'italic', fontWeight: 700 }}>
              Documentation
            </p>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--on-surface-variant)', cursor: 'pointer' }}>
             <X size={24} />
          </button>
        </div>

        <nav style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {navItems.map((item) => {
            const isActive = pathname === item.href;
            return (
              <Link 
                key={item.href} 
                href={item.href} 
                onClick={onClose}
                className={isActive ? 'active-pill' : ''}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '1rem',
                  padding: '1rem 2rem',
                  fontSize: '0.9rem',
                  color: isActive ? 'var(--primary)' : 'var(--on-surface-variant)',
                  backgroundColor: isActive ? 'rgba(79, 70, 229, 0.1)' : 'transparent',
                  textDecoration: 'none',
                  transition: 'background 0.2s'
                }}
              >
                <item.icon size={20} />
                <span style={{ fontWeight: isActive ? 700 : 400, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{item.label}</span>
              </Link>
            );
          })}
        </nav>

        <style>{`
          @keyframes slideIn {
            from { transform: translateX(-100%); }
            to { transform: translateX(0); }
          }
        `}</style>
      </aside>
    </>
  );
}
