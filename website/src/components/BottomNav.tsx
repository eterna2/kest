'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Home, Book, Terminal, User, Pencil, Moon } from 'lucide-react';
import { useTheme } from './ThemeProvider';

export default function BottomNav() {
  const pathname = usePathname();
  const { theme, toggleTheme, mounted } = useTheme();

  const navItems = [
    { label: 'Home', href: '/', icon: Home },
    { label: 'Concepts', href: '/concepts', icon: Book },
    { label: 'Portal', href: '/developers', icon: Terminal },
    { label: 'The Clowder', href: '/team', icon: User },
  ];

  return (
    <nav className="md:hidden" style={{
      position: 'fixed',
      bottom: 0,
      left: 0,
      right: 0,
      height: '64px',
      zIndex: 100,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-around',
      /* Glass Rule (DESIGN.md §2) */
      backgroundColor: mounted && theme === 'scratchpad' ? 'rgba(250, 246, 240, 0.95)' : 'rgba(12, 19, 36, 0.6)',
      backdropFilter: mounted && theme === 'scratchpad' ? 'none' : 'blur(20px)',
      WebkitBackdropFilter: 'blur(20px)',
      /* Ghost Border Fallback (DESIGN.md §4) */
      borderTop: '1px solid var(--outline-variant-ghost)',
      paddingBottom: 'env(safe-area-inset-bottom)'
    }}>
      {navItems.map((item) => {
        const isActive = pathname === item.href;
        return (
          <Link 
            key={item.href} 
            href={item.href} 
            style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: '0.25rem',
              color: isActive ? 'var(--primary)' : 'var(--on-surface-variant)',
              textDecoration: 'none',
              fontSize: '0.625rem',
              fontWeight: isActive ? 700 : 500,
              transition: 'color 0.2s'
            }}
          >
            <item.icon size={20} />
            <span style={{ textTransform: 'uppercase', letterSpacing: '0.05em' }}>{item.label}</span>
          </Link>
        );
      })}
      
      <button 
        onClick={toggleTheme}
        style={{
          display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.25rem',
          color: 'var(--on-surface-variant)', background: 'none', border: 'none', cursor: 'pointer',
          padding: 0
        }}
      >
        {mounted && theme === 'scratchpad' ? <Moon size={20} /> : <Pencil size={20} />}
        <span style={{ textTransform: 'uppercase', letterSpacing: '0.05em', fontSize: '0.625rem', fontWeight: 500 }}>Theme</span>
      </button>
    </nav>
  );
}
