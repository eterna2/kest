'use client';

import { useState } from 'react';
import Link from 'next/link';
import TopNavBar from './TopNavBar';
import SideNavBar from './SideNavBar';
import MobileDrawer from './MobileDrawer';
import KestGlow from './KestGlow';
import BottomNav from './BottomNav';
import type { SearchItem } from './GlobalSearch';
import { prefixPath } from '@/lib/utils';
import { ThemeProvider, useTheme } from './ThemeProvider';

export default function ClientLayout({ children, searchItems = [] }: { children: React.ReactNode; searchItems?: SearchItem[] }) {
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  return (
    <ThemeProvider>
      {/* SVG Filter for Scratchpad wobbly borders */}
      <svg width="0" height="0" style={{ position: 'absolute', pointerEvents: 'none' }}>
        <defs>
          <filter id="sketchy">
            <feTurbulence type="fractalNoise" baseFrequency="0.04" numOctaves="3" result="noise" />
            <feDisplacementMap in="SourceGraphic" in2="noise" scale="5" xChannelSelector="R" yChannelSelector="G" />
          </filter>
        </defs>
      </svg>
      <KestGlow />
      <TopNavBar onMenuClick={() => setIsMenuOpen(true)} searchItems={searchItems} />
      <MobileDrawer isOpen={isMenuOpen} onClose={() => setIsMenuOpen(false)} />
      <SideNavBar />
      <BottomNav />
      {/* Dynamic Content Area with Desktop Sidebar Offset */}
      <main className="layout-main" style={{ paddingTop: '80px', minHeight: '100vh' }}>
        <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '2rem' }}>
          {children}
        </div>
      </main>
      <Footer />
    </ThemeProvider>
  );
}

function Footer() {
  const { theme, mounted } = useTheme();
  
  return (
    <footer className="layout-footer" style={{ 
      backgroundColor: 'var(--surface-container-lowest)',
      padding: '5rem 2rem',
      marginTop: 'auto',
      textAlign: 'center',
    }}>
      <div style={{ 
        maxWidth: '1200px',
        margin: '0 auto',
        display: 'flex', 
        flexDirection: 'column', 
        alignItems: 'center', 
        gap: '2rem'
      }}>
        <img 
          src={prefixPath(mounted && theme === 'scratchpad' ? '/images/logo-scratchpad.svg' : '/images/logo-obsidian.svg')} 
          alt="Kest Logo" 
          style={{ width: '40px', height: '40px', opacity: 0.5, filter: 'grayscale(1)' }}
        />
        <div style={{ display: 'flex', gap: '2.5rem', flexWrap: 'wrap', justifyContent: 'center' }}>
          <a href="https://github.com/eterna2/kest" target="_blank" rel="noreferrer" style={{ color: 'rgba(220, 225, 251, 0.4)', fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.1em', textDecoration: 'none' }}>GitHub</a>
          <a href="https://github.com/eterna2/kest/issues" target="_blank" rel="noreferrer" style={{ color: 'rgba(220, 225, 251, 0.4)', fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.1em', textDecoration: 'none' }}>Issues</a>
          <a href="https://github.com/eterna2/kest/discussions" target="_blank" rel="noreferrer" style={{ color: 'rgba(220, 225, 251, 0.4)', fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.1em', textDecoration: 'none' }}>Discussions</a>
          <Link href="/changelog" style={{ color: 'rgba(220, 225, 251, 0.4)', fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.1em', textDecoration: 'none' }}>Changelog</Link>
        </div>
        <p style={{ color: 'rgba(220, 225, 251, 0.2)', fontSize: '0.675rem', textTransform: 'uppercase', letterSpacing: '0.2em' }}>
          © {new Date().getFullYear()} Kest — Key Trust. The Digital Observatory.
        </p>
      </div>
    </footer>
  );
}
