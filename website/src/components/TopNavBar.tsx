'use client';

import Link from 'next/link';
import { Menu, Terminal } from 'lucide-react';
import GlobalSearch from './GlobalSearch';
import type { SearchItem } from './GlobalSearch';

interface TopNavBarProps {
  onMenuClick: () => void;
  searchItems?: SearchItem[];
}

export default function TopNavBar({ onMenuClick, searchItems = [] }: TopNavBarProps) {
  return (
    <header style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      height: '64px',
      zIndex: 100,
      display: 'flex',
      alignItems: 'center',
      padding: '0 2rem',
      backgroundColor: 'rgba(12, 19, 36, 0.6)',
      backdropFilter: 'blur(20px)',
      WebkitBackdropFilter: 'blur(20px)',
      borderBottom: '1px solid var(--outline-variant-ghost)',
      boxShadow: 'var(--shadow-l4)',
    }}>
      {/* Mobile Menu Trigger */}
      <button 
        onClick={onMenuClick}
        className="md:hidden" 
        style={{ background: 'none', border: 'none', color: 'var(--primary)', cursor: 'pointer', padding: '0.5rem', marginRight: '1rem' }}
        aria-label="Open navigation menu"
      >
        <Menu size={24} />
      </button>

      {/* Brand */}
      <Link href="/" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', textDecoration: 'none' }}>
        <span style={{ fontSize: '1.25rem', fontWeight: 800, fontFamily: 'var(--font-display)', color: 'var(--on-surface)', letterSpacing: '-0.04em' }}>
          <span className="gradient-text">Kest</span>
        </span>
      </Link>

      {/* Desktop Links */}
      <nav style={{
        marginLeft: '3rem',
        display: 'flex',
        gap: '2rem',
        fontSize: '0.9rem',
        fontWeight: 500,
        color: 'var(--on-surface-variant)'
      }} className="hidden md:flex">
        <Link href="/concepts" style={{ color: 'inherit', textDecoration: 'none' }}>Concepts</Link>
        <Link href="/developers" style={{ color: 'inherit', textDecoration: 'none' }}>Portal</Link>
        <Link href="/team" style={{ color: 'inherit', textDecoration: 'none' }}>The Clowder</Link>
      </nav>

      {/* Action Area */}
      <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
        {/* Live Search — Fuse.js powered */}
        <div className="hidden sm:flex">
          <GlobalSearch items={searchItems} compact placeholder="Search insights..." />
        </div>

        <a href="https://github.com/eterna2/kest" target="_blank" rel="noreferrer" style={{ color: 'var(--on-surface-variant)', display: 'flex' }} aria-label="View source on GitHub">
          <Terminal size={20} />
        </a>
        
        <Link href="/developers/guide/getting_started" className="btn-premium" style={{ padding: '0.5rem 1rem', fontSize: '0.8rem', textDecoration: 'none' }}>
          Get Started
        </Link>
      </div>
    </header>
  );
}
