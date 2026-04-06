'use client';

import { useState, useMemo, useCallback, useEffect, useRef } from 'react';
import Fuse from 'fuse.js';
import { Search, FileText, ArrowRight } from 'lucide-react';

export interface SearchItem {
  title: string;
  description: string;
  slug: string;
  href: string;
  category: string;
}

interface GlobalSearchProps {
  items: SearchItem[];
  /** Compact mode for TopNavBar — no border, smaller */
  compact?: boolean;
  placeholder?: string;
}

export default function GlobalSearch({ items, compact = false, placeholder = 'Search insights...' }: GlobalSearchProps) {
  const [query, setQuery] = useState('');
  const [isOpen, setIsOpen] = useState(false);
  const wrapperRef = useRef<HTMLDivElement>(null);

  const fuse = useMemo(() => new Fuse(items, {
    keys: ['title', 'description', 'category', 'slug'],
    threshold: 0.4,
    includeScore: true,
  }), [items]);

  const results = useMemo(() => {
    if (!query.trim()) return [];
    return fuse.search(query).slice(0, 8);
  }, [fuse, query]);

  const handleChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setQuery(e.target.value);
    setIsOpen(true);
  }, []);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (wrapperRef.current && !wrapperRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Keyboard shortcut: Cmd/Ctrl+K opens search
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        const input = wrapperRef.current?.querySelector('input');
        input?.focus();
        setIsOpen(true);
      }
      if (e.key === 'Escape') {
        setIsOpen(false);
      }
    }
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, []);

  return (
    <div ref={wrapperRef} style={{ position: 'relative', width: compact ? '220px' : '100%', maxWidth: compact ? '220px' : '600px', margin: compact ? undefined : '0 auto' }}>
      <div style={{
        backgroundColor: compact ? 'rgba(195,192,255,0.04)' : 'var(--surface-container)',
        padding: compact ? '0.4rem 0.75rem' : '1rem 1.5rem',
        borderRadius: 'var(--radius-lg)',
        display: 'flex',
        alignItems: 'center',
        gap: compact ? '0.5rem' : '1rem',
        transition: 'box-shadow 0.2s',
        boxShadow: isOpen && results.length > 0 ? '0 4px 24px rgba(0,0,0,0.3)' : 'none',
      }}>
        <Search size={compact ? 14 : 20} style={{ color: 'var(--outline)', flexShrink: 0 }} />
        <input
          type="text"
          placeholder={placeholder}
          value={query}
          onChange={handleChange}
          onFocus={() => setIsOpen(true)}
          style={{
            background: 'none',
            border: 'none',
            color: 'var(--on-surface)',
            fontSize: compact ? '0.8rem' : '1rem',
            outline: 'none',
            width: '100%',
            fontFamily: 'inherit',
          }}
        />
        {!query && compact && (
          <kbd style={{
            fontSize: '0.55rem',
            padding: '0.15rem 0.4rem',
            borderRadius: '4px',
            backgroundColor: 'rgba(195,192,255,0.08)',
            color: 'var(--on-surface-variant)',
            opacity: 0.4,
            whiteSpace: 'nowrap',
          }}>⌘K</kbd>
        )}
        {query && (
          <button
            onClick={() => { setQuery(''); setIsOpen(false); }}
            style={{
              background: 'none', border: 'none', color: 'var(--on-surface-variant)',
              cursor: 'pointer', padding: '0.25rem', fontSize: '0.8rem', opacity: 0.5,
            }}
          >
            ✕
          </button>
        )}
      </div>

      {/* Results dropdown */}
      {isOpen && results.length > 0 && (
        <div style={{
          position: 'absolute',
          top: '100%',
          left: compact ? '-100px' : 0,
          right: compact ? undefined : 0,
          width: compact ? '420px' : undefined,
          marginTop: '0.5rem',
          backgroundColor: 'var(--surface-container-high)',
          borderRadius: 'var(--radius-lg)',
          boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
          overflow: 'hidden',
          zIndex: 100,
        }}>
          {results.map(({ item }) => (
            <a
              key={item.href}
              href={item.href}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '1rem',
                padding: '0.875rem 1.25rem',
                textDecoration: 'none',
                color: 'var(--on-surface)',
                borderBottom: '1px solid rgba(195,192,255,0.04)',
                transition: 'background-color 0.15s',
              }}
              onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'rgba(195,192,255,0.05)')}
              onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
              onClick={() => setIsOpen(false)}
            >
              <FileText size={14} style={{ color: 'var(--primary)', opacity: 0.5, flexShrink: 0 }} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontWeight: 600, fontSize: '0.85rem' }}>{item.title}</div>
                <div style={{ fontSize: '0.7rem', color: 'var(--on-surface-variant)', opacity: 0.5, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {item.category} · {item.description}
                </div>
              </div>
              <ArrowRight size={12} style={{ opacity: 0.2, flexShrink: 0 }} />
            </a>
          ))}
        </div>
      )}

      {isOpen && query.trim() && results.length === 0 && (
        <div style={{
          position: 'absolute',
          top: '100%',
          left: compact ? '-100px' : 0,
          right: compact ? undefined : 0,
          width: compact ? '420px' : undefined,
          marginTop: '0.5rem',
          backgroundColor: 'var(--surface-container-high)',
          borderRadius: 'var(--radius-lg)',
          padding: '1.5rem',
          textAlign: 'center',
          color: 'var(--on-surface-variant)',
          fontSize: '0.8rem',
          opacity: 0.6,
          zIndex: 100,
          boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
        }}>
          No results for &quot;{query}&quot;
        </div>
      )}
    </div>
  );
}
