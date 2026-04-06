'use client';

import { useState, useMemo, useCallback, useEffect, useRef } from 'react';
import Fuse from 'fuse.js';
import { Search, FileText, ArrowRight } from 'lucide-react';

interface SearchItem {
  title: string;
  description: string;
  slug: string;
  href: string;
  category: string;
}

interface SearchBoxProps {
  items?: SearchItem[];
}

/**
 * Client-side search with Fuse.js fuzzy matching.
 * Pre-loaded with all documentation content at build time via
 * a data attribute or inline JSON from the server component.
 */
export default function SearchBox({ items = [] }: SearchBoxProps) {
  const [query, setQuery] = useState('');
  const [isOpen, setIsOpen] = useState(false);
  const wrapperRef = useRef<HTMLDivElement>(null);

  const fuse = useMemo(() => new Fuse(items, {
    keys: ['title', 'description', 'category'],
    threshold: 0.35,
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

  // Close dropdown on outside click
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (wrapperRef.current && !wrapperRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <div ref={wrapperRef} style={{ maxWidth: '600px', margin: '0 auto', position: 'relative' }}>
      <div style={{
        backgroundColor: 'var(--surface-container)',
        padding: '1rem 1.5rem',
        borderRadius: 'var(--radius-lg)',
        display: 'flex',
        alignItems: 'center',
        gap: '1rem',
        transition: 'box-shadow 0.2s',
        boxShadow: isOpen && results.length > 0 ? '0 4px 24px rgba(0,0,0,0.3)' : 'none',
      }}>
        <Search size={20} style={{ color: 'var(--primary)', flexShrink: 0 }} />
        <input
          type="text"
          placeholder="Search guides, API specs, policies…"
          value={query}
          onChange={handleChange}
          onFocus={() => setIsOpen(true)}
          style={{
            background: 'none',
            border: 'none',
            color: 'var(--on-surface)',
            fontSize: '1rem',
            outline: 'none',
            width: '100%',
            fontFamily: 'inherit',
          }}
        />
        {query && (
          <button 
            onClick={() => { setQuery(''); setIsOpen(false); }}
            style={{
              background: 'none', border: 'none', color: 'var(--on-surface-variant)',
              cursor: 'pointer', padding: '0.25rem', fontSize: '1rem', opacity: 0.5,
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
          left: 0,
          right: 0,
          marginTop: '0.5rem',
          backgroundColor: 'var(--surface-container-high)',
          borderRadius: 'var(--radius-lg)',
          boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
          overflow: 'hidden',
          zIndex: 50,
        }}>
          {results.map(({ item }) => (
            <a
              key={item.href}
              href={item.href}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '1rem',
                padding: '1rem 1.5rem',
                textDecoration: 'none',
                color: 'var(--on-surface)',
                borderBottom: '1px solid rgba(195,192,255,0.05)',
                transition: 'background-color 0.15s',
              }}
              onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'rgba(195,192,255,0.05)')}
              onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
              onClick={() => setIsOpen(false)}
            >
              <FileText size={16} style={{ color: 'var(--primary)', opacity: 0.6, flexShrink: 0 }} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>{item.title}</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--on-surface-variant)', opacity: 0.5, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {item.category} · {item.description}
                </div>
              </div>
              <ArrowRight size={14} style={{ opacity: 0.3, flexShrink: 0 }} />
            </a>
          ))}
        </div>
      )}

      {isOpen && query.trim() && results.length === 0 && (
        <div style={{
          position: 'absolute',
          top: '100%',
          left: 0,
          right: 0,
          marginTop: '0.5rem',
          backgroundColor: 'var(--surface-container-high)',
          borderRadius: 'var(--radius-lg)',
          padding: '2rem',
          textAlign: 'center',
          color: 'var(--on-surface-variant)',
          fontSize: '0.875rem',
          opacity: 0.6,
          zIndex: 50,
        }}>
          No results for &quot;{query}&quot;
        </div>
      )}
    </div>
  );
}
