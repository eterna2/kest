'use client';

import { useState, useEffect, useCallback } from 'react';

interface ExpandableCodeProps {
  language: string;
  rawCode: string;
  /** Rendered content inside the block (token tree for code, SVG for mermaid) */
  children: React.ReactNode;
  /** When true, children are NOT wrapped in a <pre> (e.g. mermaid SVG output) */
  noPreWrapper?: boolean;
  preProps?: React.HTMLAttributes<HTMLPreElement>;
}

/**
 * Wraps a code block (or mermaid diagram) in a glass header with Copy + Expand actions.
 * Expand opens a full-viewport modal so long lines / large diagrams are easy to read.
 * Images use ExpandableImage instead — they are already handled separately.
 */
export default function ExpandableCode({
  language,
  rawCode,
  children,
  noPreWrapper = false,
  preProps = {},
}: ExpandableCodeProps) {
  const [copied, setCopied]    = useState(false);
  const [expanded, setExpanded] = useState(false);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(rawCode);
    } catch {
      const ta = document.createElement('textarea');
      ta.value = rawCode;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [rawCode]);

  // Close modal on Escape, lock body scroll while open
  useEffect(() => {
    if (!expanded) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setExpanded(false); };
    document.addEventListener('keydown', onKey);
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = '';
    };
  }, [expanded]);

  const content = noPreWrapper
    ? children
    : <pre {...preProps}>{children}</pre>;

  const expandedContent = noPreWrapper
    ? (
        <div style={{ padding: '1.5rem', overflow: 'auto', flex: 1 }}>
          {children}
        </div>
      )
    : (
        <div style={{ flex: 1, overflow: 'auto', WebkitOverflowScrolling: 'touch' as React.CSSProperties['WebkitOverflowScrolling'], padding: '1.5rem' }}>
          <pre
            {...preProps}
            style={{
              ...(preProps.style || {}),
              margin: 0,
              borderRadius: '8px',
              fontSize: '0.9rem',
              lineHeight: 1.6,
            }}
          >
            {children}
          </pre>
        </div>
      );

  return (
    <>
      {/* Inline view */}
      <div className="code-block-wrapper">
        <div className="code-block-header">
          <span className="lang-label">{language || 'code'}</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', flexShrink: 0 }}>
            <button
              onClick={handleCopy}
              className="copy-btn"
              aria-label={copied ? 'Copied!' : 'Copy code'}
            >
              <span className="copy-btn-icon">{copied ? '✓' : '⧉'}</span>
              <span className="copy-btn-text">{copied ? ' Copied' : ' Copy'}</span>
            </button>
            <button
              onClick={() => setExpanded(true)}
              className="copy-btn"
              aria-label="Expand to full screen"
              title="Expand"
              style={{ opacity: 0.5, transition: 'opacity 0.2s' }}
              onMouseEnter={e => (e.currentTarget.style.opacity = '1')}
              onMouseLeave={e => (e.currentTarget.style.opacity = '0.5')}
            >
              ⤢
            </button>
          </div>
        </div>
        {content}
      </div>

      {/* Fullscreen modal */}
      {expanded && (
        <div
          onClick={() => setExpanded(false)}
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 9999,
            backgroundColor: 'rgba(0,0,0,0.88)',
            backdropFilter: 'blur(10px)',
            WebkitBackdropFilter: 'blur(10px)',
            display: 'flex',
            flexDirection: 'column',
          }}
        >
          <div
            onClick={e => e.stopPropagation()}
            style={{ display: 'flex', flexDirection: 'column', height: '100dvh', maxWidth: '100vw' }}
          >
            {/* Modal toolbar */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '0.625rem 1.25rem',
                background: 'rgba(18, 24, 42, 0.96)',
                borderBottom: '1px solid rgba(255,255,255,0.07)',
                flexShrink: 0,
              }}
            >
              <span
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.7rem',
                  textTransform: 'uppercase',
                  letterSpacing: '0.1em',
                  opacity: 0.5,
                }}
              >
                {language || 'code'}
              </span>
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                <button
                  onClick={handleCopy}
                  style={{
                    background: 'none',
                    border: '1px solid rgba(255,255,255,0.12)',
                    color: copied ? 'var(--primary)' : 'var(--on-surface-variant)',
                    cursor: 'pointer',
                    borderRadius: '6px',
                    padding: '0.25rem 0.75rem',
                    fontSize: '0.75rem',
                    fontFamily: 'var(--font-body)',
                    transition: 'color 0.2s',
                  }}
                >
                  {copied ? '✓ Copied' : '⧉ Copy'}
                </button>
                <button
                  onClick={() => setExpanded(false)}
                  aria-label="Close expanded view (Escape)"
                  style={{
                    background: 'none',
                    border: '1px solid rgba(255,255,255,0.12)',
                    color: 'var(--on-surface-variant)',
                    cursor: 'pointer',
                    borderRadius: '6px',
                    padding: '0.25rem 0.75rem',
                    fontSize: '0.75rem',
                    fontFamily: 'var(--font-body)',
                  }}
                >
                  ✕ Close
                </button>
              </div>
            </div>

            {/* Scrollable expanded content */}
            {expandedContent}
          </div>
        </div>
      )}
    </>
  );
}
