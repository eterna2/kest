'use client';

import { useEffect, useRef, useState } from 'react';

import { useTheme } from './ThemeProvider';

/**
 * Client-side Mermaid diagram renderer.
 * Renders mermaid source code into SVG diagrams using the mermaid.js library.
 *
 * Per DESIGN.md: diagrams use surface-container-lowest background
 * with the standard glass-wrapper styling.
 */
export default function Mermaid({ chart }: { chart: string }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [svg, setSvg] = useState<string>('');
  const [error, setError] = useState<string>('');
  const { theme, mounted } = useTheme();

  useEffect(() => {
    let cancelled = false;

    async function render() {
      try {
        const mermaid = (await import('mermaid')).default;
        mermaid.initialize({
          startOnLoad: false,
          theme: mounted && theme === 'scratchpad' ? 'base' : 'dark',
          themeVariables: mounted && theme === 'scratchpad' ? {
            primaryColor: '#ffffff',
            primaryTextColor: '#2c2c2c',
            primaryBorderColor: '#2c2c2c',
            lineColor: '#555555',
            secondaryColor: '#f5f0e8',
            tertiaryColor: '#ede7db',
            fontFamily: 'var(--font-body)',
            fontSize: '18px',
            background: '#ffffff',
            mainBkg: '#ffffff',
            nodeBorder: '#2c2c2c',
            clusterBkg: '#ede7db',
            clusterBorder: '#999999',
            titleColor: '#2c3e50',
            edgeLabelBackground: '#f5f0e8',
          } : {
            primaryColor: '#4f46e5',
            primaryTextColor: '#e4e2f0',
            primaryBorderColor: '#6366f1',
            lineColor: '#768390',
            secondaryColor: '#1e293b',
            tertiaryColor: '#0f172a',
            fontFamily: 'var(--font-body)',
            fontSize: '14px',
            background: '#0c1324',
            mainBkg: '#141d33',
            nodeBorder: '#4f46e5',
            clusterBkg: '#141d33',
            clusterBorder: '#4f46e5',
            titleColor: '#e4e2f0',
            edgeLabelBackground: '#141d33',
          },
        });

        const id = `mermaid-${Math.random().toString(36).slice(2, 9)}`;
        const { svg: rendered } = await mermaid.render(id, chart.trim());

        if (!cancelled) {
          setSvg(rendered);
          setError('');
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Failed to render diagram');
        }
      }
    }

    render();
    return () => { cancelled = true; };
  }, [chart, theme, mounted]);

  if (error) {
    return (
      <div style={{
        padding: '1.5rem',
        backgroundColor: 'var(--surface-container-lowest)',
        borderRadius: 'var(--radius-lg)',
        color: 'var(--error, #ef4444)',
        fontSize: '0.85rem',
        fontFamily: 'var(--font-mono)',
      }}>
        <p style={{ margin: '0 0 0.5rem', fontWeight: 600 }}>Diagram Error</p>
        <pre style={{ margin: 0, whiteSpace: 'pre-wrap', opacity: 0.7 }}>{error}</pre>
      </div>
    );
  }

  if (!svg) {
    return (
      <div style={{
        padding: '3rem',
        textAlign: 'center',
        color: 'var(--on-surface-variant)',
        fontSize: '0.85rem',
        opacity: 0.5,
      }}>
        Rendering diagram…
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className="mermaid-diagram"
      style={{
        backgroundColor: 'var(--surface-container-lowest)',
        borderRadius: 'var(--radius-lg)',
        padding: '2rem',
        overflow: 'auto',
        textAlign: 'center',
      }}
      dangerouslySetInnerHTML={{ __html: svg }}
    />
  );
}
