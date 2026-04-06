'use client';

import { Terminal } from 'lucide-react';

interface CodeSidebarProps {
  title?: string;
  children: React.ReactNode;
}

export default function CodeSidebar({ title = 'Code Instance', children }: CodeSidebarProps) {
  return (
    <aside className="code-sidebar" style={{
      position: 'sticky',
      top: '120px',
      alignSelf: 'start',
      backgroundColor: 'var(--surface-container-lowest)',
      borderRadius: 'var(--radius-lg)',
      overflow: 'hidden',
      display: 'flex',
      flexDirection: 'column',
      minWidth: '320px',
      boxShadow: 'var(--shadow-l4)',
      maxHeight: 'calc(100vh - 160px)'
    }}>
      {/* Window Header */}
      <div style={{
         padding: '0.75rem 1rem',
         backgroundColor: 'var(--surface-container-low)',
         borderBottom: '1px solid var(--outline-variant-ghost)',
         display: 'flex',
         alignItems: 'center',
         justifyContent: 'space-between'
      }}>
         <div style={{ display: 'flex', gap: '6px' }}>
            <div style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: '#ff5f56' }} />
            <div style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: '#ffbd2e' }} />
            <div style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: '#27c93f' }} />
         </div>
         <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', opacity: 0.5 }}>
            <Terminal size={14} />
            <span style={{ fontSize: '0.675rem', fontWeight: 600, letterSpacing: '0.05em', textTransform: 'uppercase' }}>{title}</span>
         </div>
      </div>

      {/* Code Container */}
      <div style={{ padding: '1rem', overflowY: 'auto', fontSize: '0.875rem', fontFamily: 'var(--font-mono)' }}>
         {children}
      </div>

      {/* Footer Info */}
      <div style={{ padding: '0.5rem 1rem', fontSize: '0.625rem', color: 'var(--primary)', opacity: 0.4, fontStyle: 'italic', borderTop: '1px solid rgba(195,192,255,0.05)' }}>
         Initialized v0.3.0 // k-core-python
      </div>
    </aside>
  );
}
