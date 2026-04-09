'use client';

import { useState } from 'react';

/**
 * Copy-to-clipboard button for code blocks.
 * Per DESIGN.md §5 Code Blocks: glass header with Copy action.
 */
export default function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback for environments without clipboard API
      const textarea = document.createElement('textarea');
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <button
      onClick={handleCopy}
      className="copy-btn"
      aria-label={copied ? 'Copied!' : 'Copy code'}
      style={{
        background: 'none',
        border: 'none',
        color: copied ? 'var(--primary)' : 'var(--on-surface-variant)',
        cursor: 'pointer',
        padding: '0.25rem 0.5rem',
        fontSize: '0.7rem',
        fontFamily: 'var(--font-body)',
        opacity: copied ? 1 : 0.5,
        transition: 'opacity 0.2s, color 0.2s',
        borderRadius: 'var(--radius-sm)',
      }}
    >
      {copied ? (
        <>
          <span className="copy-btn-icon">✓</span>
          <span className="copy-btn-text"> Copied</span>
        </>
      ) : (
        <>
          <span className="copy-btn-icon">⧉</span>
          <span className="copy-btn-text"> Copy</span>
        </>
      )}
    </button>
  );
}
