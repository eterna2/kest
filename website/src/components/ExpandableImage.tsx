'use client';

import { useState, useCallback, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { useTheme } from './ThemeProvider';

/**
 * A client-side lightbox overlay for expanding images.
 * When an image is clicked, it opens in a full-viewport overlay
 * with a dark backdrop and can be dismissed by clicking anywhere
 * or pressing Escape.
 *
 * Uses React Portal to render the overlay at document.body,
 * avoiding the hydration error from <div> nested inside <p>.
 */
export default function ExpandableImage({
  src,
  alt,
  style,
  ...rest
}: React.ImgHTMLAttributes<HTMLImageElement>) {
  const [isOpen, setIsOpen] = useState(false);
  const [mounted, setMounted] = useState(false);
  const { theme } = useTheme();

  const close = useCallback(() => setIsOpen(false), []);

  // Only portal after client mount to avoid SSR mismatch
  useEffect(() => setMounted(true), []);

  // Determine the themed source
  const getThemedSrc = (originalSrc: string | any | undefined) => {
    if (typeof originalSrc !== 'string' || !mounted || theme !== 'scratchpad') return originalSrc;
    
    // List of images that have sketchy variants
    const sketchyImages = [
      'merkle-chain.png',
      'trust-degradation.png',
      'policy-tiers.png',
      'kest-lab-arch.png',
      'gateway_flow_diagram.png',
      'scope_narrowing.png',
      'merkle_chain_diagram.png',
      'hero.png'
    ];

    const fileName = originalSrc.split('/').pop() || '';
    if (sketchyImages.includes(fileName)) {
      return originalSrc.replace('.png', '-sketch.png');
    }
    
    return originalSrc;
  };

  const themedSrc = getThemedSrc(src);

  useEffect(() => {
    if (!isOpen) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close();
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [isOpen, close]);

  return (
    <>
      {/* Inline image with expand hint */}
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img
        src={themedSrc}
        alt={alt || ''}
        {...rest}
        onClick={() => setIsOpen(true)}
        style={{
          ...style,
          cursor: 'zoom-in',
          transition: 'transform 0.2s ease, box-shadow 0.2s ease',
        }}
        onMouseEnter={(e) => {
          (e.currentTarget as HTMLElement).style.transform = 'scale(1.01)';
          (e.currentTarget as HTMLElement).style.boxShadow = '0 8px 32px rgba(79,70,229,0.15)';
        }}
        onMouseLeave={(e) => {
          (e.currentTarget as HTMLElement).style.transform = 'scale(1)';
          (e.currentTarget as HTMLElement).style.boxShadow = 'none';
        }}
      />

      {/* Lightbox overlay — rendered via Portal to avoid <div> inside <p> */}
      {mounted && isOpen && createPortal(
        <div
          onClick={close}
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 9999,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            backgroundColor: 'rgba(7, 13, 31, 0.92)',
            backdropFilter: 'blur(12px)',
            WebkitBackdropFilter: 'blur(12px)',
            cursor: 'zoom-out',
            animation: 'lightbox-in 0.2s ease',
          }}
        >
          {/* Close hint */}
          <div style={{
            position: 'absolute',
            top: '1.5rem',
            right: '2rem',
            color: 'rgba(220, 225, 251, 0.5)',
            fontSize: '0.75rem',
            letterSpacing: '0.1em',
            textTransform: 'uppercase',
            fontWeight: 700,
          }}>
            ESC to close
          </div>

          {/* Expanded image */}
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img
            src={themedSrc}
            alt={alt || ''}
            style={{
              maxWidth: '90vw',
              maxHeight: '90vh',
              objectFit: 'contain',
              borderRadius: '12px',
              boxShadow: '0 24px 48px rgba(0, 0, 0, 0.4)',
            }}
          />
        </div>,
        document.body
      )}
    </>
  );
}
