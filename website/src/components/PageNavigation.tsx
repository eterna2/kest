import Link from 'next/link';
import { ArrowLeft, ArrowRight } from 'lucide-react';

interface NavEntry {
  slug: string;
  title: string;
}

interface PageNavigationProps {
  prev: NavEntry | null;
  next: NavEntry | null;
  basePath: string; // e.g. "/developers/guide"
}

export default function PageNavigation({ prev, next, basePath }: PageNavigationProps) {
  if (!prev && !next) return null;

  return (
    <nav
      aria-label="Page navigation"
      style={{
        display: 'flex',
        justifyContent: 'space-between',
        gap: '1rem',
        marginTop: '4rem',
        paddingTop: '2rem',
        borderTop: '1px solid var(--outline-variant-ghost)',
      }}
    >
      {/* Previous */}
      {prev ? (
        <Link
          href={`${basePath}/${prev.slug}`}
          className="kest-glow"
          style={{
            display: 'flex',
            flexDirection: 'column',
            gap: '0.4rem',
            padding: '1rem 1.25rem',
            backgroundColor: 'var(--surface-container)',
            borderRadius: 'var(--radius-lg)',
            border: '1px solid var(--outline-variant-ghost)',
            textDecoration: 'none',
            transition: 'all 0.2s ease',
            minWidth: 0,
            flex: '1 1 0',
            maxWidth: '45%',
          }}
        >
          <span
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
              fontSize: '0.7rem',
              textTransform: 'uppercase',
              letterSpacing: '0.1em',
              color: 'var(--on-surface-variant)',
              opacity: 0.5,
            }}
          >
            <ArrowLeft size={12} />
            Previous
          </span>
          <span
            style={{
              fontSize: '0.875rem',
              fontWeight: 600,
              color: 'var(--primary)',
              fontFamily: 'var(--font-display)',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
          >
            {prev.title}
          </span>
        </Link>
      ) : (
        <div style={{ flex: '1 1 0' }} />
      )}

      {/* Next */}
      {next ? (
        <Link
          href={`${basePath}/${next.slug}`}
          className="kest-glow"
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'flex-end',
            gap: '0.4rem',
            padding: '1rem 1.25rem',
            backgroundColor: 'var(--surface-container)',
            borderRadius: 'var(--radius-lg)',
            border: '1px solid var(--outline-variant-ghost)',
            textDecoration: 'none',
            transition: 'all 0.2s ease',
            minWidth: 0,
            flex: '1 1 0',
            maxWidth: '45%',
          }}
        >
          <span
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
              fontSize: '0.7rem',
              textTransform: 'uppercase',
              letterSpacing: '0.1em',
              color: 'var(--on-surface-variant)',
              opacity: 0.5,
            }}
          >
            Next
            <ArrowRight size={12} />
          </span>
          <span
            style={{
              fontSize: '0.875rem',
              fontWeight: 600,
              color: 'var(--primary)',
              fontFamily: 'var(--font-display)',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
              textAlign: 'right',
            }}
          >
            {next.title}
          </span>
        </Link>
      ) : (
        <div style={{ flex: '1 1 0' }} />
      )}
    </nav>
  );
}
