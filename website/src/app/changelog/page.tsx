import fs from 'fs';
import path from 'path';
import MarkdownContent from '@/components/MarkdownContent';
import { BookOpen } from 'lucide-react';
import Link from 'next/link';

/**
 * Reads CHANGELOG.md directly from the project root at build time.
 * When the site is rebuilt, any changes to the source file are automatically reflected.
 */
function getChangelog(): string {
  // Walk up from website/ to the monorepo root
  const changelogPath = path.join(process.cwd(), '..', 'CHANGELOG.md');
  if (!fs.existsSync(changelogPath)) {
    return '# Changelog\n\nNo changelog found.';
  }
  return fs.readFileSync(changelogPath, 'utf8');
}

export default async function ChangelogPage() {
  const content = getChangelog();

  return (
    <div style={{ maxWidth: '800px' }}>
      {/* Breadcrumb */}
      <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', marginBottom: '2rem', fontSize: '0.8rem', opacity: 0.5 }}>
        <Link href="/" style={{ color: 'inherit' }}>Home</Link>
        <span>/</span>
        <span style={{ color: 'var(--primary)' }}>Changelog</span>
      </div>

      {/* Header */}
      <div style={{ marginBottom: '3rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1rem' }}>
          <BookOpen size={28} style={{ color: 'var(--primary)' }} />
          <h1 style={{ margin: 0, fontSize: '2.5rem', fontFamily: 'var(--font-display)' }}>
            <span className="gradient-text">Changelog</span>
          </h1>
        </div>
        <p style={{ fontSize: '1.1rem', color: 'var(--on-surface-variant)', lineHeight: 1.6 }}>
          All notable changes to the Kest toolkit, automatically synced from the source repository.
        </p>
      </div>

      {/* Rendered markdown */}
      <article className="md-body">
        <MarkdownContent content={content} />
      </article>
    </div>
  );
}
