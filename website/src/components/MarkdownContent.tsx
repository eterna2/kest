import { compileContent } from '@/lib/mdx';
import CopyButton from './CopyButton';
import Mermaid from './Mermaid';

/**
 * Server-side markdown renderer using next-mdx-remote/rsc.
 *
 * Per DESIGN.md §5 Code Blocks:
 * - surface-container-lowest background (handled by globals.css .md-body pre)
 * - Glass header bar with language label + Copy action
 * - No border
 *
 * Mermaid code blocks (```mermaid) are rendered as interactive diagrams.
 * Tables are supported via remark-gfm.
 *
 * rehype-pretty-code adds:
 * - data-language attribute to <code> elements
 * - data-rehype-pretty-code-figure to wrapper <figure> elements
 * - Syntax-highlighted tokens as <span> elements
 */

// Extract raw text content from React children tree
function getTextContent(node: unknown): string {
  if (typeof node === 'string') return node;
  if (typeof node === 'number') return String(node);
  if (Array.isArray(node)) return node.map(getTextContent).join('');
  if (node && typeof node === 'object' && 'props' in node) {
    const el = node as { props: { children?: unknown } };
    return getTextContent(el.props.children);
  }
  return '';
}

// Custom pre component with glass header (DESIGN.md §5)
// Intercepts mermaid code blocks and renders them as diagrams
function Pre({ children, ...props }: React.ComponentPropsWithoutRef<'pre'>) {
  // Extract language from the code element's data-language attribute
  const codeElement = children as React.ReactElement<Record<string, unknown>>;
  const langAttr = codeElement?.props?.['data-language'];
  const language = typeof langAttr === 'string' ? langAttr : '';
  const rawCode = getTextContent(children);

  // Mermaid diagrams → render as interactive SVG
  if (language === 'mermaid') {
    return (
      <div className="code-block-wrapper">
        <div className="code-block-header">
          <span className="lang-label">diagram</span>
          <CopyButton text={rawCode} />
        </div>
        <Mermaid chart={rawCode} />
      </div>
    );
  }

  // Regular code blocks → glass header + syntax-highlighted pre
  return (
    <div className="code-block-wrapper">
      <div className="code-block-header">
        <span className="lang-label">{language}</span>
        <CopyButton text={rawCode} />
      </div>
      <pre {...props}>{children}</pre>
    </div>
  );
}

// Custom figure component for rehype-pretty-code figures
function Figure({ children, ...props }: React.ComponentPropsWithoutRef<'figure'>) {
  return <figure {...props}>{children}</figure>;
}

export default async function MarkdownContent({ content }: { content: string }) {
  const { content: renderedContent } = await compileContent(content, {
    pre: Pre,
    figure: Figure,
  });

  return (
    <div className="md-body">
      {renderedContent}
    </div>
  );
}
