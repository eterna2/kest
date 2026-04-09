import { compileContent } from '@/lib/mdx';
import { prefixPath } from '@/lib/utils';
import ExpandableCode from './ExpandableCode';
import Mermaid from './Mermaid';
import ExpandableImage from './ExpandableImage';

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
 * Images are expandable — click to open in a full-viewport lightbox.
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

  // Mermaid diagrams → render as interactive SVG, wrapped in ExpandableCode header
  if (language === 'mermaid') {
    return (
      <ExpandableCode language="diagram" rawCode={rawCode} noPreWrapper>
        <Mermaid chart={rawCode} />
      </ExpandableCode>
    );
  }

  // Regular code blocks → glass header + expand + copy + syntax-highlighted pre
  return (
    <ExpandableCode language={language} rawCode={rawCode} preProps={props}>
      {children}
    </ExpandableCode>
  );
}

// Custom figure component for rehype-pretty-code figures
function Figure({ children, ...props }: React.ComponentPropsWithoutRef<'figure'>) {
  return <figure {...props}>{children}</figure>;
}

// Custom table component — wraps in a scrollable div so IDs/index never wrap
function Table({ children, ...props }: React.ComponentPropsWithoutRef<'table'>) {
  return (
    <div className="table-scroll">
      <table {...props}>{children}</table>
    </div>
  );
}

// Custom img component — renders as ExpandableImage (click to zoom in lightbox)
function Img(props: React.ImgHTMLAttributes<HTMLImageElement>) {
  const { src, alt, ...rest } = props;
  const resolvedSrc = typeof src === 'string' && src.startsWith('/') ? prefixPath(src) : src;
  return (
    <ExpandableImage
      src={resolvedSrc}
      alt={alt || ''}
      {...rest}
      style={{
        maxWidth: '100%',
        height: 'auto',
        maxHeight: '520px',
        display: 'block',
        borderRadius: '12px',
        margin: '2rem auto',
        objectFit: 'contain',
      }}
    />
  );
}

// Custom anchor component to prefix basePath for internal links in markdown content.
// MDX renders markdown links as raw <a> tags, not Next.js <Link> components,
// so they don't automatically receive the basePath prefix.
function Anchor(props: React.AnchorHTMLAttributes<HTMLAnchorElement>) {
  const { href, ...rest } = props;
  const resolvedHref = typeof href === 'string' && href.startsWith('/') && !href.startsWith('//') ? prefixPath(href) : href;
  return <a href={resolvedHref} {...rest} />;
}

// Builds a H1 component that suppresses the FIRST h1 only (used when the
// page template already renders the title from frontmatter to prevent duplication)
function makeSuppressedH1() {
  let seen = false;
  return function H1({ children, ...props }: React.ComponentPropsWithoutRef<'h1'>) {
    if (!seen) {
      seen = true;
      return null; // swallow the first h1
    }
    return <h1 {...props}>{children}</h1>;
  };
}

export default async function MarkdownContent({
  content,
  currentDir,
  suppressFirstH1 = false,
}: {
  content: string;
  currentDir?: string;
  suppressFirstH1?: boolean;
}) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const components: Record<string, React.ComponentType<any>> = {
    pre: Pre,
    figure: Figure,
    table: Table,
    img: Img,
    a: Anchor,
  };

  if (suppressFirstH1) {
    components.h1 = makeSuppressedH1();
  }

  const { content: renderedContent } = await compileContent(content, components, currentDir);

  return (
    <div className="md-body">
      {renderedContent}
    </div>
  );
}
