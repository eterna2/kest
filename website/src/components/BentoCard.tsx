import Link from 'next/link';

interface BentoCardProps {
  title: string;
  description: string;
  href: string;
  icon?: React.ReactNode;
  tag?: string;
  className?: string;
  style?: React.CSSProperties;
}

export default function BentoCard({ title, description, href, icon, tag, className = '', style }: BentoCardProps) {
  return (
    <Link href={href} className={`bento-card kest-glow ${className}`} style={style}>
      <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
        {tag && (
          <span style={{ 
            fontSize: '0.625rem', 
            textTransform: 'uppercase', 
            letterSpacing: '0.15em', 
            color: 'var(--primary)', 
            marginBottom: '1rem',
            fontWeight: 800
          }}>
            {tag}
          </span>
        )}
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
          <h3 style={{ fontSize: '1.5rem', margin: 0, lineHeight: 1.1 }}>{title}</h3>
          {icon && <div style={{ color: 'var(--primary)', opacity: 0.8 }}>{icon}</div>}
        </div>
        <p style={{ 
          fontSize: '0.875rem', 
          color: 'var(--on-surface-variant)', 
          margin: 0, 
          lineHeight: 1.6,
          opacity: 0.7 
        }}>
          {description}
        </p>
        <div style={{ marginTop: 'auto', paddingTop: '2rem' }}>
          <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--primary)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            Explore <span style={{ fontSize: '1.1rem' }}>→</span>
          </span>
        </div>
      </div>
    </Link>
  );
}
