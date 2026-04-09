'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useState } from 'react';
import { X, Info, BookOpen, Terminal, Users, ChevronRight, Scroll } from 'lucide-react';

interface NavChild {
  label: string;
  href: string;
}

interface NavSection {
  label: string;
  href: string;
  icon: React.ElementType;
  children?: NavChild[];
}

const NAV: NavSection[] = [
  { label: 'Introduction', href: '/', icon: Info },
  {
    label: 'Concepts',
    href: '/concepts',
    icon: BookOpen,
    children: [
      { label: 'Design Principles',    href: '/concepts/design/principles' },
      { label: 'Why Kest?',            href: '/concepts/design/overview' },
      { label: 'Identity & Zero Trust',href: '/concepts/design/secret_zero' },
      { label: 'Merkle DAG Lineage',   href: '/concepts/design/merkle_dag' },
      { label: 'Audit Entry Schema',   href: '/concepts/design/audit_entry' },
      { label: 'Policy as Code',       href: '/concepts/design/abac_policy' },
      { label: 'Fail-Secure Edges',    href: '/concepts/design/edge_cases' },
    ],
  },
  { label: 'Specification', href: '/concepts/design/kest_spec_v0.3.0', icon: Scroll },
  {
    label: 'Developer Portal',
    href: '/developers',
    icon: Terminal,
    children: [
      { label: 'Guide Overview',       href: '/developers/guide/README' },
      { label: 'Getting Started',      href: '/developers/guide/getting_started' },
      { label: 'Decorators Reference', href: '/developers/guide/decorators' },
      { label: 'Middleware',           href: '/developers/guide/middleware' },
      { label: 'Trust Model',          href: '/developers/guide/trust_model' },
      { label: 'Identity & Context',   href: '/developers/guide/identity_context' },
      { label: 'Telemetry',            href: '/developers/guide/telemetry' },
      { label: 'Testing',              href: '/developers/guide/testing' },
      { label: 'Kest Lab',             href: '/developers/guide/kest_lab' },
      { label: 'Distributed Verif.',   href: '/developers/guide/distributed_verification' },
      { label: 'Gateway E2E',          href: '/developers/guide/gateway_e2e' },
    ],
  },
  { label: 'The Clowder', href: '/team', icon: Users },
];

export default function MobileDrawer({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const pathname = usePathname();

  const initialOpen = NAV.reduce<Record<string, boolean>>((acc, s) => {
    acc[s.href] =
      s.href === pathname ||
      (s.href !== '/' && pathname.startsWith(s.href));
    return acc;
  }, {});

  const [openSections, setOpenSections] = useState<Record<string, boolean>>(initialOpen);
  const toggle = (href: string) => setOpenSections((p) => ({ ...p, [href]: !p[href] }));

  if (!isOpen) return null;

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={onClose}
        style={{
          position: 'fixed', inset: 0,
          backgroundColor: 'rgba(0,0,0,0.5)',
          backdropFilter: 'blur(4px)',
          zIndex: 140,
        }}
      />

      {/* Drawer */}
      <aside style={{
        position: 'fixed', top: 0, left: 0, bottom: 0,
        width: '280px',
        backgroundColor: 'rgba(12, 19, 36, 0.92)',
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
        borderRight: '1px solid var(--outline-variant-ghost)',
        zIndex: 150,
        display: 'flex',
        flexDirection: 'column',
        boxShadow: 'var(--shadow-l4)',
        animation: 'slideIn 0.3s ease-out',
        overflowY: 'auto',
        scrollbarWidth: 'none',
      }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', padding: '2rem 1.5rem 1.5rem', alignItems: 'center' }}>
          <div>
            <h3 style={{ fontSize: '1.15rem', fontWeight: 800, margin: 0, color: 'var(--on-surface)', fontFamily: 'var(--font-display)' }}>
              <span className="gradient-text">Kest</span>
            </h3>
            <p style={{ fontSize: '0.6rem', color: 'var(--primary)', letterSpacing: '0.2em', textTransform: 'uppercase', fontStyle: 'italic', fontWeight: 700, marginTop: '0.15rem' }}>
              v0.3.0 Docs
            </p>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--on-surface-variant)', cursor: 'pointer' }}>
            <X size={22} />
          </button>
        </div>

        {/* Nav */}
        <nav style={{ display: 'flex', flexDirection: 'column', flex: 1 }}>
          {NAV.map((section) => {
            const isOpen = openSections[section.href] ?? false;
            const hasChildren = !!section.children?.length;
            const isSectionActive =
              pathname === section.href ||
              (section.href !== '/' && pathname.startsWith(section.href));

            return (
              <div key={section.href}>
                <div style={{ display: 'flex', alignItems: 'center' }}>
                  <Link
                    href={section.href}
                    onClick={onClose}
                    style={{
                      flex: 1,
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.875rem',
                      padding: '0.875rem 1.5rem',
                      fontSize: '0.875rem',
                      fontWeight: isSectionActive ? 700 : 500,
                      textTransform: 'uppercase',
                      letterSpacing: '0.06em',
                      color: isSectionActive ? 'var(--primary)' : 'var(--on-surface-variant)',
                      backgroundColor: isSectionActive ? 'rgba(79,70,229,0.08)' : 'transparent',
                      textDecoration: 'none',
                    }}
                  >
                    <section.icon size={17} />
                    <span>{section.label}</span>
                  </Link>

                  {hasChildren && (
                    <button
                      onClick={() => toggle(section.href)}
                      style={{
                        background: 'none', border: 'none', cursor: 'pointer',
                        padding: '0.875rem 1rem',
                        color: isSectionActive ? 'var(--primary)' : 'var(--on-surface-variant)',
                        opacity: 0.6,
                        display: 'flex', alignItems: 'center',
                      }}
                    >
                      <ChevronRight
                        size={15}
                        style={{
                          transform: isOpen ? 'rotate(90deg)' : 'rotate(0deg)',
                          transition: 'transform 0.2s ease',
                        }}
                      />
                    </button>
                  )}
                </div>

                {hasChildren && isOpen && (
                  <div style={{ paddingBottom: '0.5rem' }}>
                    {section.children!.map((child) => {
                      const isChildActive = pathname === child.href;
                      return (
                        <Link
                          key={child.href}
                          href={child.href}
                          onClick={onClose}
                          style={{
                            display: 'block',
                            padding: '0.5rem 1.5rem 0.5rem 3.5rem',
                            fontSize: '0.8rem',
                            color: isChildActive ? 'var(--primary)' : 'rgba(220,225,251,0.5)',
                            fontWeight: isChildActive ? 600 : 400,
                            borderLeft: isChildActive ? '2px solid var(--primary)' : '2px solid transparent',
                            marginLeft: '1rem',
                            textDecoration: 'none',
                            lineHeight: 1.5,
                          }}
                        >
                          {child.label}
                        </Link>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}
        </nav>

        <style>{`
          @keyframes slideIn {
            from { transform: translateX(-100%); }
            to   { transform: translateX(0); }
          }
        `}</style>
      </aside>
    </>
  );
}
