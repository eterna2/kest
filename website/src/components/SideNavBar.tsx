"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import {
  Info,
  BookOpen,
  Terminal,
  Users,
  ExternalLink,
  ChevronRight,
  FileText,
  Scroll,
} from "lucide-react";

interface NavChild {
  label: string;
  href: string;
}

interface NavSection {
  label: string;
  href: string; // the section root — clicking this also navigates
  icon: React.ElementType;
  children?: NavChild[];
}

const NAV: NavSection[] = [
  {
    label: "Introduction",
    href: "/",
    icon: Info,
  },
  {
    label: "Specification",
    href: "/concepts/design/kest_spec_v0.3.0",
    icon: Scroll,
  },
  {
    label: "Concepts",
    href: "/concepts",
    icon: BookOpen,
    children: [
      { label: "Design Principles", href: "/concepts/design/principles" },
      { label: "Why Kest?", href: "/concepts/design/overview" },
      { label: "Identity & Zero Trust", href: "/concepts/design/secret_zero" },
      { label: "Merkle DAG Lineage", href: "/concepts/design/merkle_dag" },
      { label: "Audit Entry Schema", href: "/concepts/design/audit_entry" },
      { label: "Policy as Code", href: "/concepts/design/abac_policy" },
      { label: "Fail-Secure Edges", href: "/concepts/design/edge_cases" },
    ],
  },
  {
    label: "Developer Portal",
    href: "/developers",
    icon: Terminal,
    children: [
      { label: "Guide Overview", href: "/developers/guide/README" },
      { label: "Getting Started", href: "/developers/guide/getting_started" },
      { label: "Decorators Reference", href: "/developers/guide/decorators" },
      { label: "Middleware", href: "/developers/guide/middleware" },
      { label: "Trust Model", href: "/developers/guide/trust_model" },
      {
        label: "Identity & Context",
        href: "/developers/guide/identity_context",
      },
      { label: "Telemetry", href: "/developers/guide/telemetry" },
      { label: "Testing", href: "/developers/guide/testing" },
      { label: "Kest Lab", href: "/developers/guide/kest_lab" },
      { label: "Distributed Verification", href: "/developers/guide/distributed_verification" },
      { label: "Gateway E2E", href: "/developers/guide/gateway_e2e" },
    ],
  },
  {
    label: "The Clowder",
    href: "/team",
    icon: Users,
  },
];

export default function SideNavBar() {
  const pathname = usePathname();

  // Auto-expand whichever section is active
  const initialOpen = NAV.reduce<Record<string, boolean>>((acc, section) => {
    const isActive =
      section.href === pathname ||
      (section.children?.some((c) => c.href === pathname) ?? false) ||
      (section.href !== "/" && pathname.startsWith(section.href));
    acc[section.href] = isActive;
    return acc;
  }, {});

  const [openSections, setOpenSections] =
    useState<Record<string, boolean>>(initialOpen);

  const toggleSection = (href: string) =>
    setOpenSections((prev) => ({ ...prev, [href]: !prev[href] }));

  return (
    <aside
      className="hidden lg:flex"
      style={{
        position: "fixed",
        left: 0,
        top: "64px",
        width: "256px",
        height: "calc(100vh - 64px)",
        flexDirection: "column",
        overflowY: "auto",
        scrollbarWidth: "none",
        /* Glass Rule (DESIGN.md §2) */
        backgroundColor: "rgba(12, 19, 36, 0.4)",
        backdropFilter: "blur(20px)",
        WebkitBackdropFilter: "blur(20px)",
        borderRight: "1px solid var(--outline-variant-ghost)",
        zIndex: 90,
      }}
    >
      {/* Title block */}
      <div style={{ padding: "2rem 2rem 1.5rem" }}>
        <h3
          style={{
            fontSize: "1.0rem",
            fontWeight: 700,
            margin: 0,
            color: "var(--on-surface)",
            fontFamily: "var(--font-display)",
          }}
        >
          Documentation
        </h3>
        <p
          style={{
            fontSize: "0.6rem",
            color: "var(--primary)",
            letterSpacing: "0.1em",
            textTransform: "uppercase",
            marginTop: "0.25rem",
            opacity: 0.6,
          }}
        >
          v0.3.0
        </p>
      </div>

      {/* Nav sections */}
      <nav
        style={{
          display: "flex",
          flexDirection: "column",
          gap: "0.125rem",
          flex: 1,
        }}
      >
        {NAV.map((section) => {
          const isOpen = openSections[section.href] ?? false;
          const isRootActive = pathname === section.href;
          const hasChildren = !!section.children?.length;

          const isSectionActive =
            isRootActive ||
            !!(section.href !== "/" && pathname.startsWith(section.href));

          return (
            <div key={section.href}>
              {/* Section header row */}
              <div style={{ display: "flex", alignItems: "center" }}>
                <Link
                  href={section.href}
                  className={isSectionActive ? "active-pill" : ""}
                  style={{
                    flex: 1,
                    display: "flex",
                    alignItems: "center",
                    gap: "0.75rem",
                    padding: "0.625rem 2rem 0.625rem 1.5rem",
                    fontSize: "0.875rem",
                    color: isSectionActive
                      ? "var(--primary)"
                      : "var(--on-surface-variant)",
                    transition: "all 0.2s ease",
                    textDecoration: "none",
                    borderRadius: "0 8px 8px 0",
                  }}
                >
                  <section.icon size={16} />
                  <span>{section.label}</span>
                </Link>

                {/* Chevron toggle (only if section has children) */}
                {hasChildren && (
                  <button
                    onClick={() => toggleSection(section.href)}
                    style={{
                      background: "none",
                      border: "none",
                      cursor: "pointer",
                      padding: "0.625rem 1rem 0.625rem 0",
                      color: isSectionActive
                        ? "var(--primary)"
                        : "var(--on-surface-variant)",
                      opacity: 0.6,
                      display: "flex",
                      alignItems: "center",
                      transition: "transform 0.2s ease, opacity 0.2s",
                    }}
                    aria-label={isOpen ? "Collapse" : "Expand"}
                  >
                    <ChevronRight
                      size={14}
                      style={{
                        transform: isOpen ? "rotate(90deg)" : "rotate(0deg)",
                        transition: "transform 0.2s ease",
                      }}
                    />
                  </button>
                )}
              </div>

              {/* Child links */}
              {hasChildren && isOpen && (
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "0.0625rem",
                    paddingBottom: "0.5rem",
                  }}
                >
                  {section.children!.map((child) => {
                    const isChildActive = pathname === child.href;
                    return (
                      <Link
                        key={child.href}
                        href={child.href}
                        style={{
                          display: "block",
                          padding: "0.375rem 1rem 0.375rem 3.5rem",
                          fontSize: "0.775rem",
                          color: isChildActive
                            ? "var(--primary)"
                            : "rgba(220, 225, 251, 0.45)",
                          textDecoration: "none",
                          fontWeight: isChildActive ? 600 : 400,
                          borderLeft: isChildActive
                            ? "2px solid var(--primary)"
                            : "2px solid transparent",
                          marginLeft: "1.5rem",
                          transition: "all 0.15s ease",
                          borderRadius: "0 6px 6px 0",
                          lineHeight: 1.4,
                        }}
                        onMouseEnter={(e) => {
                          if (!isChildActive) {
                            (e.currentTarget as HTMLElement).style.color =
                              "rgba(220, 225, 251, 0.75)";
                          }
                        }}
                        onMouseLeave={(e) => {
                          if (!isChildActive) {
                            (e.currentTarget as HTMLElement).style.color =
                              "rgba(220, 225, 251, 0.45)";
                          }
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

      {/* Bottom actions */}
      <div
        style={{
          padding: "1.5rem",
          display: "flex",
          flexDirection: "column",
          gap: "0.75rem",
        }}
      >
        <Link
          href="/developers/guide/getting_started"
          className="btn-secondary"
          style={{
            width: "100%",
            fontSize: "0.7rem",
            padding: "0.75rem",
            letterSpacing: "0.1em",
            textTransform: "uppercase",
            fontWeight: 700,
            textAlign: "center",
            textDecoration: "none",
          }}
        >
          Get Started
        </Link>

        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: "0.5rem",
            marginTop: "0.5rem",
          }}
        >
          <a
            href="https://github.com/eterna2/kest/issues"
            target="_blank"
            rel="noreferrer"
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.5rem",
              fontSize: "0.7rem",
              color: "rgba(220, 225, 251, 0.35)",
              textDecoration: "none",
            }}
          >
            <ExternalLink size={13} /> <span>Support</span>
          </a>
          <a
            href="https://github.com/eterna2/kest/discussions"
            target="_blank"
            rel="noreferrer"
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.5rem",
              fontSize: "0.7rem",
              color: "rgba(220, 225, 251, 0.35)",
              textDecoration: "none",
            }}
          >
            <ExternalLink size={13} /> <span>Feedback</span>
          </a>
        </div>
      </div>
    </aside>
  );
}
