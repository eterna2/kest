import Link from "next/link";
import { getAllPosts } from "@/lib/mdx";
import { Layers, Terminal, Shield, BookOpen } from "lucide-react";

// Blog category mapping: content dirs → display categories
const CATEGORIES = [
  {
    label: "Architecture",
    icon: Layers,
    dir: "design",
    slugs: [
      "principles",
      "overview",
      "secret_zero",
      "merkle_dag",
      "audit_entry",
      "abac_policy",
      "edge_cases",
      "kest_spec_v0.3.0",
    ],
  },
  {
    label: "Infrastructure",
    icon: Terminal,
    dir: "infra",
  },
  {
    label: "Assurance",
    icon: Shield,
    dir: "compliance",
  },
];

interface BlogPost {
  meta: { title: string; description: string; [key: string]: unknown };
  slug: string;
  sourceDir: string; // actual content directory for correct linking
}

function getCategoryPosts(cat: (typeof CATEGORIES)[number]): BlogPost[] {
  // Get all posts from the primary directory
  let posts = getAllPosts(cat.dir).map((p) => ({ ...p, sourceDir: cat.dir }));

  // If specific slugs are listed, filter to only those
  if (cat.slugs) {
    posts = posts.filter((p) => cat.slugs!.includes(p.slug));
  }


  return posts;
}

export default function BlogIndex() {
  const categories = CATEGORIES.map((cat) => ({
    ...cat,
    posts: getCategoryPosts(cat),
  }));

  // Pick the first post from the first category as featured
  const allPosts = categories.flatMap((c) =>
    c.posts.map((p) => ({ ...p, categoryLabel: c.label })),
  );
  const featuredPost = allPosts[0];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "5rem" }}>
      {/* Editorial Header */}
      <section>
        <span
          style={{
            fontSize: "0.75rem",
            fontWeight: 800,
            letterSpacing: "0.1em",
            color: "var(--primary)",
            textTransform: "uppercase",
          }}
        >
          Core Concepts
        </span>
        <h1
          style={{
            fontSize: "3.5rem",
            marginTop: "0.5rem",
            marginBottom: "2rem",
            fontFamily: "var(--font-display)",
          }}
        >
          Kest Conceptual <span className="gradient-text">Architecture</span>
        </h1>
      </section>

      {/* Featured Post */}
      {featuredPost && (
        <section
          style={{
            display: "grid",
            gridTemplateColumns: "3fr 2fr",
            gap: "2rem",
            backgroundColor: "var(--surface-container-low)",
            borderRadius: "var(--radius-xl)",
            overflow: "hidden",
            minHeight: "400px",
          }}
          className="kest-glow"
        >
          <div
            style={{
              position: "relative",
              backgroundColor: "var(--surface-container-highest)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <BookOpen
              size={64}
              style={{ color: "var(--primary)", opacity: 0.1 }}
            />
            <div
              style={{
                position: "absolute",
                inset: 0,
                background:
                  "linear-gradient(to right, transparent, var(--surface-container-low))",
              }}
            />
          </div>
          <div
            style={{
              padding: "3rem",
              display: "flex",
              flexDirection: "column",
              justifyContent: "center",
              gap: "1rem",
            }}
          >
            <span
              style={{
                fontSize: "0.625rem",
                fontWeight: 800,
                letterSpacing: "0.15em",
                color: "var(--primary)",
                textTransform: "uppercase",
              }}
            >
              Featured Post
            </span>
            <h2
              style={{
                fontSize: "2rem",
                margin: 0,
                fontFamily: "var(--font-display)",
              }}
            >
              {featuredPost.meta.title}
            </h2>
            <p
              style={{
                color: "var(--on-surface-variant)",
                fontSize: "1rem",
                lineHeight: 1.6,
              }}
            >
              {featuredPost.meta.description}
            </p>
            <Link
              href={`/concepts/${featuredPost.sourceDir}/${featuredPost.slug}`}
              className="btn-premium"
              style={{ width: "fit-content", marginTop: "1rem" }}
            >
              Read the Full Signal
            </Link>
          </div>
        </section>
      )}

      {/* 3-Column Grid */}
      <section
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))",
          gap: "3rem",
        }}
      >
        {categories.map((cat) => (
          <div
            key={cat.label}
            style={{ display: "flex", flexDirection: "column", gap: "2rem" }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "0.75rem",
                paddingBottom: "1rem",
                borderBottom: "1px solid rgba(195,192,255,0.04)",
              }}
            >
              <cat.icon size={20} style={{ color: "var(--primary)" }} />
              <h3
                style={{
                  fontSize: "1.25rem",
                  margin: 0,
                  fontFamily: "var(--font-display)",
                }}
              >
                {cat.label}
              </h3>
              <span
                style={{
                  fontSize: "0.65rem",
                  opacity: 0.3,
                  marginLeft: "auto",
                }}
              >
                {cat.posts.length}
              </span>
            </div>
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                gap: "1.5rem",
              }}
            >
              {cat.posts.map((post) => (
                <Link
                  key={`${post.sourceDir}-${post.slug}`}
                  href={`/concepts/${post.sourceDir}/${post.slug}`}
                  style={{ textDecoration: "none" }}
                >
                  <article
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      gap: "0.5rem",
                    }}
                  >
                    <h4
                      style={{
                        fontSize: "1.1rem",
                        margin: 0,
                        color: "var(--on-surface)",
                      }}
                    >
                      {post.meta.title}
                    </h4>
                    <p
                      style={{
                        fontSize: "0.875rem",
                        color: "var(--on-surface-variant)",
                        margin: 0,
                        opacity: 0.6,
                      }}
                    >
                      {post.meta.description}
                    </p>
                  </article>
                </Link>
              ))}
            </div>
          </div>
        ))}
      </section>
    </div>
  );
}
