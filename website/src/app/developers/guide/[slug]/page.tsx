import { getPost, getAllPosts } from "@/lib/mdx";
import MarkdownContent from "@/components/MarkdownContent";
import PageNavigation from "@/components/PageNavigation";
import { notFound } from "next/navigation";
import Link from "next/link";

export function generateStaticParams() {
  return getAllPosts("developer").map((p) => ({ slug: p.slug }));
}

export default async function GuidePage({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  const post = getPost("developer", slug);

  if (!post) {
    return notFound();
  }

  const allPosts = getAllPosts("developer");
  const currentIndex = allPosts.findIndex((p) => p.slug === slug);
  const prev = currentIndex > 0 ? allPosts[currentIndex - 1] : null;
  const next = currentIndex < allPosts.length - 1 ? allPosts[currentIndex + 1] : null;

  return (
    <div className="detail-layout">
      <article className="md-body">
        <div style={{ marginBottom: "3rem" }}>
          <div
            style={{
              display: "flex",
              gap: "1rem",
              alignItems: "center",
              marginBottom: "1.5rem",
              fontSize: "0.8rem",
              opacity: 0.5,
            }}
          >
            <Link href="/developers" style={{ color: "inherit" }}>
              Portal
            </Link>
            <span>/</span>
            <Link href="/developers/guide" style={{ color: "inherit" }}>
              Guide
            </Link>
            <span>/</span>
            <span style={{ color: "var(--primary)" }}>{post.meta.title}</span>
          </div>
          <h1>{post.meta.title}</h1>
          {post.meta.description && (post.meta as Record<string, unknown>)._fromFrontmatter && (
            <p
              style={{
                fontSize: "1.25rem",
                color: "var(--on-surface-variant)",
                lineHeight: 1.6,
              }}
            >
              {post.meta.description}
            </p>
          )}
        </div>
        <MarkdownContent content={post.content} currentDir="developer" suppressFirstH1 />
        <PageNavigation
          prev={prev ? { slug: prev.slug, title: prev.meta.title } : null}
          next={next ? { slug: next.slug, title: next.meta.title } : null}
          basePath="/developers/guide"
        />
      </article>
    </div>
  );
}
