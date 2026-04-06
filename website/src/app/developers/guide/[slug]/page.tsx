import { getPost, getFiles } from "@/lib/mdx";
import MarkdownContent from "@/components/MarkdownContent";
import { notFound } from "next/navigation";
import Link from "next/link";

export function generateStaticParams() {
  return getFiles("developer").map((f) => ({ slug: f.replace(/\.md$/, "") }));
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
          <p
            style={{
              fontSize: "1.25rem",
              color: "var(--on-surface-variant)",
              lineHeight: 1.6,
            }}
          >
            {post.meta.description}
          </p>
        </div>
        <MarkdownContent content={post.content} currentDir="developer" />
      </article>
    </div>
  );
}
