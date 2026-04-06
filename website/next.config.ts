import type { NextConfig } from "next";

// NEXT_PUBLIC_BASE_PATH is injected by CI for each deployment subfolder.
// e.g. /kest/stable, /kest/v0.3.0, /kest/preview/my-branch
// When running locally it is unset, so the app works at /.
const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? "";

const nextConfig: NextConfig = {
  output: "export",

  // basePath tells Next.js the sub-directory the app is mounted at.
  // All internal <Link> hrefs and router.push() calls are relative to this.
  basePath,

  // assetPrefix tells Next.js where to load _next/static/* chunks from.
  // Must match basePath for GitHub Pages subfolder deployments.
  assetPrefix: basePath,

  images: {
    unoptimized: true,
  },
};

export default nextConfig;
