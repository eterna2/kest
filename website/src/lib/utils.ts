/**
 * Prefixes a given path with the Next.js basePath if it's set.
 *
 * In Next.js, Image components using string src do not automatically
 * prefix the basePath. This utility ensures that static assets
 * (like hero images and team avatars) are correctly resolved when
 * the application is hosted in a sub-folder (e.g., /kest/stable).
 */
export function prefixPath(path: string): string {
  const basePath = process.env.NEXT_PUBLIC_BASE_PATH || "";
  // Ensure we don't double up on slashes and that we handle relative paths
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  return `${basePath}${normalizedPath}`;
}
