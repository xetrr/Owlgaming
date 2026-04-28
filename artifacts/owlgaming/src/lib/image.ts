/**
 * Optimize an image URL through wsrv.nl proxy.
 * Resizes, converts to WebP, and compresses for fast loading.
 */
export function optimizeImage(
  url: string,
  options: { w?: number; h?: number; q?: number } = {}
): string {
  if (!url || url.startsWith("data:")) return url;
  const { w = 400, q = 80 } = options;
  const params = new URLSearchParams({ url, w: String(w), q: String(q), output: "webp" });
  if (options.h) params.set("h", String(options.h));
  return `https://wsrv.nl/?${params.toString()}`;
}
