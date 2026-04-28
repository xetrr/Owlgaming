export function parseGameSizeGB(size: string): number {
  if (!size) return 0;
  const cleaned = size.toUpperCase().trim();
  const tbMatch = cleaned.match(/([\d.]+)\s*TB/);
  if (tbMatch) return parseFloat(tbMatch[1]) * 1024;
  const gbMatch = cleaned.match(/([\d.]+)\s*GB?/);
  if (gbMatch) return parseFloat(gbMatch[1]);
  const numMatch = cleaned.match(/([\d.]+)/);
  if (numMatch) return parseFloat(numMatch[1]);
  return 0;
}

export function roundUpGameSizeGB(size: string): number {
  return Math.ceil(parseGameSizeGB(size));
}

export function formatSizeDisplay(gb: number): string {
  if (gb >= 1024) return `${(gb / 1024).toFixed(1)}TB`;
  return `${gb}GB`;
}
