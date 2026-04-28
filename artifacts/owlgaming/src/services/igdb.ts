import { apiUrl } from "@/lib/api";

export interface IGDBGame {
  id: number;
  name: string;
  summary: string | null;
  rating: number | null;
  coverUrl: string | null;
  screenshots: string[];
  genres: string[];
  releaseYear: number | null;
  developers: string[];
  publishers: string[];
}

export const searchIGDBGame = async (name: string): Promise<IGDBGame | null> => {
  try {
    const res = await fetch(apiUrl(`/api/igdb/search?name=${encodeURIComponent(name)}`));
    if (!res.ok) {
      console.warn(`[igdb] search failed: HTTP ${res.status}`);
      return null;
    }
    const data = await res.json();
    if (!data?.data) {
      const status = res.headers.get("X-API-Status");
      if (status) console.warn(`[igdb] search returned no data:`, status);
    }
    return data.data ?? null;
  } catch (err) {
    console.warn(`[igdb] search threw:`, err);
    return null;
  }
};

export const getIGDBGameById = async (id: number): Promise<IGDBGame | null> => {
  try {
    const res = await fetch(apiUrl(`/api/igdb/${id}`));
    if (!res.ok) return null;
    const data = await res.json();
    return data.data ?? null;
  } catch {
    return null;
  }
};

export const getIGDBStatus = async (): Promise<{ configured: boolean; connected?: boolean }> => {
  try {
    const res = await fetch(apiUrl("/api/igdb/status"));
    if (!res.ok) return { configured: false };
    return res.json();
  } catch {
    return { configured: false };
  }
};
