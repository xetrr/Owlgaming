import { apiUrl } from "@/lib/api";

export const LS_RAWG_KEY = "gh_rawg_key";

const getOverrideKey = (): string => {
  try { return localStorage.getItem(LS_RAWG_KEY) || ""; } catch { return ""; }
};

const rawgHeaders = (): HeadersInit => {
  const key = getOverrideKey();
  return key ? { "X-RAWG-Key": key } : {};
};

export interface RAWGGame {
  id: number;
  name: string;
  description_raw: string;
  rating: number;
  metacritic: number | null;
  background_image: string;
  short_screenshots: { id: number; image: string }[];
  genres: { id: number; name: string }[];
  developers: { id: number; name: string }[];
  publishers: { id: number; name: string }[];
  released: string;
  playtime: number;
  pc_requirements: {
    minimum: string | null;
    recommended: string | null;
  } | null;
}

export interface RAWGMovie {
  id: number;
  name: string;
  preview: string;
  data: { "480": string; max: string };
}

export const searchGameByName = async (name: string): Promise<RAWGGame | null> => {
  try {
    const res = await fetch(apiUrl(`/api/rawg/search?name=${encodeURIComponent(name)}`), { headers: rawgHeaders() });
    if (!res.ok) {
      console.warn(`[rawg] search failed: HTTP ${res.status}`);
      return null;
    }
    const data = await res.json();
    if (!data?.data) {
      const status = res.headers.get("X-API-Status");
      if (status) console.warn(`[rawg] search returned no data:`, status);
    }
    return data.data ?? null;
  } catch (err) {
    console.warn(`[rawg] search threw:`, err);
    return null;
  }
};

export const getRAWGGameById = async (id: number): Promise<RAWGGame | null> => {
  try {
    const res = await fetch(apiUrl(`/api/rawg/${id}`), { headers: rawgHeaders() });
    if (!res.ok) return null;
    const data = await res.json();
    return data.data ?? null;
  } catch {
    return null;
  }
};

export const getGameScreenshots = async (id: number): Promise<string[]> => {
  try {
    const res = await fetch(apiUrl(`/api/rawg/${id}/screenshots`), { headers: rawgHeaders() });
    if (!res.ok) return [];
    const data = await res.json();
    return data.data ?? [];
  } catch {
    return [];
  }
};

export const getGameMovies = async (id: number): Promise<RAWGMovie[]> => {
  try {
    const res = await fetch(apiUrl(`/api/rawg/${id}/movies`), { headers: rawgHeaders() });
    if (!res.ok) return [];
    const data = await res.json();
    return data.data ?? [];
  } catch {
    return [];
  }
};

export const getRawgStatus = async (): Promise<{ configured: boolean; override?: boolean }> => {
  try {
    const res = await fetch(apiUrl("/api/rawg/status"), { headers: rawgHeaders() });
    if (!res.ok) return { configured: false };
    return res.json();
  } catch {
    return { configured: false };
  }
};
