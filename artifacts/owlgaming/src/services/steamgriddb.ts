import { apiUrl } from "@/lib/api";

const API_BASE = apiUrl("/api/games");

export interface SteamGame {
  id: string;
  title: string;
  size: string;
  downloads: number;
  price: number;
  image: string;
  steamId?: number;
  releaseDate?: string;
  developers?: string[];
}

export const searchGamesByName = async (query: string): Promise<SteamGame[]> => {
  try {
    const response = await fetch(`${API_BASE}/search?query=${encodeURIComponent(query)}`);
    if (!response.ok) throw new Error(`API error: ${response.status}`);
    const data = await response.json();
    return data.data || [];
  } catch (error) {
    console.error("Error searching games:", error);
    return [];
  }
};

export const searchGameBySteamID = async (gameId: number): Promise<SteamGame | null> => {
  try {
    const response = await fetch(`${API_BASE}/${gameId}`);
    if (!response.ok) return null;
    const data = await response.json();
    return data.data || null;
  } catch (error) {
    console.error("Error fetching game from SteamGridDB:", error);
    return null;
  }
};

export const getPopularGames = async (): Promise<SteamGame[]> => {
  try {
    const response = await fetch(`${API_BASE}/popular`);
    if (!response.ok) throw new Error(`API error: ${response.status}`);
    const data = await response.json();
    return data.data || [];
  } catch (error) {
    console.error("Error fetching popular games:", error);
    return [];
  }
};

export const getGameImages = async (gameId: number): Promise<{ grids: any[]; heroes: any[]; logos: any[] }> => {
  try {
    const response = await fetch(`${API_BASE}/${gameId}/images`);
    if (!response.ok) return { grids: [], heroes: [], logos: [] };
    const data = await response.json();
    return data.data || { grids: [], heroes: [], logos: [] };
  } catch (error) {
    console.error("Error fetching game images:", error);
    return { grids: [], heroes: [], logos: [] };
  }
};
