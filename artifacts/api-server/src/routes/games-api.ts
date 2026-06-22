import { RequestHandler } from "express";

const API_BASE = "https://www.steamgriddb.com/api/v2";

async function fetchGridImage(gameId: number): Promise<string | null> {
  try {
    const r = await fetch(`${API_BASE}/grids/game/${gameId}`);
    if (!r.ok) return null;
    const d = (await r.json()) as any;
    return d?.data?.[0]?.thumb ?? null;
  } catch {
    return null;
  }
}

export const searchGames: RequestHandler = async (req, res) => {
  const { query } = req.query;
  if (!query || typeof query !== "string") {
    res.status(400).json({ error: "Query parameter required" });
    return;
  }

  try {
    const response = await fetch(
      `${API_BASE}/search/autocomplete/${encodeURIComponent(query)}`,
    );
    if (!response.ok) {
      res.status(response.status).json({ error: "SteamGridDB API error" });
      return;
    }
    const data = (await response.json()) as any;
    const results = (data?.data || []).slice(0, 10);

    const games = await Promise.all(
      results.map(async (result: any) => {
        const imageUrl =
          (await fetchGridImage(result.id)) ??
          `https://placehold.co/400x225?text=${encodeURIComponent(result.name)}`;
        return {
          id: result.id.toString(),
          title: result.name,
          size: "60GB",
          image: imageUrl,
          steamId: result.id,
          releaseDate: result.release_date,
        };
      }),
    );

    res.json({ data: games });
  } catch {
    res.status(500).json({ error: "Failed to search games" });
  }
};

export const getGameById: RequestHandler = async (req, res) => {
  const steamId = String(req.params.steamId ?? "");
  if (!/^\d+$/.test(steamId)) {
    res.status(400).json({ error: "Invalid Steam ID" });
    return;
  }

  try {
    const response = await fetch(`${API_BASE}/games/id/${steamId}`);
    if (!response.ok) {
      res.status(response.status).json({ error: "Game not found" });
      return;
    }
    const data = (await response.json()) as any;
    if (!data?.data) {
      res.status(404).json({ error: "Game not found" });
      return;
    }
    const game = data.data;
    const imageUrl =
      (await fetchGridImage(game.id)) ??
      `https://placehold.co/400x225?text=${encodeURIComponent(game.name)}`;

    res.json({
      data: {
        id: game.id.toString(),
        title: game.name,
        size: "60GB",
        image: imageUrl,
        steamId: game.id,
        releaseDate: game.release_date,
        developers: game.developers || [],
      },
    });
  } catch {
    res.status(500).json({ error: "Failed to fetch game" });
  }
};

export const getPopularGames: RequestHandler = async (_req, res) => {
  const popularSteamIds = [
    730, 570, 271590, 202990, 8980, 221100, 108600, 1817070, 1086940, 1172380,
  ];

  try {
    const games = (
      await Promise.all(
        popularSteamIds.map(async (steamId) => {
          try {
            const gameRes = await fetch(`${API_BASE}/games/id/${steamId}`);
            if (!gameRes.ok) return null;
            const gameData = (await gameRes.json()) as any;
            if (!gameData?.data) return null;
            const game = gameData.data;
            const imageUrl =
              (await fetchGridImage(game.id)) ??
              `https://placehold.co/400x225?text=${encodeURIComponent(game.name)}`;
            return {
              id: game.id.toString(),
              title: game.name,
              size: "60GB",
              image: imageUrl,
              steamId: game.id,
              releaseDate: game.release_date,
              developers: game.developers || [],
            };
          } catch {
            return null;
          }
        }),
      )
    ).filter(Boolean);

    res.json({ data: games });
  } catch {
    res.status(500).json({ error: "Failed to fetch popular games" });
  }
};

export const getGameImages: RequestHandler = async (req, res) => {
  const gameId = String(req.params.gameId ?? "");
  if (!/^\d+$/.test(gameId)) {
    res.status(400).json({ error: "Invalid game ID" });
    return;
  }

  try {
    const [gridsRes, heroesRes, logosRes] = await Promise.all([
      fetch(`${API_BASE}/grids/game/${gameId}`).catch(() => null),
      fetch(`${API_BASE}/heroes/game/${gameId}`).catch(() => null),
      fetch(`${API_BASE}/logos/game/${gameId}`).catch(() => null),
    ]);

    const grids = gridsRes?.ok ? ((await gridsRes.json()) as any).data ?? [] : [];
    const heroes = heroesRes?.ok ? ((await heroesRes.json()) as any).data ?? [] : [];
    const logos = logosRes?.ok ? ((await logosRes.json()) as any).data ?? [] : [];

    res.json({ data: { grids, heroes, logos } });
  } catch {
    res.status(500).json({ error: "Failed to fetch game images" });
  }
};
