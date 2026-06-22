import { RequestHandler } from "express";

const RAWG_KEY = process.env.RAWG_API_KEY || "";
const BASE_URL = "https://api.rawg.io/api";

function getKey(req: import("express").Request): string {
  const override = req.headers["x-rawg-key"];
  if (typeof override === "string" && override.length > 5) return override;
  return RAWG_KEY;
}

export const rawgSearchGame: RequestHandler = async (req, res) => {
  const { name } = req.query;
  if (!name || typeof name !== "string") {
    res.status(400).json({ error: "name is required" });
    return;
  }
  const key = getKey(req);
  if (!key) {
    res.json({ data: null });
    return;
  }

  try {
    const r = await fetch(
      `${BASE_URL}/games?key=${key}&search=${encodeURIComponent(name)}&page_size=1`,
    );
    if (!r.ok) {
      res.json({ data: null });
      return;
    }
    const list = (await r.json()) as any;
    if (!list?.results?.length) {
      res.json({ data: null });
      return;
    }

    const id: number = list.results[0].id;
    const detail = await fetch(`${BASE_URL}/games/${id}?key=${key}`);
    if (!detail.ok) {
      res.json({ data: null });
      return;
    }
    const game = (await detail.json()) as any;
    res.json({ data: normalise(game) });
  } catch {
    res.status(500).json({ error: "RAWG fetch failed" });
  }
};

export const rawgGetById: RequestHandler = async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    res.status(400).json({ error: "Invalid game id" });
    return;
  }
  const key = getKey(req);
  if (!key) {
    res.json({ data: null });
    return;
  }

  try {
    const r = await fetch(`${BASE_URL}/games/${id}?key=${key}`);
    if (!r.ok) {
      res.status(r.status).json({ error: "Not found" });
      return;
    }
    const game = (await r.json()) as any;
    res.json({ data: normalise(game) });
  } catch {
    res.status(500).json({ error: "RAWG fetch failed" });
  }
};

export const rawgScreenshots: RequestHandler = async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    res.status(400).json({ error: "Invalid game id" });
    return;
  }
  const key = getKey(req);
  if (!key) {
    res.json({ data: [] });
    return;
  }

  try {
    const r = await fetch(`${BASE_URL}/games/${id}/screenshots?key=${key}`);
    if (!r.ok) {
      res.json({ data: [] });
      return;
    }
    const d = (await r.json()) as any;
    res.json({ data: (d?.results || []).map((s: { image: string }) => s.image) });
  } catch {
    res.status(500).json({ error: "RAWG fetch failed" });
  }
};

export const rawgMovies: RequestHandler = async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    res.status(400).json({ error: "Invalid game id" });
    return;
  }
  const key = getKey(req);
  if (!key) {
    res.json({ data: [] });
    return;
  }

  try {
    const r = await fetch(`${BASE_URL}/games/${id}/movies?key=${key}`);
    if (!r.ok) {
      res.json({ data: [] });
      return;
    }
    const d = (await r.json()) as any;
    res.json({ data: d?.results || [] });
  } catch {
    res.status(500).json({ error: "RAWG fetch failed" });
  }
};

export const rawgStatus: RequestHandler = async (req, res) => {
  const key = getKey(req);
  if (!key) {
    res.json({ configured: false });
    return;
  }
  try {
    const override = req.headers["x-rawg-key"];
    const r = await fetch(`${BASE_URL}/games?key=${key}&page_size=1`);
    if (!r.ok) {
      res.json({ configured: false });
      return;
    }
    res.json({ configured: true, override: !!(typeof override === "string" && override.length > 5) });
  } catch {
    res.json({ configured: false });
  }
};

function normalise(g: any) {
  const pcPlatform = (g.platforms || []).find(
    (p: any) => p.platform?.name === "PC",
  );
  const pcReqs = pcPlatform?.requirements ?? null;

  return {
    id: g.id,
    name: g.name,
    description_raw: g.description_raw || null,
    rating: g.rating || null,
    metacritic: g.metacritic || null,
    background_image: g.background_image || null,
    short_screenshots: g.short_screenshots || [],
    genres: g.genres || [],
    developers: g.developers || [],
    publishers: g.publishers || [],
    released: g.released || null,
    playtime: g.playtime || 0,
    pc_requirements: pcReqs
      ? {
          minimum: pcReqs.minimum || null,
          recommended: pcReqs.recommended || null,
        }
      : null,
  };
}
