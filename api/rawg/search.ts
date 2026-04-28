const ENV_KEY = process.env.RAWG_API_KEY || "";
const BASE_URL = "https://api.rawg.io/api";

function getKey(req: any): string {
  const override = req.headers?.["x-rawg-key"];
  if (typeof override === "string" && override.length > 5) return override;
  return ENV_KEY;
}

function normalise(g: any) {
  const pcPlatform = (g.platforms || []).find((p: any) => p.platform?.name === "PC");
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
      ? { minimum: pcReqs.minimum || null, recommended: pcReqs.recommended || null }
      : null,
  };
}

export default async function handler(req: any, res: any) {
  try {
    res.setHeader("Access-Control-Allow-Origin", "*");
    if (req.method === "OPTIONS") return res.status(204).end();

    const name = req.query?.name;
    if (!name || typeof name !== "string") {
      return res.status(400).json({ error: "name is required" });
    }

    const key = getKey(req);
    if (!key) {
      res.setHeader("X-API-Status", "missing-RAWG_API_KEY");
      return res.status(200).json({ data: null });
    }

    const listRes = await fetch(
      `${BASE_URL}/games?key=${key}&search=${encodeURIComponent(name)}&page_size=1`,
    );
    if (!listRes.ok) {
      res.setHeader("X-API-Status", `rawg-list-${listRes.status}`);
      return res.status(200).json({ data: null });
    }
    const list = (await listRes.json()) as any;
    if (!list?.results?.length) {
      res.setHeader("X-API-Status", "no-results");
      return res.status(200).json({ data: null });
    }

    const id: number = list.results[0].id;
    const detail = await fetch(`${BASE_URL}/games/${id}?key=${key}`);
    if (!detail.ok) {
      res.setHeader("X-API-Status", `rawg-detail-${detail.status}`);
      return res.status(200).json({ data: null });
    }
    return res.status(200).json({ data: normalise(await detail.json()) });
  } catch (err: any) {
    try {
      res.setHeader("X-API-Status", `crash-${(err?.name || "Error")}`);
    } catch {}
    return res.status(200).json({ data: null });
  }
}
