const ENV_KEY = process.env.RAWG_API_KEY || "";
const BASE_URL = "https://api.rawg.io/api";

function getKey(req: any): string {
  const override = req.headers?.["x-rawg-key"];
  if (typeof override === "string" && override.length > 5) return override;
  return ENV_KEY;
}

export default async function handler(req: any, res: any) {
  try {
    res.setHeader("Access-Control-Allow-Origin", "*");
    if (req.method === "OPTIONS") return res.status(204).end();

    const id = Number(req.query?.id);
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ error: "Invalid game id" });
    }

    const key = getKey(req);
    if (!key) {
      res.setHeader("X-API-Status", "missing-RAWG_API_KEY");
      return res.status(200).json({ data: [] });
    }

    const r = await fetch(`${BASE_URL}/games/${id}/screenshots?key=${key}`);
    if (!r.ok) {
      res.setHeader("X-API-Status", `rawg-${r.status}`);
      return res.status(200).json({ data: [] });
    }
    const d = (await r.json()) as any;
    return res
      .status(200)
      .json({ data: (d?.results || []).map((s: { image: string }) => s.image) });
  } catch (err: any) {
    try {
      res.setHeader("X-API-Status", `crash-${(err?.name || "Error")}`);
    } catch {}
    return res.status(200).json({ data: [] });
  }
}
