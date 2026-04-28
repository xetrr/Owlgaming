const RAWG_KEY = process.env.RAWG_API_KEY || "";

export default async function handler(req: any, res: any) {
  try {
    res.setHeader("Access-Control-Allow-Origin", "*");
    if (req.method === "OPTIONS") return res.status(204).end();

    const override = req.headers?.["x-rawg-key"];
    const key = typeof override === "string" && override.length > 5 ? override : RAWG_KEY;

    if (!key) return res.status(200).json({ configured: false });

    const r = await fetch(`https://api.rawg.io/api/games?key=${key}&page_size=1`);
    if (!r.ok) return res.status(200).json({ configured: false });
    return res.status(200).json({ configured: true, override: !!override });
  } catch {
    return res.status(200).json({ configured: false });
  }
}
