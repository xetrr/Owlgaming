const CLIENT_ID = process.env.IGDB_CLIENT_ID || "";
const CLIENT_SECRET = process.env.IGDB_CLIENT_SECRET || "";

let cachedToken: string | null = null;
let tokenExpiry = 0;

async function getAccessToken(): Promise<string | null> {
  if (!CLIENT_ID || !CLIENT_SECRET) return null;
  if (cachedToken && Date.now() < tokenExpiry) return cachedToken;
  try {
    const res = await fetch(
      `https://id.twitch.tv/oauth2/token?client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&grant_type=client_credentials`,
      { method: "POST" },
    );
    if (!res.ok) return null;
    const data = (await res.json()) as { access_token: string; expires_in: number };
    cachedToken = data.access_token;
    tokenExpiry = Date.now() + (data.expires_in - 60) * 1000;
    return cachedToken;
  } catch {
    return null;
  }
}

async function igdbPost(endpoint: string, query: string): Promise<any | null> {
  const token = await getAccessToken();
  if (!token) return null;
  try {
    const res = await fetch(`https://api.igdb.com/v4/${endpoint}`, {
      method: "POST",
      headers: {
        "Client-ID": CLIENT_ID,
        Authorization: `Bearer ${token}`,
        "Content-Type": "text/plain",
      },
      body: query,
    });
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

function normaliseGame(g: any) {
  const coverUrl = g.cover?.url
    ? `https:${g.cover.url.replace("t_thumb", "t_cover_big")}`
    : null;
  const screenshots: string[] = (g.screenshots || [])
    .slice(0, 8)
    .map((s: any) => `https:${s.url.replace("t_thumb", "t_screenshot_big")}`);
  const developers = (g.involved_companies || [])
    .filter((c: any) => c.developer)
    .map((c: any) => c.company?.name)
    .filter(Boolean);
  const publishers = (g.involved_companies || [])
    .filter((c: any) => c.publisher)
    .map((c: any) => c.company?.name)
    .filter(Boolean);
  const releaseYear = g.first_release_date
    ? new Date(g.first_release_date * 1000).getFullYear()
    : null;
  return {
    id: g.id,
    name: g.name,
    summary: g.summary || null,
    rating: g.rating ? Math.round(g.rating) / 20 : null,
    coverUrl,
    screenshots,
    genres: (g.genres || []).map((genre: any) => genre.name),
    releaseYear,
    developers,
    publishers,
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
    if (!CLIENT_ID || !CLIENT_SECRET) {
      res.setHeader("X-API-Status", "missing-IGDB-credentials");
      return res.status(200).json({ data: null });
    }

    const data = await igdbPost(
      "games",
      `fields name,summary,rating,screenshots.url,cover.url,genres.name,first_release_date,involved_companies.company.name,involved_companies.developer,involved_companies.publisher;
       search "${name.replace(/"/g, "")}";
       limit 1;`,
    );
    if (!data || !data.length) {
      res.setHeader("X-API-Status", "no-results-or-token-failed");
      return res.status(200).json({ data: null });
    }
    return res.status(200).json({ data: normaliseGame(data[0]) });
  } catch (err: any) {
    try {
      res.setHeader("X-API-Status", `crash-${(err?.name || "Error")}`);
    } catch {}
    return res.status(200).json({ data: null });
  }
}
