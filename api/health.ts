export default function handler(_req: any, res: any) {
  res.setHeader("Content-Type", "application/json");
  res.status(200).end(
    JSON.stringify({
      ok: true,
      time: new Date().toISOString(),
      hasRawgKey: !!process.env.RAWG_API_KEY,
      hasIgdbId: !!process.env.IGDB_CLIENT_ID,
      hasIgdbSecret: !!process.env.IGDB_CLIENT_SECRET,
      node: process.version,
    }),
  );
}
