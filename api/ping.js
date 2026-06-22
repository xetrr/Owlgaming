module.exports = (_req, res) => {
  res.setHeader("Content-Type", "application/json");
  res.statusCode = 200;
  res.end(
    JSON.stringify({
      ok: true,
      time: new Date().toISOString(),
      node: process.version,
      hasRawgKey: !!process.env.RAWG_API_KEY,
      hasIgdbId: !!process.env.IGDB_CLIENT_ID,
      hasIgdbSecret: !!process.env.IGDB_CLIENT_SECRET,
    }),
  );
};
