import { Router, type IRouter } from "express";
import crypto from "node:crypto";
import healthRouter from "./health";
import { igdbSearchGame, igdbGetById, igdbStatus } from "./igdb";
import { rawgSearchGame, rawgGetById, rawgScreenshots, rawgMovies, rawgStatus } from "./rawg";
import { searchGames, getGameById, getPopularGames, getGameImages } from "./games-api";
import { getSiteSettings, saveSiteSettings } from "./site-settings";
import { requireAdmin, issueAdminToken, checkLogin, recordLoginResult } from "../lib/admin-auth";

const router: IRouter = Router();

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";

router.use(healthRouter);

// Admin auth — password lives only on the server.
router.post("/admin/verify", (req, res) => {
  if (!ADMIN_PASSWORD) {
    return res.status(503).json({ ok: false, error: "Admin auth not configured" });
  }
  const gate = checkLogin(req);
  if (!gate.allowed) {
    res.setHeader("Retry-After", String(gate.retryAfterSec ?? 900));
    return res.status(429).json({ ok: false, error: "Too many attempts. Try again later." });
  }
  const { password } = (req.body || {}) as { password?: string };
  if (!password || typeof password !== "string") {
    recordLoginResult(req, false);
    return res.status(400).json({ ok: false, error: "Password required" });
  }
  const a = Buffer.from(password);
  const b = Buffer.from(ADMIN_PASSWORD);
  const ok = a.length === b.length && crypto.timingSafeEqual(a, b);
  recordLoginResult(req, ok);
  if (!ok) {
    return res.status(401).json({ ok: false, error: "Invalid password" });
  }
  const token = issueAdminToken();
  return res.json({ ok: true, token });
});

// RAWG proxy — key never leaves the server
router.get("/rawg/status", rawgStatus);
router.get("/rawg/search", rawgSearchGame);
router.get("/rawg/:id/screenshots", rawgScreenshots);
router.get("/rawg/:id/movies", rawgMovies);
router.get("/rawg/:id", rawgGetById);

// SteamGridDB proxy routes
router.get("/games/search", searchGames);
router.get("/games/popular", getPopularGames);
router.get("/games/:gameId/images", getGameImages);
router.get("/games/:steamId", getGameById);

// IGDB proxy routes
router.get("/igdb/status", igdbStatus);
router.get("/igdb/search", igdbSearchGame);
router.get("/igdb/:id", igdbGetById);

// Site settings — read is public, writes require admin token
router.get("/site-settings", getSiteSettings);
router.post("/site-settings", requireAdmin, saveSiteSettings);

export default router;
