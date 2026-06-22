import { Router, type IRouter } from "express";
import pg from "pg";
import { rateLimit } from "express-rate-limit";
import { requireAdmin } from "../lib/admin-auth";

const { Pool } = pg;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const router: IRouter = Router();

// Strict rate limiter for auth mutation endpoints (register, login, change-password)
const authMutationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many attempts. Please try again later." },
});

// ─── Input validation helpers ─────────────────────────────────────────────────

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

function validateStr(v: unknown, max: number): string | null {
  if (typeof v !== "string" || !v.trim()) return null;
  return v.trim().slice(0, max);
}

// ─── Session helper ───────────────────────────────────────────────────────────

function regenerateSession(req: any, newUserId: string): Promise<void> {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err: any) => {
      if (err) return reject(err);
      req.session.userId = newUserId;
      resolve();
    });
  });
}

// ─── Auth routes ──────────────────────────────────────────────────────────────

router.get("/auth/me", async (req, res) => {
  const userId = (req.session as any)?.userId;
  if (!userId) {
    res.json({ user: null });
    return;
  }
  try {
    const { rows } = await pool.query("SELECT id, username, email, created_at FROM users WHERE id = $1", [userId]);
    if (!rows.length) {
      (req.session as any).userId = undefined;
      res.json({ user: null });
      return;
    }
    res.json({ user: rows[0] });
  } catch {
    res.status(500).json({ error: "Failed to get user" });
  }
});

router.post("/auth/register", authMutationLimiter, async (req, res) => {
  const username = validateStr(req.body?.username, 50);
  const email = validateStr(req.body?.email, 254);
  const password = validateStr(req.body?.password, 128);

  if (!username || !email || !password) {
    res.status(400).json({ error: "username, email and password are required" });
    return;
  }
  if (!isValidEmail(email)) {
    res.status(400).json({ error: "Invalid email address" });
    return;
  }
  if ((req.body?.password as string).length < 6) {
    res.status(400).json({ error: "Password must be at least 6 characters" });
    return;
  }
  try {
    const bcrypt = await import("bcryptjs");
    const hash = await bcrypt.hash(password, 10);
    const id = crypto.randomUUID();
    const { rows } = await pool.query(
      "INSERT INTO users (id, username, email, password_hash) VALUES ($1, $2, $3, $4) RETURNING id, username, email, created_at",
      [id, username, email.toLowerCase(), hash]
    );
    await regenerateSession(req, rows[0].id);
    res.json({ user: rows[0] });
  } catch (err: any) {
    if (err?.code === "23505") {
      res.status(409).json({ error: "Email already registered" });
    } else {
      res.status(500).json({ error: "Failed to register" });
    }
  }
});

router.post("/auth/login", authMutationLimiter, async (req, res) => {
  const email = validateStr(req.body?.email, 254);
  const password = validateStr(req.body?.password, 128);

  if (!email || !password) {
    res.status(400).json({ error: "email and password are required" });
    return;
  }
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE email = $1", [email.toLowerCase()]);
    if (!rows.length) {
      res.status(401).json({ error: "Invalid login credentials" });
      return;
    }
    const bcrypt = await import("bcryptjs");
    const ok = await bcrypt.compare(password, rows[0].password_hash);
    if (!ok) {
      res.status(401).json({ error: "Invalid login credentials" });
      return;
    }
    await regenerateSession(req, rows[0].id);
    res.json({ user: { id: rows[0].id, username: rows[0].username, email: rows[0].email, created_at: rows[0].created_at } });
  } catch {
    res.status(500).json({ error: "Failed to login" });
  }
});

router.post("/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ ok: true });
  });
});

router.post("/auth/change-password", authMutationLimiter, async (req, res) => {
  const userId = (req.session as any)?.userId;
  if (!userId) { res.status(401).json({ error: "Not logged in" }); return; }

  const currentPassword = validateStr(req.body?.currentPassword, 128);
  const newPassword = validateStr(req.body?.newPassword, 128);

  if (!currentPassword || !newPassword) {
    res.status(400).json({ error: "currentPassword and newPassword required" }); return;
  }
  if ((req.body?.newPassword as string).length < 6) {
    res.status(400).json({ error: "New password must be at least 6 characters" }); return;
  }
  try {
    const bcrypt = await import("bcryptjs");
    const { rows } = await pool.query("SELECT password_hash FROM users WHERE id = $1", [userId]);
    if (!rows.length) { res.status(404).json({ error: "User not found" }); return; }
    const ok = await bcrypt.compare(currentPassword, rows[0].password_hash);
    if (!ok) { res.status(401).json({ error: "Current password is incorrect" }); return; }
    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query("UPDATE users SET password_hash = $1 WHERE id = $2", [hash, userId]);
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Failed to change password" });
  }
});

// ─── Favorites ────────────────────────────────────────────────────────────────

router.get("/favorites", async (req, res) => {
  const userId = (req.session as any)?.userId;
  if (!userId) { res.json({ data: [] }); return; }
  try {
    const { rows } = await pool.query("SELECT game_id FROM favorites WHERE user_id = $1", [userId]);
    res.json({ data: rows.map((r: any) => r.game_id) });
  } catch {
    res.status(500).json({ error: "Failed to get favorites" });
  }
});

router.post("/favorites/:gameId", async (req, res) => {
  const userId = (req.session as any)?.userId;
  if (!userId) { res.status(401).json({ error: "Not logged in" }); return; }
  const { gameId } = req.params;
  try {
    await pool.query(
      "INSERT INTO favorites (user_id, game_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
      [userId, gameId]
    );
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Failed to add favorite" });
  }
});

router.delete("/favorites/:gameId", async (req, res) => {
  const userId = (req.session as any)?.userId;
  if (!userId) { res.status(401).json({ error: "Not logged in" }); return; }
  const { gameId } = req.params;
  try {
    await pool.query("DELETE FROM favorites WHERE user_id = $1 AND game_id = $2", [userId, gameId]);
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Failed to remove favorite" });
  }
});

router.get("/favorites/games", async (req, res) => {
  const userId = (req.session as any)?.userId;
  if (!userId) { res.json({ data: [] }); return; }
  try {
    const { rows } = await pool.query(
      `SELECT g.* FROM games g
       INNER JOIN favorites f ON f.game_id = g.id
       WHERE f.user_id = $1
       ORDER BY f.created_at DESC`,
      [userId]
    );
    res.json({ data: rows });
  } catch {
    res.status(500).json({ error: "Failed to get favorite games" });
  }
});

// ─── Games (admin write, public read) ─────────────────────────────────────────

router.get("/store/games", async (_req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM games ORDER BY created_at DESC");
    res.json({ data: rows });
  } catch {
    res.status(500).json({ error: "Failed to get games" });
  }
});

router.post("/store/games", requireAdmin, async (req, res) => {
  const { id, name, size, source, genre } = req.body || {};
  const image_url = req.body?.image_url || `https://placehold.co/640x360/1a1d2e/a66cff?text=${encodeURIComponent(name || "")}`;
  if (!id || !name || !size) {
    res.status(400).json({ error: "id, name, size are required" });
    return;
  }
  try {
    const { rows } = await pool.query(
      "INSERT INTO games (id, name, image_url, size, source, genre) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
      [id, name, image_url, size, source || "", genre || ""]
    );
    res.json({ data: rows[0] });
  } catch (err: any) {
    if (err?.code === "23505") res.status(409).json({ error: "Game with this ID already exists" });
    else res.status(500).json({ error: "Failed to add game" });
  }
});

router.put("/store/games/:id", requireAdmin, async (req, res) => {
  const { name, image_url, size, source, genre } = req.body || {};
  try {
    const { rows } = await pool.query(
      "UPDATE games SET name=$1, image_url=$2, size=$3, source=$4, genre=$5 WHERE id=$6 RETURNING *",
      [name, image_url, size, source || "", genre || "", req.params.id]
    );
    if (!rows.length) res.status(404).json({ error: "Not found" });
    else res.json({ data: rows[0] });
  } catch {
    res.status(500).json({ error: "Failed to update game" });
  }
});

router.delete("/store/games/:id", requireAdmin, async (req, res) => {
  try {
    await pool.query("DELETE FROM games WHERE id=$1", [req.params.id]);
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Failed to delete game" });
  }
});

// ─── Hard Drives ──────────────────────────────────────────────────────────────

router.get("/store/hard-drives", async (_req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM hard_drives ORDER BY created_at DESC");
    res.json({ data: rows });
  } catch {
    res.status(500).json({ error: "Failed to get hard drives" });
  }
});

router.post("/store/hard-drives", requireAdmin, async (req, res) => {
  const { id, name, image_url, capacity, type, speed, price, description } = req.body || {};
  if (!id || !name || !image_url || !capacity || !type || !speed || !price) {
    res.status(400).json({ error: "Required fields missing" });
    return;
  }
  try {
    const { rows } = await pool.query(
      "INSERT INTO hard_drives (id, name, image_url, capacity, type, speed, price, description) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *",
      [id, name, image_url, capacity, type, speed, price, description || ""]
    );
    res.json({ data: rows[0] });
  } catch (err: any) {
    if (err?.code === "23505") res.status(409).json({ error: "Hard drive with this ID already exists" });
    else res.status(500).json({ error: "Failed to add hard drive" });
  }
});

router.put("/store/hard-drives/:id", requireAdmin, async (req, res) => {
  const { name, image_url, capacity, type, speed, price, description } = req.body || {};
  try {
    const { rows } = await pool.query(
      "UPDATE hard_drives SET name=$1, image_url=$2, capacity=$3, type=$4, speed=$5, price=$6, description=$7 WHERE id=$8 RETURNING *",
      [name, image_url, capacity, type, speed, price, description || "", req.params.id]
    );
    if (!rows.length) res.status(404).json({ error: "Not found" });
    else res.json({ data: rows[0] });
  } catch {
    res.status(500).json({ error: "Failed to update hard drive" });
  }
});

router.delete("/store/hard-drives/:id", requireAdmin, async (req, res) => {
  try {
    await pool.query("DELETE FROM hard_drives WHERE id=$1", [req.params.id]);
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Failed to delete hard drive" });
  }
});

// ─── Accessories ──────────────────────────────────────────────────────────────

router.get("/store/accessories", async (_req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM accessories ORDER BY created_at DESC");
    res.json({ data: rows });
  } catch {
    res.status(500).json({ error: "Failed to get accessories" });
  }
});

router.post("/store/accessories", requireAdmin, async (req, res) => {
  const { id, name, image_url, category, price, description } = req.body || {};
  if (!id || !name || !image_url || !category || !price) {
    res.status(400).json({ error: "Required fields missing" });
    return;
  }
  try {
    const { rows } = await pool.query(
      "INSERT INTO accessories (id, name, image_url, category, price, description) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *",
      [id, name, image_url, category, price, description || ""]
    );
    res.json({ data: rows[0] });
  } catch (err: any) {
    if (err?.code === "23505") res.status(409).json({ error: "Accessory with this ID already exists" });
    else res.status(500).json({ error: "Failed to add accessory" });
  }
});

router.put("/store/accessories/:id", requireAdmin, async (req, res) => {
  const { name, image_url, category, price, description } = req.body || {};
  try {
    const { rows } = await pool.query(
      "UPDATE accessories SET name=$1, image_url=$2, category=$3, price=$4, description=$5 WHERE id=$6 RETURNING *",
      [name, image_url, category, price, description || "", req.params.id]
    );
    if (!rows.length) res.status(404).json({ error: "Not found" });
    else res.json({ data: rows[0] });
  } catch {
    res.status(500).json({ error: "Failed to update accessory" });
  }
});

router.delete("/store/accessories/:id", requireAdmin, async (req, res) => {
  try {
    await pool.query("DELETE FROM accessories WHERE id=$1", [req.params.id]);
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Failed to delete accessory" });
  }
});

export default router;
