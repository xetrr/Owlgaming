import crypto from "node:crypto";
import type { RequestHandler } from "express";

const TOKEN_TTL_MS = 1000 * 60 * 60 * 8; // 8 hours

function getSecret(): string | null {
  const pw = process.env.ADMIN_PASSWORD;
  if (!pw) return null;
  // Derive a stable per-deployment secret from the admin password so we
  // don't need an extra env var. Tokens auto-invalidate when password rotates.
  return crypto.createHash("sha256").update(`admin-token-v1:${pw}`).digest("hex");
}

function b64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function sign(payload: string, secret: string): string {
  return b64url(crypto.createHmac("sha256", secret).update(payload).digest());
}

export function issueAdminToken(): string | null {
  const secret = getSecret();
  if (!secret) return null;
  const expISO = new Date(Date.now() + TOKEN_TTL_MS).toISOString();
  const payload = b64url(Buffer.from(JSON.stringify({ exp: expISO })));
  const sig = sign(payload, secret);
  return `${payload}.${sig}`;
}

export function verifyAdminToken(token: string | undefined | null): boolean {
  if (!token || typeof token !== "string") return false;
  const secret = getSecret();
  if (!secret) return false;
  const parts = token.split(".");
  if (parts.length !== 2) return false;
  const [payload, sig] = parts;
  const expected = sign(payload, secret);
  // Constant-time compare
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  try {
    const json = JSON.parse(Buffer.from(payload.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
    if (typeof json?.exp !== "string") return false;
    return Date.parse(json.exp) > Date.now();
  } catch {
    return false;
  }
}

export const requireAdmin: RequestHandler = (req, res, next) => {
  const header = req.header("authorization") || "";
  const bearer = header.toLowerCase().startsWith("bearer ") ? header.slice(7).trim() : "";
  const token = bearer || (req.header("x-admin-token") || "").trim();
  if (!verifyAdminToken(token)) {
    res.status(401).json({ ok: false, error: "Unauthorized" });
    return;
  }
  next();
};

// ── Simple in-memory brute-force throttle (per IP) ─────────────────────
interface Attempt {
  count: number;
  firstMs: number;
  lockUntilMs: number;
}
const attempts = new Map<string, Attempt>();
const WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const MAX_ATTEMPTS = 5;
const LOCK_MS = 15 * 60 * 1000;

function clientIp(req: any): string {
  const xf = (req.headers["x-forwarded-for"] || "").toString().split(",")[0].trim();
  return xf || req.ip || req.socket?.remoteAddress || "unknown";
}

export function checkLogin(req: any): { allowed: boolean; retryAfterSec?: number } {
  const ip = clientIp(req);
  const now = Date.now();
  const a = attempts.get(ip);
  if (a && a.lockUntilMs > now) {
    return { allowed: false, retryAfterSec: Math.ceil((a.lockUntilMs - now) / 1000) };
  }
  return { allowed: true };
}

export function recordLoginResult(req: any, success: boolean) {
  const ip = clientIp(req);
  const now = Date.now();
  if (success) {
    attempts.delete(ip);
    return;
  }
  const a = attempts.get(ip);
  if (!a || now - a.firstMs > WINDOW_MS) {
    attempts.set(ip, { count: 1, firstMs: now, lockUntilMs: 0 });
    return;
  }
  a.count += 1;
  if (a.count >= MAX_ATTEMPTS) a.lockUntilMs = now + LOCK_MS;
}
