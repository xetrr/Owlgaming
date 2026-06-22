import crypto from "node:crypto";

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const TOKEN_TTL_MS = 1000 * 60 * 60 * 8;

function getSecret(): string | null {
  if (!ADMIN_PASSWORD) return null;
  return crypto
    .createHash("sha256")
    .update(`admin-token-v1:${ADMIN_PASSWORD}`)
    .digest("hex");
}

function b64url(buf: Buffer): string {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function sign(payload: string, secret: string): string {
  return b64url(
    crypto.createHmac("sha256", secret).update(payload).digest(),
  );
}

function issueToken(): string | null {
  const secret = getSecret();
  if (!secret) return null;
  const expISO = new Date(Date.now() + TOKEN_TTL_MS).toISOString();
  const payload = b64url(Buffer.from(JSON.stringify({ exp: expISO })));
  return `${payload}.${sign(payload, secret)}`;
}

interface Attempt {
  count: number;
  firstMs: number;
  lockUntilMs: number;
}
const attempts = new Map<string, Attempt>();
const WINDOW_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const LOCK_MS = 15 * 60 * 1000;

function clientIp(req: any): string {
  const xf = (req.headers?.["x-forwarded-for"] || "")
    .toString()
    .split(",")[0]
    .trim();
  return xf || req.socket?.remoteAddress || "unknown";
}

function checkLogin(req: any): { allowed: boolean; retryAfterSec?: number } {
  const ip = clientIp(req);
  const now = Date.now();
  const a = attempts.get(ip);
  if (a && a.lockUntilMs > now) {
    return {
      allowed: false,
      retryAfterSec: Math.ceil((a.lockUntilMs - now) / 1000),
    };
  }
  return { allowed: true };
}

function recordLoginResult(req: any, success: boolean) {
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

async function readBody(req: any): Promise<any> {
  if (req.body && typeof req.body === "object") return req.body;
  if (typeof req.body === "string") {
    try {
      return JSON.parse(req.body);
    } catch {
      return {};
    }
  }
  return await new Promise((resolve) => {
    let data = "";
    req.on("data", (c: any) => (data += c));
    req.on("end", () => {
      try {
        resolve(JSON.parse(data || "{}"));
      } catch {
        resolve({});
      }
    });
    req.on("error", () => resolve({}));
  });
}

export default async function handler(req: any, res: any) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, error: "Method not allowed" });
  }

  if (!ADMIN_PASSWORD) {
    return res
      .status(503)
      .json({ ok: false, error: "Admin auth not configured" });
  }

  const gate = checkLogin(req);
  if (!gate.allowed) {
    res.setHeader("Retry-After", String(gate.retryAfterSec ?? 900));
    return res
      .status(429)
      .json({ ok: false, error: "Too many attempts. Try again later." });
  }

  const body = await readBody(req);
  const password = body?.password;
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

  const token = issueToken();
  return res.status(200).json({ ok: true, token });
}
