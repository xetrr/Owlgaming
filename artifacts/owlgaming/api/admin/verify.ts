import type { VercelRequest, VercelResponse } from "@vercel/node";
import crypto from "crypto";

export default function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const { password } = req.body ?? {};
  const adminPassword = process.env.ADMIN_PASSWORD;

  if (!adminPassword) {
    return res.status(503).json({ error: "Admin password not configured" });
  }

  if (
    typeof password !== "string" ||
    !password ||
    password !== adminPassword
  ) {
    return res.status(401).json({ error: "Invalid password" });
  }

  const token = crypto.randomBytes(32).toString("hex");
  return res.status(200).json({ token });
}
