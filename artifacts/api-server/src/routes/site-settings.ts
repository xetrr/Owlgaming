import { RequestHandler } from "express";
import fs from "node:fs";
import path from "node:path";
import { z } from "zod";

const SETTINGS_FILE = path.join(process.cwd(), ".data", "site-settings.json");

// Allow strings/numbers/booleans/null and one level of objects/arrays of those.
const Primitive = z.union([z.string().max(5000), z.number(), z.boolean(), z.null()]);
const SettingValue = z.union([
  Primitive,
  z.array(Primitive).max(200),
  z.record(Primitive),
]);
const SettingsSchema = z.record(SettingValue).refine(
  (obj) => Object.keys(obj).length <= 200,
  { message: "Too many settings keys" }
);

function ensureDir() {
  const dir = path.dirname(SETTINGS_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

export const getSiteSettings: RequestHandler = (_req, res) => {
  try {
    ensureDir();
    if (fs.existsSync(SETTINGS_FILE)) {
      const raw = fs.readFileSync(SETTINGS_FILE, "utf-8");
      res.json({ ok: true, data: JSON.parse(raw) });
    } else {
      res.json({ ok: true, data: null });
    }
  } catch {
    res.status(500).json({ ok: false, error: "Failed to read settings" });
  }
};

export const saveSiteSettings: RequestHandler = (req, res) => {
  try {
    const parsed = SettingsSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ ok: false, error: "Invalid settings payload" });
      return;
    }
    ensureDir();
    const existing = fs.existsSync(SETTINGS_FILE)
      ? JSON.parse(fs.readFileSync(SETTINGS_FILE, "utf-8"))
      : {};
    const merged = { ...existing, ...parsed.data };
    fs.writeFileSync(SETTINGS_FILE, JSON.stringify(merged, null, 2), "utf-8");
    res.json({ ok: true });
  } catch {
    res.status(500).json({ ok: false, error: "Failed to save settings" });
  }
};
