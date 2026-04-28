import { useState, useEffect, useRef } from "react";
import {
  Plus, Pencil, Trash2, LogOut, Shield, CheckCircle,
  AlertCircle, Loader2, ExternalLink, Copy, Check,
  HardDrive as HardDriveIcon, Upload, Download, X, FileSpreadsheet, Home, RotateCcw, Save,
  Key, Eye, EyeOff, RefreshCw, Server, Package, DollarSign,
  Palette,
} from "lucide-react";
import { apiUrl } from "@/lib/api";
import { usePricing } from "@/hooks/usePricing";
import { getIGDBStatus } from "@/services/igdb";
import { getRawgStatus, LS_RAWG_KEY } from "@/services/rawg";
import { useHomeContent } from "@/hooks/useHomeContent";
import { useContactInfo, DEFAULT_CONTACT, type BusinessHour } from "@/hooks/useContactInfo";
import { useBrand } from "@/hooks/useBrand";
type XLSXModule = typeof import("xlsx");
const loadXLSX = (): Promise<XLSXModule> => import("xlsx");
import {
  Game, getGames, addGame, updateGame, deleteGame,
  HardDrive, getHardDrives, addHardDrive, updateHardDrive, deleteHardDrive,
  Accessory, getAccessories, addAccessory, updateAccessory, deleteAccessory,
  isSupabaseConfigured,
} from "@/lib/supabase";


const SQL_SETUP = `-- Run this in your Supabase SQL Editor (Dashboard → SQL Editor → New query)

-- Games table
CREATE TABLE IF NOT EXISTS games (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  image_url TEXT NOT NULL,
  size TEXT NOT NULL,
  source TEXT DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT NOW()
);
ALTER TABLE games ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Public read" ON games FOR SELECT USING (true);
CREATE POLICY "Public write" ON games FOR ALL USING (true);

-- Hard Drives table
CREATE TABLE IF NOT EXISTS hard_drives (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  image_url TEXT NOT NULL,
  capacity TEXT NOT NULL,
  type TEXT NOT NULL,
  speed TEXT NOT NULL,
  price TEXT NOT NULL,
  description TEXT DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT NOW()
);
ALTER TABLE hard_drives ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Public read hd" ON hard_drives FOR SELECT USING (true);
CREATE POLICY "Public write hd" ON hard_drives FOR ALL USING (true);

-- Accessories table
CREATE TABLE IF NOT EXISTS accessories (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  image_url TEXT NOT NULL,
  category TEXT NOT NULL,
  price TEXT NOT NULL,
  description TEXT DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT NOW()
);
ALTER TABLE accessories ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Public read acc" ON accessories FOR SELECT USING (true);
CREATE POLICY "Public write acc" ON accessories FOR ALL USING (true);

-- Site Settings table (stores home page images, contact info, etc.)
CREATE TABLE IF NOT EXISTS site_settings (
  key TEXT PRIMARY KEY,
  value JSONB NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);
ALTER TABLE site_settings ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Public read settings" ON site_settings FOR SELECT USING (true);
CREATE POLICY "Public write settings" ON site_settings FOR ALL USING (true);

-- Favorites table (requires Supabase Auth to be enabled)
CREATE TABLE IF NOT EXISTS favorites (
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  game_id TEXT REFERENCES games(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (user_id, game_id)
);
ALTER TABLE favorites ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users manage own favorites" ON favorites FOR ALL USING (auth.uid() = user_id);`;

const EMPTY_GAME_FORM = { id: "", name: "", image_url: "", size: "", source: "" };
const EMPTY_HD_FORM = { id: "", name: "", image_url: "", capacity: "", type: "HDD", speed: "", price: "", description: "" };
const EMPTY_ACC_FORM = { id: "", name: "", image_url: "", category: "Controllers", price: "", description: "" };

const ACC_CATEGORIES = ["Controllers", "Headsets", "Keyboards", "Mice", "Monitors", "Chairs", "Mousepads", "Cables & Adapters", "Other"];

type AdminTab = "games" | "hard_drives" | "accessories" | "setup" | "home" | "api_keys" | "contact" | "pricing" | "brand";

// ─── API Keys Tab Component ───────────────────────────────────────────────────

const LS = {
  sbUrl: "gh_supabase_url",
  sbKey: "gh_supabase_key",
};

function ApiKeysTab({ onFlash }: { onFlash: (msg: string, type: "success" | "error") => void }) {
  const readLS = (k: string) => { try { return localStorage.getItem(k) || ""; } catch { return ""; } };

  const [sbUrl, setSbUrl] = useState(readLS(LS.sbUrl));
  const [sbKey, setSbKey] = useState(readLS(LS.sbKey));
  const [showSbKey, setShowSbKey] = useState(false);
  const [saved, setSaved] = useState(false);
  const [igdbStatus, setIgdbStatus] = useState<{ configured: boolean; connected?: boolean } | null>(null);

  const [rawgKey, setRawgKey] = useState(readLS(LS_RAWG_KEY));
  const [showRawgKey, setShowRawgKey] = useState(false);
  const [rawgStatus, setRawgStatus] = useState<{ configured: boolean; override?: boolean } | null>(null);
  const [rawgTesting, setRawgTesting] = useState(false);

  useEffect(() => {
    getIGDBStatus().then(setIgdbStatus);
    getRawgStatus().then(setRawgStatus);
  }, []);

  const saveKeys = () => {
    try {
      if (sbUrl.trim()) localStorage.setItem(LS.sbUrl, sbUrl.trim()); else localStorage.removeItem(LS.sbUrl);
      if (sbKey.trim()) localStorage.setItem(LS.sbKey, sbKey.trim()); else localStorage.removeItem(LS.sbKey);
      if (rawgKey.trim()) localStorage.setItem(LS_RAWG_KEY, rawgKey.trim()); else localStorage.removeItem(LS_RAWG_KEY);
      setSaved(true);
      onFlash("Keys saved — reload the page to apply them", "success");
      setTimeout(() => setSaved(false), 3000);
    } catch {
      onFlash("Failed to save keys", "error");
    }
  };

  const clearKey = (which: "sbUrl" | "sbKey") => {
    if (which === "sbUrl") { localStorage.removeItem(LS.sbUrl); setSbUrl(""); }
    if (which === "sbKey") { localStorage.removeItem(LS.sbKey); setSbKey(""); }
    onFlash("Key cleared — using environment variable fallback", "success");
  };

  const testRawgKey = async () => {
    const toTest = rawgKey.trim();
    if (!toTest) { onFlash("Enter a RAWG API key first", "error"); return; }
    setRawgTesting(true);
    try {
      localStorage.setItem(LS_RAWG_KEY, toTest);
      const status = await getRawgStatus();
      setRawgStatus(status);
      if (status.configured) {
        onFlash("RAWG key is valid and connected!", "success");
      } else {
        onFlash("RAWG key test failed — check the key and try again", "error");
      }
    } finally {
      setRawgTesting(false);
    }
  };

  const Field = ({
    label, sublabel, value, onChange, show, onToggleShow, placeholder, onClear,
  }: {
    label: string; sublabel: string; value: string; onChange: (v: string) => void;
    show?: boolean; onToggleShow?: () => void; placeholder?: string; onClear: () => void;
  }) => (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-bold text-foreground">{label}</p>
          <p className="text-xs text-foreground/50">{sublabel}</p>
        </div>
        {value && (
          <button onClick={onClear} className="text-xs text-destructive/70 hover:text-destructive transition-colors">
            Clear (use env)
          </button>
        )}
      </div>
      <div className="relative">
        <input
          type={show === false ? "password" : "text"}
          value={value}
          onChange={e => onChange(e.target.value)}
          placeholder={placeholder || "Paste your key here…"}
          className="w-full pl-4 pr-10 py-2.5 bg-muted border border-border rounded-xl text-foreground placeholder:text-foreground/30 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-primary/50"
        />
        {onToggleShow && (
          <button
            type="button"
            onClick={onToggleShow}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-foreground/40 hover:text-foreground transition-colors"
          >
            {show ? <Eye className="w-4 h-4" /> : <EyeOff className="w-4 h-4" />}
          </button>
        )}
      </div>
    </div>
  );

  return (
    <div className="max-w-2xl space-y-8">
      <div>
        <h2 className="text-2xl font-bold mb-1 flex items-center gap-2">
          <Key className="w-6 h-6 text-primary" />API Keys
        </h2>
        <p className="text-foreground/60 text-sm">
          Override the Supabase connection without touching the code. Keys are stored in your browser and take effect after a page reload.
        </p>
      </div>

      {/* RAWG */}
      <div className="bg-card border border-border rounded-2xl p-6 space-y-4">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h3 className="text-sm font-bold text-foreground/50 uppercase tracking-wider">RAWG.io — Game Data API</h3>
            <p className="text-xs text-foreground/40 mt-1">
              Powers game previews, screenshots, ratings, and descriptions. Free tier at{" "}
              <a href="https://rawg.io/apidocs" target="_blank" rel="noopener noreferrer"
                className="text-primary hover:underline inline-flex items-center gap-1">
                rawg.io/apidocs <ExternalLink className="w-3 h-3" />
              </a>
            </p>
          </div>
          {rawgStatus === null ? (
            <Loader2 className="w-4 h-4 animate-spin text-foreground/40 flex-shrink-0 mt-0.5" />
          ) : rawgStatus.configured ? (
            <span className="flex items-center gap-1 text-xs font-bold text-green-400 bg-green-500/10 border border-green-500/30 px-2.5 py-1 rounded-lg flex-shrink-0">
              <CheckCircle className="w-3.5 h-3.5" />Connected{rawgStatus.override ? " (override)" : ""}
            </span>
          ) : (
            <span className="flex items-center gap-1 text-xs font-bold text-foreground/40 bg-muted border border-border px-2.5 py-1 rounded-lg flex-shrink-0">
              <AlertCircle className="w-3.5 h-3.5" />Not Set
            </span>
          )}
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-bold text-foreground">API Key</p>
              <p className="text-xs text-foreground/50">
                Browser-stored override — takes effect immediately without redeploying.
                Leave blank to use the <code className="bg-muted px-1 rounded text-[11px]">RAWG_API_KEY</code> environment variable.
              </p>
            </div>
            {rawgKey && (
              <button
                onClick={() => { localStorage.removeItem(LS_RAWG_KEY); setRawgKey(""); onFlash("RAWG key cleared — using env variable", "success"); }}
                className="text-xs text-destructive/70 hover:text-destructive transition-colors flex-shrink-0 ml-4"
              >
                Clear (use env)
              </button>
            )}
          </div>
          <div className="relative">
            <input
              type={showRawgKey ? "text" : "password"}
              value={rawgKey}
              onChange={e => setRawgKey(e.target.value)}
              placeholder="Paste your RAWG API key here…"
              className="w-full pl-4 pr-10 py-2.5 bg-muted border border-border rounded-xl text-foreground placeholder:text-foreground/30 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-primary/50"
            />
            <button
              type="button"
              onClick={() => setShowRawgKey(!showRawgKey)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-foreground/40 hover:text-foreground transition-colors"
            >
              {showRawgKey ? <Eye className="w-4 h-4" /> : <EyeOff className="w-4 h-4" />}
            </button>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={testRawgKey}
            disabled={rawgTesting || !rawgKey.trim()}
            className="flex items-center gap-2 px-4 py-2 bg-muted border border-border hover:border-primary/50 text-foreground/70 hover:text-foreground font-medium rounded-xl text-sm transition-all disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {rawgTesting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
            Test Connection
          </button>
          <p className="text-xs text-foreground/40">Verifies the key by making a live request to RAWG</p>
        </div>

        <div className="bg-muted/60 border border-border rounded-xl p-4 space-y-2.5 text-xs text-foreground/60">
          <p className="font-bold text-foreground/70 flex items-center gap-1.5"><Package className="w-3.5 h-3.5" />How to get a free RAWG API key</p>
          <ol className="space-y-1.5 list-decimal list-inside leading-relaxed">
            <li>Go to <a href="https://rawg.io/apidocs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">rawg.io/apidocs</a> and create a free account</li>
            <li>In your RAWG dashboard, find the <strong className="text-foreground/80">API key</strong> section</li>
            <li>Copy the key, paste it into the field above, and click <strong className="text-foreground/80">Test Connection</strong></li>
            <li>Once verified, click <strong className="text-foreground/80">Save Keys</strong> below — game info will load immediately</li>
          </ol>
        </div>
      </div>

      {/* Supabase */}
      <div className="bg-card border border-border rounded-2xl p-6 space-y-4">
        <h3 className="text-sm font-bold text-foreground/50 uppercase tracking-wider">Supabase — Database</h3>
        <p className="text-xs text-foreground/40">Used to store games, hard drives, and user favorites. Free at supabase.com</p>
        <Field
          label="Supabase Project URL"
          sublabel="Found in your Supabase project Settings → API"
          value={sbUrl}
          onChange={setSbUrl}
          placeholder="https://xxxx.supabase.co"
          onClear={() => clearKey("sbUrl")}
        />
        <Field
          label="Supabase Anon Key"
          sublabel="The public anon key from Settings → API"
          value={sbKey}
          onChange={setSbKey}
          show={showSbKey}
          onToggleShow={() => setShowSbKey(!showSbKey)}
          onClear={() => clearKey("sbKey")}
        />
      </div>

      {/* IGDB */}
      <div className="bg-card border border-border rounded-2xl p-6 space-y-4">
        <h3 className="text-sm font-bold text-foreground/50 uppercase tracking-wider">IGDB — Internet Game Database</h3>
        <p className="text-xs text-foreground/40">
          Used alongside RAWG for additional game info, screenshots, and metadata. Powered by Twitch — credentials are configured server-side for security.
        </p>
        <div className="flex items-center gap-3 px-4 py-3 bg-muted border border-border rounded-xl">
          <Server className="w-4 h-4 text-foreground/50 flex-shrink-0" />
          <div className="flex-1">
            <p className="text-sm font-semibold text-foreground">Server-side credentials</p>
            <p className="text-xs text-foreground/50">IGDB Client ID and Client Secret are stored as environment secrets — they never reach the browser.</p>
          </div>
          {igdbStatus === null ? (
            <Loader2 className="w-4 h-4 animate-spin text-foreground/40" />
          ) : igdbStatus.configured && igdbStatus.connected ? (
            <span className="flex items-center gap-1 text-xs font-bold text-green-400 bg-green-500/10 border border-green-500/30 px-2.5 py-1 rounded-lg">
              <CheckCircle className="w-3.5 h-3.5" />Connected
            </span>
          ) : igdbStatus.configured ? (
            <span className="flex items-center gap-1 text-xs font-bold text-yellow-400 bg-yellow-500/10 border border-yellow-500/30 px-2.5 py-1 rounded-lg">
              <AlertCircle className="w-3.5 h-3.5" />Configured
            </span>
          ) : (
            <span className="flex items-center gap-1 text-xs font-bold text-foreground/40 bg-muted border border-border px-2.5 py-1 rounded-lg">
              <AlertCircle className="w-3.5 h-3.5" />Not Set
            </span>
          )}
        </div>
        <button
          onClick={() => getIGDBStatus().then(setIgdbStatus)}
          className="flex items-center gap-2 text-xs text-foreground/50 hover:text-foreground transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />Re-check IGDB connection
        </button>
      </div>

      {/* Save */}
      <div className="flex gap-3 items-center">
        <button
          onClick={saveKeys}
          className="flex items-center gap-2 px-6 py-2.5 bg-primary hover:bg-primary/90 text-primary-foreground font-bold rounded-xl text-sm transition-all"
        >
          {saved ? <Check className="w-4 h-4" /> : <Save className="w-4 h-4" />}
          {saved ? "Saved!" : "Save Keys"}
        </button>
        <button
          onClick={() => window.location.reload()}
          className="flex items-center gap-2 px-5 py-2.5 bg-muted border border-border hover:border-primary/50 text-foreground/70 hover:text-foreground font-medium rounded-xl text-sm transition-all"
        >
          <RefreshCw className="w-4 h-4" />
          Reload Page to Apply
        </button>
      </div>

      <div className="flex items-start gap-3 px-4 py-3 bg-amber-500/10 border border-amber-500/30 rounded-xl text-amber-400 text-sm">
        <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
        <div>
          <p className="font-bold mb-0.5">How it works</p>
          <p className="text-amber-400/70 text-xs leading-relaxed">
            Keys you enter here are saved in your browser's local storage. They override the default environment keys without needing a code change or redeploy.
            After saving, click "Reload Page" for the new keys to take effect. If a field is empty, the original environment variable key is used as a fallback.
          </p>
        </div>
      </div>
    </div>
  );
}

interface ImportRow {
  id: string;
  name: string;
  image_url: string;
  size: string;
  source: string;
  _valid: boolean;
  _error: string;
}

export default function Admin() {
  const [authed, setAuthed] = useState(false);
  const [passwordInput, setPasswordInput] = useState("");
  const [passwordError, setPasswordError] = useState(false);
  const [authLoading, setAuthLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<AdminTab>(isSupabaseConfigured ? "games" : "setup");

  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Games state
  const [games, setGames] = useState<Game[]>([]);
  const [gamesLoading, setGamesLoading] = useState(false);
  const [gameForm, setGameForm] = useState(EMPTY_GAME_FORM);
  const [editingGameId, setEditingGameId] = useState<string | null>(null);
  const [showGameForm, setShowGameForm] = useState(false);
  const [gameSaving, setGameSaving] = useState(false);

  // Excel import state
  const [importRows, setImportRows] = useState<ImportRow[]>([]);
  const [showImportModal, setShowImportModal] = useState(false);
  const [importing, setImporting] = useState(false);
  const [importProgress, setImportProgress] = useState({ done: 0, total: 0, errors: 0 });
  const [importDone, setImportDone] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Hard drives state
  const [drives, setDrives] = useState<HardDrive[]>([]);
  const [drivesLoading, setDrivesLoading] = useState(false);
  const [driveForm, setDriveForm] = useState(EMPTY_HD_FORM);
  const [editingDriveId, setEditingDriveId] = useState<string | null>(null);
  const [showDriveForm, setShowDriveForm] = useState(false);
  const [driveSaving, setDriveSaving] = useState(false);

  // Accessories state
  const [accessories, setAccessories] = useState<Accessory[]>([]);
  const [accsLoading, setAccsLoading] = useState(false);
  const [accForm, setAccForm] = useState(EMPTY_ACC_FORM);
  const [editingAccId, setEditingAccId] = useState<string | null>(null);
  const [showAccForm, setShowAccForm] = useState(false);
  const [accSaving, setAccSaving] = useState(false);

  // Home content state
  const { content: homeContent, updateContent: updateHome, resetContent: resetHome } = useHomeContent();
  const { brand, updateBrand, resetBrand } = useBrand();

  // Contact info state
  const { info: contactInfo, updateInfo: updateContact, resetInfo: resetContact } = useContactInfo();

  // Pricing state
  const { pricing, updatePricing, resetPricing } = usePricing();

  const flash = (msg: string, type: "success" | "error") => {
    if (type === "success") { setSuccess(msg); setTimeout(() => setSuccess(null), 4000); }
    else { setError(msg); setTimeout(() => setError(null), 5000); }
  };

  const loadGames = async () => {
    if (!isSupabaseConfigured) return;
    setGamesLoading(true);
    try { setGames(await getGames()); } catch { flash("Failed to load games", "error"); }
    finally { setGamesLoading(false); }
  };

  const loadDrives = async () => {
    if (!isSupabaseConfigured) return;
    setDrivesLoading(true);
    try { setDrives(await getHardDrives()); } catch { flash("Failed to load hard drives", "error"); }
    finally { setDrivesLoading(false); }
  };

  const loadAccessories = async () => {
    if (!isSupabaseConfigured) return;
    setAccsLoading(true);
    try { setAccessories(await getAccessories()); } catch { flash("Failed to load accessories", "error"); }
    finally { setAccsLoading(false); }
  };

  useEffect(() => {
    if (authed && isSupabaseConfigured) { loadGames(); loadDrives(); loadAccessories(); }
  }, [authed]);

  const handleLogin = async () => {
    setAuthLoading(true);
    setPasswordError(false);
    try {
      const res = await fetch(apiUrl("/api/admin/verify"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: passwordInput }),
      });
      if (res.ok) {
        try {
          const data = await res.json();
          if (data?.token) sessionStorage.setItem("gh_admin_token", data.token);
        } catch {}
        setAuthed(true);
      } else {
        setPasswordError(true);
      }
    } catch {
      setPasswordError(true);
    } finally {
      setAuthLoading(false);
    }
  };

  // Game CRUD
  const handleGameSave = async () => {
    if (!gameForm.id.trim() || !gameForm.name.trim() || !gameForm.image_url.trim() || !gameForm.size.trim()) {
      flash("ID, name, image URL, and size are required", "error"); return;
    }
    setGameSaving(true);
    try {
      if (editingGameId) {
        await updateGame(editingGameId, { name: gameForm.name, image_url: gameForm.image_url, size: gameForm.size, source: gameForm.source });
        flash("Game updated!", "success");
      } else {
        await addGame({ id: gameForm.id, name: gameForm.name, image_url: gameForm.image_url, size: gameForm.size, source: gameForm.source });
        flash("Game added!", "success");
      }
      setGameForm(EMPTY_GAME_FORM); setShowGameForm(false); setEditingGameId(null);
      await loadGames();
    } catch (e: any) { flash(e.message || "Failed to save game", "error"); }
    finally { setGameSaving(false); }
  };

  const handleGameEdit = (game: Game) => {
    setGameForm({ id: game.id, name: game.name, image_url: game.image_url, size: game.size, source: game.source || "" });
    setEditingGameId(game.id); setShowGameForm(true);
  };

  const handleGameDelete = async (id: string, name: string) => {
    if (!confirm(`Delete "${name}"? This cannot be undone.`)) return;
    try { await deleteGame(id); flash("Game deleted", "success"); await loadGames(); }
    catch { flash("Failed to delete", "error"); }
  };

  // ─── Excel Import ────────────────────────────────────────────────────────────

  const downloadTemplate = async () => {
    const XLSX = await loadXLSX();
    const ws = XLSX.utils.aoa_to_sheet([
      ["id", "name", "image_url", "size", "source"],
      ["red-dead-redemption-2", "Red Dead Redemption 2", "https://example.com/rdr2.jpg", "120GB", "FitGirl"],
      ["elden-ring", "Elden Ring", "https://example.com/elden.jpg", "60GB", "DODI"],
      ["cyberpunk-2077", "Cyberpunk 2077", "https://example.com/cp77.jpg", "130GB", ""],
    ]);

    ws["!cols"] = [
      { wch: 30 }, { wch: 30 }, { wch: 50 }, { wch: 10 }, { wch: 20 },
    ];

    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, "Games");
    XLSX.writeFile(wb, "PixelPC_Games_Template.xlsx");
  };

  const slugify = (str: string) =>
    str.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

  const parseExcelFile = (file: File) => {
    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const XLSX = await loadXLSX();
        const data = new Uint8Array(e.target!.result as ArrayBuffer);
        const wb = XLSX.read(data, { type: "array" });
        const ws = wb.Sheets[wb.SheetNames[0]];
        const raw: any[] = XLSX.utils.sheet_to_json(ws, { defval: "" });

        if (raw.length === 0) {
          flash("The file is empty or has no data rows", "error"); return;
        }

        const rows: ImportRow[] = raw.map((row, i) => {
          const name = String(row["name"] || row["Name"] || row["NAME"] || "").trim();
          const rawId = String(row["id"] || row["ID"] || row["Id"] || "").trim();
          const id = rawId || slugify(name);
          const image_url = String(row["image_url"] || row["Image URL"] || row["image"] || row["Image"] || "").trim();
          const size = String(row["size"] || row["Size"] || row["SIZE"] || "").trim();
          const source = String(row["source"] || row["Source"] || row["SOURCE"] || "").trim();

          const errors: string[] = [];
          if (!name) errors.push("name is required");
          if (!id) errors.push("id/name is required");
          if (!image_url) errors.push("image_url is required");
          if (!size) errors.push("size is required");

          return {
            id,
            name,
            image_url,
            size,
            source,
            _valid: errors.length === 0,
            _error: errors.join(", "),
          };
        });

        setImportRows(rows);
        setImportDone(false);
        setImportProgress({ done: 0, total: 0, errors: 0 });
        setShowImportModal(true);
      } catch (err) {
        flash("Could not read file. Make sure it's a valid Excel (.xlsx) or CSV file.", "error");
      }
    };
    reader.readAsArrayBuffer(file);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) parseExcelFile(file);
    e.target.value = "";
  };

  const handleImport = async () => {
    const validRows = importRows.filter((r) => r._valid);
    if (validRows.length === 0) { flash("No valid rows to import", "error"); return; }

    setImporting(true);
    setImportProgress({ done: 0, total: validRows.length, errors: 0 });

    let errors = 0;
    for (let i = 0; i < validRows.length; i++) {
      const row = validRows[i];
      try {
        await addGame({ id: row.id, name: row.name, image_url: row.image_url, size: row.size, source: row.source });
      } catch {
        errors++;
      }
      setImportProgress({ done: i + 1, total: validRows.length, errors });
    }

    setImporting(false);
    setImportDone(true);
    await loadGames();

    const added = validRows.length - errors;
    flash(
      errors === 0
        ? `Successfully imported ${added} game${added !== 1 ? "s" : ""}!`
        : `Imported ${added} game${added !== 1 ? "s" : ""}, ${errors} failed (may already exist).`,
      errors === 0 ? "success" : "error"
    );
  };

  const closeImportModal = () => {
    if (importing) return;
    setShowImportModal(false);
    setImportRows([]);
    setImportDone(false);
  };

  // ─── Hard drive CRUD ─────────────────────────────────────────────────────────

  const handleDriveSave = async () => {
    if (!driveForm.id.trim() || !driveForm.name.trim() || !driveForm.capacity.trim() || !driveForm.type.trim() || !driveForm.speed.trim() || !driveForm.price.trim()) {
      flash("All required fields must be filled", "error"); return;
    }
    setDriveSaving(true);
    try {
      if (editingDriveId) {
        await updateHardDrive(editingDriveId, { name: driveForm.name, image_url: driveForm.image_url, capacity: driveForm.capacity, type: driveForm.type, speed: driveForm.speed, price: driveForm.price, description: driveForm.description });
        flash("Hard drive updated!", "success");
      } else {
        await addHardDrive({ id: driveForm.id, name: driveForm.name, image_url: driveForm.image_url, capacity: driveForm.capacity, type: driveForm.type, speed: driveForm.speed, price: driveForm.price, description: driveForm.description });
        flash("Hard drive added!", "success");
      }
      setDriveForm(EMPTY_HD_FORM); setShowDriveForm(false); setEditingDriveId(null);
      await loadDrives();
    } catch (e: any) { flash(e.message || "Failed to save hard drive", "error"); }
    finally { setDriveSaving(false); }
  };

  const handleDriveEdit = (drive: HardDrive) => {
    setDriveForm({ id: drive.id, name: drive.name, image_url: drive.image_url, capacity: drive.capacity, type: drive.type, speed: drive.speed, price: drive.price, description: drive.description || "" });
    setEditingDriveId(drive.id); setShowDriveForm(true);
  };

  const handleDriveDelete = async (id: string, name: string) => {
    if (!confirm(`Delete "${name}"? This cannot be undone.`)) return;
    try { await deleteHardDrive(id); flash("Hard drive deleted", "success"); await loadDrives(); }
    catch { flash("Failed to delete", "error"); }
  };

  // Accessory CRUD
  const handleAccSave = async () => {
    if (!accForm.id.trim() || !accForm.name.trim() || !accForm.price.trim()) {
      flash("ID, name, and price are required", "error"); return;
    }
    setAccSaving(true);
    try {
      if (editingAccId) {
        await updateAccessory(editingAccId, { name: accForm.name, image_url: accForm.image_url, category: accForm.category, price: accForm.price, description: accForm.description });
        flash("Accessory updated!", "success");
      } else {
        await addAccessory({ id: accForm.id, name: accForm.name, image_url: accForm.image_url, category: accForm.category, price: accForm.price, description: accForm.description });
        flash("Accessory added!", "success");
      }
      setAccForm(EMPTY_ACC_FORM); setShowAccForm(false); setEditingAccId(null);
      await loadAccessories();
    } catch (e: any) { flash(e.message || "Failed to save accessory", "error"); }
    finally { setAccSaving(false); }
  };

  const handleAccEdit = (acc: Accessory) => {
    setAccForm({ id: acc.id, name: acc.name, image_url: acc.image_url, category: acc.category, price: acc.price, description: acc.description || "" });
    setEditingAccId(acc.id); setShowAccForm(true);
  };

  const handleAccDelete = async (id: string, name: string) => {
    if (!confirm(`Delete "${name}"? This cannot be undone.`)) return;
    try { await deleteAccessory(id); flash("Accessory deleted", "success"); await loadAccessories(); }
    catch { flash("Failed to delete", "error"); }
  };

  const copySQL = () => {
    navigator.clipboard.writeText(SQL_SETUP);
    setCopied(true); setTimeout(() => setCopied(false), 2000);
  };

  const inp = "w-full px-3 py-2.5 bg-muted border border-border rounded-lg text-sm text-foreground placeholder:text-foreground/30 focus:outline-none focus:ring-1 focus:ring-primary";
  const validCount = importRows.filter((r) => r._valid).length;
  const invalidCount = importRows.length - validCount;

  // ─── Login screen ─────────────────────────────────────────────────────────────

  if (!authed) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="w-full max-w-sm">
          <div className="bg-card border border-border rounded-2xl p-8 space-y-6">
            <div className="text-center">
              <div className="w-14 h-14 rounded-xl bg-primary/20 flex items-center justify-center mx-auto mb-4">
                <Shield className="w-7 h-7 text-primary" />
              </div>
              <h1 className="text-2xl font-black text-foreground">Admin Panel</h1>
              <p className="text-sm text-foreground/50 mt-1">GAMEARLY — Management</p>
            </div>
            <div className="space-y-3">
              <input
                type="password"
                placeholder="Admin password"
                value={passwordInput}
                onChange={(e) => { setPasswordInput(e.target.value); setPasswordError(false); }}
                onKeyDown={(e) => e.key === "Enter" && handleLogin()}
                className={`w-full px-4 py-3 bg-muted border rounded-xl text-foreground placeholder:text-foreground/40 focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all ${passwordError ? "border-destructive" : "border-border"}`}
              />
              {passwordError && <p className="text-xs text-destructive">Incorrect password</p>}
              <button
                onClick={handleLogin}
                disabled={authLoading}
                className="w-full py-3 bg-primary hover:bg-primary/90 text-primary-foreground font-bold rounded-xl transition-all disabled:opacity-60 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                {authLoading && <Loader2 className="w-4 h-4 animate-spin" />}
                {authLoading ? "Verifying…" : "Sign In"}
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // ─── Main admin UI ────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-background">
      <div className="h-16" />

      <div className="border-b border-border bg-card/50 sticky top-16 z-40">
        <div className="container mx-auto px-4 h-14 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <span className="font-black text-foreground">Admin Panel</span>
            <div className="flex gap-1">
              {([
                { key: "brand", label: "Brand" },
                { key: "games", label: "Games" },
                { key: "hard_drives", label: "Hard Drives" },
                { key: "accessories", label: "Accessories" },
                { key: "home", label: "Home Page" },
                { key: "contact", label: "Contact Info" },
                { key: "pricing", label: "Pricing" },
                { key: "api_keys", label: "API Keys" },
                { key: "setup", label: "DB Setup" },
              ] as const).map(({ key, label }) => (
                <button
                  key={key}
                  onClick={() => setActiveTab(key)}
                  className={`px-4 py-1.5 rounded-lg text-sm font-medium transition-colors ${activeTab === key ? "bg-primary text-primary-foreground" : "text-foreground/60 hover:text-foreground"}`}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>
          <button onClick={() => setAuthed(false)} className="flex items-center gap-2 text-sm text-foreground/60 hover:text-foreground transition-colors">
            <LogOut className="w-4 h-4" />Logout
          </button>
        </div>
      </div>

      <div className="container mx-auto px-4 py-8">
        {success && (
          <div className="mb-4 flex items-center gap-2 px-4 py-3 bg-green-500/15 border border-green-500/30 rounded-xl text-green-400 text-sm">
            <CheckCircle className="w-4 h-4 flex-shrink-0" />{success}
          </div>
        )}
        {error && (
          <div className="mb-4 flex items-center gap-2 px-4 py-3 bg-destructive/15 border border-destructive/30 rounded-xl text-destructive text-sm">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />{error}
          </div>
        )}

        {/* ── SETUP TAB ── */}
        {activeTab === "setup" && (
          <div className="max-w-2xl space-y-6">
            <div>
              <h2 className="text-2xl font-bold mb-1">Supabase Database Setup</h2>
              <p className="text-foreground/60 text-sm">Follow these steps once to connect your free database.</p>
            </div>
            {isSupabaseConfigured ? (
              <div className="flex items-center gap-2 px-4 py-3 bg-green-500/15 border border-green-500/30 rounded-xl text-green-400 text-sm">
                <CheckCircle className="w-4 h-4" />Supabase is connected and ready!
              </div>
            ) : (
              <div className="flex items-center gap-2 px-4 py-3 bg-yellow-500/15 border border-yellow-500/30 rounded-xl text-yellow-400 text-sm">
                <AlertCircle className="w-4 h-4" />Supabase is not configured yet
              </div>
            )}
            {[
              { step: "1", title: "Create a free Supabase account", content: <a href="https://supabase.com" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-2 text-primary hover:underline font-medium">Go to supabase.com and sign up <ExternalLink className="w-3.5 h-3.5" /></a> },
              { step: "2", title: "Create a new project", content: <p className="text-sm text-foreground/60">Click "New Project", choose a name, set a password, wait ~2 minutes.</p> },
              {
                step: "3", title: "Run the database setup SQL", content: (
                  <div>
                    <p className="text-sm text-foreground/60 mb-3">SQL Editor → New query, paste and run:</p>
                    <div className="relative">
                      <pre className="bg-muted rounded-lg p-4 text-xs text-foreground/80 overflow-x-auto whitespace-pre-wrap">{SQL_SETUP}</pre>
                      <button onClick={copySQL} className="absolute top-2 right-2 p-1.5 bg-card border border-border rounded-lg hover:bg-muted transition-colors">
                        {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>
                )
              },
              { step: "4", title: "Get your API keys", content: <p className="text-sm text-foreground/60">Project Settings → API → copy <strong>Project URL</strong> and <strong>anon key</strong>.</p> },
              {
                step: "5", title: "Add keys to Replit Secrets", content: (
                  <div className="text-sm text-foreground/60 space-y-2">
                    <p>Open Replit <strong>Secrets</strong> tab and add:</p>
                    <ul className="space-y-1 font-mono text-xs bg-muted rounded-lg p-3">
                      <li><span className="text-primary">VITE_SUPABASE_URL</span> = your Project URL</li>
                      <li><span className="text-primary">VITE_SUPABASE_ANON_KEY</span> = your anon key</li>
                    </ul>
                    <p>Then restart the app.</p>
                  </div>
                )
              },
            ].map(({ step, title, content }) => (
              <div key={step} className="bg-card border border-border rounded-xl p-5">
                <div className="flex gap-4">
                  <div className="w-7 h-7 rounded-full bg-primary/20 flex items-center justify-center flex-shrink-0">
                    <span className="text-xs font-black text-primary">{step}</span>
                  </div>
                  <div className="flex-1"><h3 className="font-bold mb-2">{title}</h3>{content}</div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* ── GAMES TAB ── */}
        {activeTab === "games" && (
          <div className="space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-2xl font-bold">Games</h2>
                <p className="text-foreground/50 text-sm">{isSupabaseConfigured ? `${games.length} game${games.length !== 1 ? "s" : ""} in database` : "Supabase not configured"}</p>
              </div>

              {isSupabaseConfigured && (
                <div className="flex flex-wrap gap-2">
                  {/* Download template */}
                  <button
                    onClick={downloadTemplate}
                    className="flex items-center gap-2 px-4 py-2 bg-muted border border-border hover:border-secondary/50 text-foreground font-medium rounded-xl transition-all text-sm"
                  >
                    <Download className="w-4 h-4 text-secondary" />
                    Download Template
                  </button>

                  {/* Import Excel */}
                  <button
                    onClick={() => fileInputRef.current?.click()}
                    className="flex items-center gap-2 px-4 py-2 bg-secondary/15 border border-secondary/40 hover:bg-secondary/25 text-secondary font-bold rounded-xl transition-all text-sm"
                  >
                    <FileSpreadsheet className="w-4 h-4" />
                    Import Excel / CSV
                  </button>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".xlsx,.xls,.csv"
                    className="hidden"
                    onChange={handleFileChange}
                  />

                  {/* Add single game */}
                  {!showGameForm && (
                    <button
                      onClick={() => { setGameForm(EMPTY_GAME_FORM); setEditingGameId(null); setShowGameForm(true); }}
                      className="flex items-center gap-2 px-4 py-2 bg-primary hover:bg-primary/90 text-primary-foreground font-bold rounded-xl transition-all text-sm"
                    >
                      <Plus className="w-4 h-4" />Add Game
                    </button>
                  )}
                </div>
              )}
            </div>

            {!isSupabaseConfigured && (
              <div className="bg-card border border-border rounded-xl p-8 text-center space-y-3">
                <AlertCircle className="w-10 h-10 text-yellow-400 mx-auto" />
                <p className="text-foreground/60">Database not connected.</p>
                <button onClick={() => setActiveTab("setup")} className="text-primary hover:underline text-sm font-medium">Go to Setup Guide →</button>
              </div>
            )}

            {/* How-to tip */}
            {isSupabaseConfigured && !showGameForm && games.length === 0 && !gamesLoading && (
              <div className="bg-secondary/5 border border-secondary/20 rounded-xl p-5 flex gap-4">
                <FileSpreadsheet className="w-6 h-6 text-secondary flex-shrink-0 mt-0.5" />
                <div>
                  <p className="font-bold text-sm text-foreground mb-1">Bulk import games from Excel</p>
                  <p className="text-xs text-foreground/60">
                    Download the template, fill in your games, then click <strong>Import Excel / CSV</strong> to upload them all at once.
                    Each row becomes a game on your website.
                  </p>
                </div>
              </div>
            )}

            {/* Add/Edit form */}
            {showGameForm && isSupabaseConfigured && (
              <div className="bg-card border border-primary/30 rounded-xl p-6 space-y-4">
                <h3 className="font-bold text-lg">{editingGameId ? "Edit Game" : "Add New Game"}</h3>
                <div className="grid sm:grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1 block">
                      Game ID (slug) {editingGameId && <span className="text-foreground/40">— cannot change</span>}
                    </label>
                    <input value={gameForm.id} onChange={(e) => setGameForm({ ...gameForm, id: e.target.value.toLowerCase().replace(/\s+/g, "-") })} disabled={!!editingGameId} placeholder="e.g. red-dead-redemption-2" className={inp + " disabled:opacity-50"} />
                    <p className="text-[10px] text-foreground/40 mt-1">Use hyphens, no spaces.</p>
                  </div>
                  <div>
                    <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1 block">Game Name</label>
                    <input value={gameForm.name} onChange={(e) => setGameForm({ ...gameForm, name: e.target.value })} placeholder="e.g. Red Dead Redemption 2" className={inp} />
                  </div>
                  <div>
                    <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1 block">Image URL</label>
                    <input value={gameForm.image_url} onChange={(e) => setGameForm({ ...gameForm, image_url: e.target.value })} placeholder="https://..." className={inp} />
                  </div>
                  <div>
                    <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1 block">Size</label>
                    <input value={gameForm.size} onChange={(e) => setGameForm({ ...gameForm, size: e.target.value })} placeholder="e.g. 120GB" className={inp} />
                  </div>
                  <div className="sm:col-span-2">
                    <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1 block">Source</label>
                    <input value={gameForm.source} onChange={(e) => setGameForm({ ...gameForm, source: e.target.value })} placeholder="e.g. FitGirl, DODI, or https://..." className={inp} />
                  </div>
                </div>
                {gameForm.image_url && (
                  <div>
                    <p className="text-xs text-foreground/60 mb-1">Preview:</p>
                    <img src={gameForm.image_url} alt="preview" className="w-32 h-20 object-cover rounded-lg border border-border" onError={(e) => { (e.target as HTMLImageElement).style.display = "none"; }} />
                  </div>
                )}
                <div className="flex gap-3">
                  <button onClick={handleGameSave} disabled={gameSaving} className="flex items-center gap-2 px-5 py-2.5 bg-primary hover:bg-primary/90 disabled:opacity-50 text-primary-foreground font-bold rounded-xl text-sm transition-all">
                    {gameSaving ? <Loader2 className="w-4 h-4 animate-spin" /> : <CheckCircle className="w-4 h-4" />}
                    {gameSaving ? "Saving..." : editingGameId ? "Save Changes" : "Add Game"}
                  </button>
                  <button onClick={() => { setShowGameForm(false); setEditingGameId(null); setGameForm(EMPTY_GAME_FORM); }} className="px-5 py-2.5 bg-muted border border-border hover:border-foreground/30 text-foreground font-medium rounded-xl text-sm transition-colors">
                    Cancel
                  </button>
                </div>
              </div>
            )}

            {/* Games table */}
            {isSupabaseConfigured && (
              gamesLoading ? (
                <div className="flex justify-center py-12"><Loader2 className="w-8 h-8 animate-spin text-primary" /></div>
              ) : games.length === 0 ? (
                <div className="bg-card border border-border rounded-xl p-12 text-center text-foreground/50">
                  No games yet. Add one manually or import from Excel.
                </div>
              ) : (
                <div className="bg-card border border-border rounded-xl overflow-hidden">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-border bg-muted/50">
                        <th className="px-4 py-3 text-left text-xs font-bold text-foreground/50 uppercase tracking-wider">Image</th>
                        <th className="px-4 py-3 text-left text-xs font-bold text-foreground/50 uppercase tracking-wider">Name</th>
                        <th className="px-4 py-3 text-left text-xs font-bold text-foreground/50 uppercase tracking-wider hidden md:table-cell">Size</th>
                        <th className="px-4 py-3 text-left text-xs font-bold text-foreground/50 uppercase tracking-wider hidden lg:table-cell">Source</th>
                        <th className="px-4 py-3 text-right text-xs font-bold text-foreground/50 uppercase tracking-wider">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                      {games.map((game) => (
                        <tr key={game.id} className="hover:bg-muted/30 transition-colors">
                          <td className="px-4 py-3">
                            <img src={game.image_url} alt={game.name} className="w-16 h-10 object-cover rounded-lg border border-border" onError={(e) => { (e.target as HTMLImageElement).src = ""; }} />
                          </td>
                          <td className="px-4 py-3 font-medium text-sm">{game.name}</td>
                          <td className="px-4 py-3 text-sm text-secondary font-bold hidden md:table-cell">{game.size}</td>
                          <td className="px-4 py-3 text-xs text-foreground/50 hidden lg:table-cell">{game.source || "—"}</td>
                          <td className="px-4 py-3">
                            <div className="flex gap-2 justify-end">
                              <button onClick={() => handleGameEdit(game)} className="p-1.5 hover:bg-primary/20 text-primary rounded-lg transition-colors"><Pencil className="w-4 h-4" /></button>
                              <button onClick={() => handleGameDelete(game.id, game.name)} className="p-1.5 hover:bg-destructive/20 text-destructive rounded-lg transition-colors"><Trash2 className="w-4 h-4" /></button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )
            )}
          </div>
        )}

        {/* ── HARD DRIVES TAB ── */}
        {activeTab === "hard_drives" && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-2xl font-bold">Hard Drives</h2>
                <p className="text-foreground/50 text-sm">{isSupabaseConfigured ? `${drives.length} product${drives.length !== 1 ? "s" : ""} in database` : "Supabase not configured"}</p>
              </div>
              {isSupabaseConfigured && !showDriveForm && (
                <button onClick={() => { setDriveForm(EMPTY_HD_FORM); setEditingDriveId(null); setShowDriveForm(true); }} className="flex items-center gap-2 px-4 py-2 bg-primary hover:bg-primary/90 text-primary-foreground font-bold rounded-xl transition-all text-sm">
                  <Plus className="w-4 h-4" />Add Hard Drive
                </button>
              )}
            </div>

            {!isSupabaseConfigured && (
              <div className="bg-card border border-border rounded-xl p-8 text-center space-y-3">
                <AlertCircle className="w-10 h-10 text-yellow-400 mx-auto" />
                <p className="text-foreground/60">Database not connected.</p>
                <button onClick={() => setActiveTab("setup")} className="text-primary hover:underline text-sm font-medium">Go to Setup Guide →</button>
              </div>
            )}

            {showDriveForm && isSupabaseConfigured && (
              <div className="bg-card border border-primary/30 rounded-xl p-6 space-y-4">
                <h3 className="font-bold text-lg">{editingDriveId ? "Edit Hard Drive" : "Add New Hard Drive"}</h3>
                <div className="grid sm:grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1 block">ID (slug) {editingDriveId && <span className="text-foreground/40">— cannot change</span>}</label>
                    <input value={driveForm.id} onChange={(e) => setDriveForm({ ...driveForm, id: e.target.value.toLowerCase().replace(/\s+/g, "-") })} disabled={!!editingDriveId} placeholder="e.g. wd-blue-1tb" className={inp + " disabled:opacity-50"} />
                  </div>
                  <div>
                    <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1 block">Product Name</label>
                    <input value={driveForm.name} onChange={(e) => setDriveForm({ ...driveForm, name: e.target.value })} placeholder="e.g. WD Blue 1TB" className={inp} />
                  </div>
                  <div>
                    <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1 block">Image URL</label>
                    <input value={driveForm.image_url} onChange={(e) => setDriveForm({ ...driveForm, image_url: e.target.value })} placeholder="https://..." className={inp} />
                  </div>
                  <div>
                    <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1 block">Capacity</label>
                    <input value={driveForm.capacity} onChange={(e) => setDriveForm({ ...driveForm, capacity: e.target.value })} placeholder="e.g. 1TB, 2TB, 500GB" className={inp} />
                  </div>
                  <div>
                    <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1 block">Type</label>
                    <select value={driveForm.type} onChange={(e) => setDriveForm({ ...driveForm, type: e.target.value })} className={inp}>
                      <option value="HDD">HDD</option>
                      <option value="SATA SSD">SATA SSD</option>
                      <option value="NVMe SSD">NVMe SSD</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1 block">Speed</label>
                    <input value={driveForm.speed} onChange={(e) => setDriveForm({ ...driveForm, speed: e.target.value })} placeholder="e.g. 7200 RPM / 550 MB/s" className={inp} />
                  </div>
                  <div>
                    <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1 block">Price</label>
                    <input value={driveForm.price} onChange={(e) => setDriveForm({ ...driveForm, price: e.target.value })} placeholder="e.g. 350 EGP" className={inp} />
                  </div>
                  <div className="sm:col-span-2">
                    <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1 block">Description</label>
                    <textarea value={driveForm.description} onChange={(e) => setDriveForm({ ...driveForm, description: e.target.value })} placeholder="Short product description..." rows={2} className={inp + " resize-none"} />
                  </div>
                </div>
                {driveForm.image_url && (
                  <div>
                    <p className="text-xs text-foreground/60 mb-1">Preview:</p>
                    <img src={driveForm.image_url} alt="preview" className="w-32 h-20 object-cover rounded-lg border border-border" onError={(e) => { (e.target as HTMLImageElement).style.display = "none"; }} />
                  </div>
                )}
                <div className="flex gap-3">
                  <button onClick={handleDriveSave} disabled={driveSaving} className="flex items-center gap-2 px-5 py-2.5 bg-primary hover:bg-primary/90 disabled:opacity-50 text-primary-foreground font-bold rounded-xl text-sm transition-all">
                    {driveSaving ? <Loader2 className="w-4 h-4 animate-spin" /> : <CheckCircle className="w-4 h-4" />}
                    {driveSaving ? "Saving..." : editingDriveId ? "Save Changes" : "Add Hard Drive"}
                  </button>
                  <button onClick={() => { setShowDriveForm(false); setEditingDriveId(null); setDriveForm(EMPTY_HD_FORM); }} className="px-5 py-2.5 bg-muted border border-border hover:border-foreground/30 text-foreground font-medium rounded-xl text-sm transition-colors">
                    Cancel
                  </button>
                </div>
              </div>
            )}

            {isSupabaseConfigured && (
              drivesLoading ? (
                <div className="flex justify-center py-12"><Loader2 className="w-8 h-8 animate-spin text-primary" /></div>
              ) : drives.length === 0 ? (
                <div className="bg-card border border-border rounded-xl p-12 text-center text-foreground/50">
                  No hard drives yet. Click "Add Hard Drive" to get started.
                </div>
              ) : (
                <div className="bg-card border border-border rounded-xl overflow-hidden">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-border bg-muted/50">
                        <th className="px-4 py-3 text-left text-xs font-bold text-foreground/50 uppercase tracking-wider">Image</th>
                        <th className="px-4 py-3 text-left text-xs font-bold text-foreground/50 uppercase tracking-wider">Name</th>
                        <th className="px-4 py-3 text-left text-xs font-bold text-foreground/50 uppercase tracking-wider hidden md:table-cell">Capacity</th>
                        <th className="px-4 py-3 text-left text-xs font-bold text-foreground/50 uppercase tracking-wider hidden md:table-cell">Type</th>
                        <th className="px-4 py-3 text-left text-xs font-bold text-foreground/50 uppercase tracking-wider hidden lg:table-cell">Price</th>
                        <th className="px-4 py-3 text-right text-xs font-bold text-foreground/50 uppercase tracking-wider">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                      {drives.map((drive) => (
                        <tr key={drive.id} className="hover:bg-muted/30 transition-colors">
                          <td className="px-4 py-3">
                            {drive.image_url ? (
                              <img src={drive.image_url} alt={drive.name} className="w-16 h-10 object-cover rounded-lg border border-border" onError={(e) => { (e.target as HTMLImageElement).style.display = "none"; }} />
                            ) : (
                              <div className="w-16 h-10 bg-muted rounded-lg border border-border flex items-center justify-center">
                                <HardDriveIcon className="w-5 h-5 text-foreground/30" />
                              </div>
                            )}
                          </td>
                          <td className="px-4 py-3 font-medium text-sm">{drive.name}</td>
                          <td className="px-4 py-3 text-sm text-secondary font-bold hidden md:table-cell">{drive.capacity}</td>
                          <td className="px-4 py-3 text-xs text-foreground/70 hidden md:table-cell">{drive.type}</td>
                          <td className="px-4 py-3 text-sm text-green-400 font-bold hidden lg:table-cell">{drive.price}</td>
                          <td className="px-4 py-3">
                            <div className="flex gap-2 justify-end">
                              <button onClick={() => handleDriveEdit(drive)} className="p-1.5 hover:bg-primary/20 text-primary rounded-lg transition-colors"><Pencil className="w-4 h-4" /></button>
                              <button onClick={() => handleDriveDelete(drive.id, drive.name)} className="p-1.5 hover:bg-destructive/20 text-destructive rounded-lg transition-colors"><Trash2 className="w-4 h-4" /></button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )
            )}
          </div>
        )}

        {/* ── ACCESSORIES TAB ── */}
        {activeTab === "accessories" && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-2xl font-bold">Accessories</h2>
                <p className="text-foreground/50 text-sm">{isSupabaseConfigured ? `${accessories.length} product${accessories.length !== 1 ? "s" : ""} in database` : "Supabase not configured"}</p>
              </div>
              {isSupabaseConfigured && !showAccForm && (
                <button onClick={() => { setAccForm(EMPTY_ACC_FORM); setEditingAccId(null); setShowAccForm(true); }} className="flex items-center gap-2 px-4 py-2 bg-primary hover:bg-primary/90 text-primary-foreground font-bold rounded-xl transition-all text-sm">
                  <Plus className="w-4 h-4" />Add Accessory
                </button>
              )}
            </div>

            {!isSupabaseConfigured && (
              <div className="bg-card border border-border rounded-xl p-8 text-center space-y-3">
                <AlertCircle className="w-10 h-10 text-yellow-400 mx-auto" />
                <p className="text-foreground/60">Database not connected.</p>
                <button onClick={() => setActiveTab("setup")} className="text-primary hover:underline text-sm font-medium">Go to Setup Guide →</button>
              </div>
            )}

            {showAccForm && isSupabaseConfigured && (
              <div className="bg-card border border-primary/30 rounded-xl p-6 space-y-4">
                <h3 className="font-bold text-lg">{editingAccId ? "Edit Accessory" : "Add New Accessory"}</h3>
                <div className="grid sm:grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1 block">ID (slug) {editingAccId && <span className="text-foreground/40">— cannot change</span>}</label>
                    <input value={accForm.id} onChange={(e) => setAccForm({ ...accForm, id: e.target.value.toLowerCase().replace(/\s+/g, "-") })} disabled={!!editingAccId} placeholder="e.g. razer-deathadder-v3" className={inp + " disabled:opacity-50"} />
                  </div>
                  <div>
                    <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1 block">Product Name</label>
                    <input value={accForm.name} onChange={(e) => setAccForm({ ...accForm, name: e.target.value })} placeholder="e.g. Razer DeathAdder V3" className={inp} />
                  </div>
                  <div>
                    <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1 block">Image URL</label>
                    <input value={accForm.image_url} onChange={(e) => setAccForm({ ...accForm, image_url: e.target.value })} placeholder="https://..." className={inp} />
                  </div>
                  <div>
                    <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1 block">Category</label>
                    <select value={accForm.category} onChange={(e) => setAccForm({ ...accForm, category: e.target.value })} className={inp}>
                      {ACC_CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
                    </select>
                  </div>
                  <div>
                    <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1 block">Price</label>
                    <input value={accForm.price} onChange={(e) => setAccForm({ ...accForm, price: e.target.value })} placeholder="e.g. 850 EGP" className={inp} />
                  </div>
                  <div className="sm:col-span-2">
                    <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1 block">Description</label>
                    <textarea value={accForm.description} onChange={(e) => setAccForm({ ...accForm, description: e.target.value })} placeholder="Short product description..." rows={2} className={inp + " resize-none"} />
                  </div>
                </div>
                {accForm.image_url && (
                  <div>
                    <p className="text-xs text-foreground/60 mb-1">Preview:</p>
                    <img src={accForm.image_url} alt="preview" className="w-32 h-20 object-cover rounded-lg border border-border" onError={(e) => { (e.target as HTMLImageElement).style.display = "none"; }} />
                  </div>
                )}
                <div className="flex gap-3">
                  <button onClick={handleAccSave} disabled={accSaving} className="flex items-center gap-2 px-5 py-2.5 bg-primary hover:bg-primary/90 disabled:opacity-50 text-primary-foreground font-bold rounded-xl text-sm transition-all">
                    {accSaving ? <Loader2 className="w-4 h-4 animate-spin" /> : <CheckCircle className="w-4 h-4" />}
                    {accSaving ? "Saving..." : editingAccId ? "Save Changes" : "Add Accessory"}
                  </button>
                  <button onClick={() => { setShowAccForm(false); setEditingAccId(null); setAccForm(EMPTY_ACC_FORM); }} className="px-5 py-2.5 bg-muted border border-border hover:border-foreground/30 text-foreground font-medium rounded-xl text-sm transition-colors">
                    Cancel
                  </button>
                </div>
              </div>
            )}

            {isSupabaseConfigured && (
              accsLoading ? (
                <div className="flex justify-center py-12"><Loader2 className="w-8 h-8 animate-spin text-primary" /></div>
              ) : accessories.length === 0 ? (
                <div className="bg-card border border-border rounded-xl p-12 text-center text-foreground/50">
                  No accessories yet. Click "Add Accessory" to get started.
                </div>
              ) : (
                <div className="bg-card border border-border rounded-xl overflow-hidden">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-border bg-muted/50">
                        <th className="px-4 py-3 text-left text-xs font-bold text-foreground/50 uppercase tracking-wider">Image</th>
                        <th className="px-4 py-3 text-left text-xs font-bold text-foreground/50 uppercase tracking-wider">Name</th>
                        <th className="px-4 py-3 text-left text-xs font-bold text-foreground/50 uppercase tracking-wider hidden md:table-cell">Category</th>
                        <th className="px-4 py-3 text-left text-xs font-bold text-foreground/50 uppercase tracking-wider hidden lg:table-cell">Price</th>
                        <th className="px-4 py-3 text-right text-xs font-bold text-foreground/50 uppercase tracking-wider">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                      {accessories.map((acc) => (
                        <tr key={acc.id} className="hover:bg-muted/30 transition-colors">
                          <td className="px-4 py-3">
                            {acc.image_url ? (
                              <img src={acc.image_url} alt={acc.name} className="w-16 h-10 object-cover rounded-lg border border-border" onError={(e) => { (e.target as HTMLImageElement).style.display = "none"; }} />
                            ) : (
                              <div className="w-16 h-10 bg-muted rounded-lg border border-border flex items-center justify-center">
                                <Package className="w-5 h-5 text-foreground/30" />
                              </div>
                            )}
                          </td>
                          <td className="px-4 py-3 font-medium text-sm">{acc.name}</td>
                          <td className="px-4 py-3 text-xs text-foreground/70 hidden md:table-cell">{acc.category}</td>
                          <td className="px-4 py-3 text-sm text-green-400 font-bold hidden lg:table-cell">{acc.price}</td>
                          <td className="px-4 py-3">
                            <div className="flex gap-2 justify-end">
                              <button onClick={() => handleAccEdit(acc)} className="p-1.5 hover:bg-primary/20 text-primary rounded-lg transition-colors"><Pencil className="w-4 h-4" /></button>
                              <button onClick={() => handleAccDelete(acc.id, acc.name)} className="p-1.5 hover:bg-destructive/20 text-destructive rounded-lg transition-colors"><Trash2 className="w-4 h-4" /></button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )
            )}
          </div>
        )}

        {/* ── HOME PAGE TAB ── */}
        {activeTab === "brand" && (
            <div className="max-w-xl space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-2xl font-bold mb-1 flex items-center gap-2"><Palette className="w-6 h-6 text-primary" />Brand Name</h2>
                  <p className="text-foreground/60 text-sm">Change the name shown across the whole site, browser tab, and the invoice. Saved automatically as you type.</p>
                </div>
                <button
                  onClick={() => { resetBrand(); flash("Brand reset to default", "success"); }}
                  className="flex items-center gap-2 px-4 py-2 bg-muted border border-border hover:border-destructive/50 hover:text-destructive text-foreground/60 rounded-xl text-sm transition-colors"
                >
                  <RotateCcw className="w-4 h-4" />Reset
                </button>
              </div>

              <div className="bg-card border border-border rounded-2xl p-6 space-y-3">
                <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider block">Brand Name</label>
                <input
                  type="text"
                  value={brand.name}
                  onChange={e => updateBrand({ name: e.target.value })}
                  className="w-full px-4 py-3 bg-muted border border-border rounded-xl text-foreground text-lg font-bold focus:outline-none focus:ring-2 focus:ring-primary/50"
                  placeholder="Your brand name"
                />
                <p className="text-xs text-foreground/40">Appears in the header, footer, hero, sign-up modal, browser tab, and on every invoice.</p>
              </div>

              <div className="flex items-center gap-2 px-4 py-3 bg-primary/10 border border-primary/30 rounded-xl text-primary text-sm">
                <Save className="w-4 h-4 flex-shrink-0" />
                Saved automatically — changes show up live for everyone.
              </div>
            </div>
          )}
        {activeTab === "home" && (
          <div className="max-w-2xl space-y-8">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-2xl font-bold mb-1 flex items-center gap-2"><Home className="w-6 h-6 text-primary" />Home Page Content</h2>
                <p className="text-foreground/60 text-sm">Edit the text and images shown on the home page. Changes are saved instantly.</p>
              </div>
              <button
                onClick={() => { resetHome(); flash("Home page reset to defaults", "success"); }}
                className="flex items-center gap-2 px-4 py-2 bg-muted border border-border hover:border-destructive/50 hover:text-destructive text-foreground/60 rounded-xl text-sm transition-colors"
              >
                <RotateCcw className="w-4 h-4" />Reset
              </button>
            </div>

            {/* Hero Text */}
            <div className="bg-card border border-border rounded-2xl p-6 space-y-4">
              <h3 className="text-sm font-bold text-foreground/50 uppercase tracking-wider">Hero Section — Text</h3>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1.5 block">Title (line 1)</label>
                  <input type="text" value={homeContent.heroTitle} onChange={e => updateHome({ heroTitle: e.target.value })}
                    className="w-full px-3 py-2 bg-muted border border-border rounded-xl text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-primary/50" />
                </div>
                <div>
                  <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1.5 block">Title (gradient line)</label>
                  <input type="text" value={homeContent.heroSubtitle} onChange={e => updateHome({ heroSubtitle: e.target.value })}
                    className="w-full px-3 py-2 bg-muted border border-border rounded-xl text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-primary/50" />
                </div>
              </div>
              <div>
                <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1.5 block">Badge Text</label>
                <input type="text" value={homeContent.badgeText} onChange={e => updateHome({ badgeText: e.target.value })}
                  className="w-full px-3 py-2 bg-muted border border-border rounded-xl text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-primary/50" />
              </div>
              <div>
                <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1.5 block">Description</label>
                <textarea rows={3} value={homeContent.heroDescription} onChange={e => updateHome({ heroDescription: e.target.value })}
                  className="w-full px-3 py-2 bg-muted border border-border rounded-xl text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 resize-none" />
              </div>
            </div>

            {/* Hero Image */}
            <div className="bg-card border border-border rounded-2xl p-6 space-y-4">
              <h3 className="text-sm font-bold text-foreground/50 uppercase tracking-wider">Hero Section — Image</h3>
              <div className="grid grid-cols-3 gap-4">
                <div className="col-span-2">
                  <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1.5 block">Hero Image URL</label>
                  <input type="url" value={homeContent.heroImage} onChange={e => updateHome({ heroImage: e.target.value })}
                    className="w-full px-3 py-2 bg-muted border border-border rounded-xl text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-primary/50" placeholder="https://..." />
                </div>
                <div>
                  <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1.5 block">Image Label</label>
                  <input type="text" value={homeContent.heroImageLabel} onChange={e => updateHome({ heroImageLabel: e.target.value })}
                    className="w-full px-3 py-2 bg-muted border border-border rounded-xl text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-primary/50" />
                </div>
              </div>
              {homeContent.heroImage && (
                <div className="rounded-xl overflow-hidden border border-border/50 max-h-40">
                  <img src={homeContent.heroImage} alt="Preview" className="w-full h-40 object-cover" onError={e => (e.currentTarget.style.display = "none")} />
                </div>
              )}
            </div>

            {/* Background Image */}
            <div className="bg-card border border-border rounded-2xl p-6 space-y-4">
              <h3 className="text-sm font-bold text-foreground/50 uppercase tracking-wider">Page Background Image</h3>
              <div>
                <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1.5 block">Background Image URL</label>
                <input type="url" value={homeContent.backgroundImage} onChange={e => updateHome({ backgroundImage: e.target.value })}
                  className="w-full px-3 py-2 bg-muted border border-border rounded-xl text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-primary/50" placeholder="https://..." />
                <p className="text-xs text-foreground/40 mt-1.5">Full-page background image shown behind the hero section.</p>
              </div>
              {homeContent.backgroundImage && (
                <div className="rounded-xl overflow-hidden border border-border/50">
                  <img src={homeContent.backgroundImage} alt="Preview" className="w-full h-32 object-cover" onError={e => (e.currentTarget.style.display = "none")} />
                </div>
              )}
            </div>

            {/* Stats */}
            <div className="bg-card border border-border rounded-2xl p-6 space-y-4">
              <h3 className="text-sm font-bold text-foreground/50 uppercase tracking-wider">Stats Row</h3>
              <div className="grid grid-cols-3 gap-4">
                {([
                  { valueKey: "stat1Value", labelKey: "stat1Label" },
                  { valueKey: "stat2Value", labelKey: "stat2Label" },
                  { valueKey: "stat3Value", labelKey: "stat3Label" },
                ] as const).map(({ valueKey, labelKey }, i) => (
                  <div key={i} className="space-y-2">
                    <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider block">Stat {i + 1}</label>
                    <input type="text" value={homeContent[valueKey]} onChange={e => updateHome({ [valueKey]: e.target.value })}
                      className="w-full px-3 py-2 bg-muted border border-border rounded-xl text-foreground text-sm font-bold focus:outline-none focus:ring-2 focus:ring-primary/50" placeholder="500+" />
                    <input type="text" value={homeContent[labelKey]} onChange={e => updateHome({ [labelKey]: e.target.value })}
                      className="w-full px-3 py-2 bg-muted border border-border rounded-xl text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-primary/50" placeholder="Games Available" />
                  </div>
                ))}
              </div>
            </div>

            {/* Secondary Image */}
            <div className="bg-card border border-border rounded-2xl p-6 space-y-4">
              <h3 className="text-sm font-bold text-foreground/50 uppercase tracking-wider">Why Choose Us — Image</h3>
              <div>
                <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1.5 block">Image URL</label>
                <input type="url" value={homeContent.secondaryImage} onChange={e => updateHome({ secondaryImage: e.target.value })}
                  className="w-full px-3 py-2 bg-muted border border-border rounded-xl text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-primary/50" placeholder="https://..." />
              </div>
              {homeContent.secondaryImage && (
                <div className="rounded-xl overflow-hidden border border-border/50">
                  <img src={homeContent.secondaryImage} alt="Preview" className="w-full h-32 object-cover" onError={e => (e.currentTarget.style.display = "none")} />
                </div>
              )}
            </div>

            <div className="flex items-center gap-2 px-4 py-3 bg-primary/10 border border-primary/30 rounded-xl text-primary text-sm">
              <Save className="w-4 h-4 flex-shrink-0" />
              All changes are saved automatically as you type — no need to click save.
            </div>
          </div>
        )}

        {/* ── CONTACT INFO TAB ── */}
        {activeTab === "contact" && (
          <div className="max-w-2xl space-y-8">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-2xl font-bold mb-1">Contact Info</h2>
                <p className="text-foreground/60 text-sm">Update the contact details shown on the Contact page and Footer across the entire site.</p>
              </div>
              <button
                onClick={() => { resetContact(); flash("Contact info reset to defaults", "success"); }}
                className="flex items-center gap-2 px-4 py-2 bg-muted border border-border hover:border-destructive/50 hover:text-destructive text-foreground/60 rounded-xl text-sm transition-colors"
              >
                <RotateCcw className="w-4 h-4" />Reset
              </button>
            </div>

            {/* Basic contact fields */}
            <div className="bg-card border border-border rounded-2xl p-6 space-y-4">
              <h3 className="text-sm font-bold text-foreground/50 uppercase tracking-wider">Brand &amp; Contact Details</h3>
              <div className="grid sm:grid-cols-2 gap-4">
                <div className="sm:col-span-2">
                  <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1.5 block">Brand Name <span className="normal-case text-foreground/30">(appears on receipts, bills &amp; everywhere)</span></label>
                  <input type="text" value={contactInfo.brandName ?? ""} onChange={e => updateContact({ brandName: e.target.value })}
                    className="w-full px-3 py-2 bg-muted border border-border rounded-xl text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-primary/50" placeholder="GAMEARLY" />
                </div>
                <div>
                  <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1.5 block">Phone Number</label>
                  <input type="text" value={contactInfo.phone} onChange={e => updateContact({ phone: e.target.value })}
                    className="w-full px-3 py-2 bg-muted border border-border rounded-xl text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-primary/50" placeholder="01559665337" />
                </div>
                <div>
                  <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1.5 block">WhatsApp Number <span className="normal-case text-foreground/30">(with country code)</span></label>
                  <input type="text" value={contactInfo.whatsapp} onChange={e => updateContact({ whatsapp: e.target.value })}
                    className="w-full px-3 py-2 bg-muted border border-border rounded-xl text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-primary/50" placeholder="201559665337" />
                </div>
                <div>
                  <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1.5 block">Email</label>
                  <input type="email" value={contactInfo.email} onChange={e => updateContact({ email: e.target.value })}
                    className="w-full px-3 py-2 bg-muted border border-border rounded-xl text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-primary/50" placeholder="gamearly@gmail.com" />
                </div>
                <div>
                  <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1.5 block">Location</label>
                  <input type="text" value={contactInfo.location} onChange={e => updateContact({ location: e.target.value })}
                    className="w-full px-3 py-2 bg-muted border border-border rounded-xl text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-primary/50" placeholder="Cairo, Egypt" />
                </div>
                <div className="sm:col-span-2">
                  <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1.5 block">Facebook Page URL</label>
                  <input type="url" value={contactInfo.facebook} onChange={e => updateContact({ facebook: e.target.value })}
                    className="w-full px-3 py-2 bg-muted border border-border rounded-xl text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-primary/50" placeholder="https://facebook.com/gamearly" />
                </div>
                <div className="sm:col-span-2">
                  <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1.5 block">Google Maps URL</label>
                  <input type="url" value={contactInfo.mapUrl} onChange={e => updateContact({ mapUrl: e.target.value })}
                    className="w-full px-3 py-2 bg-muted border border-border rounded-xl text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-primary/50" placeholder="https://maps.app.goo.gl/..." />
                </div>
              </div>
            </div>

            {/* Business Hours */}
            <div className="bg-card border border-border rounded-2xl p-6 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-foreground/50 uppercase tracking-wider">Business Hours</h3>
                <button
                  onClick={() => updateContact({ hours: [...contactInfo.hours, { days: "", hours: "" }] })}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-primary/10 border border-primary/30 hover:bg-primary/20 text-primary rounded-lg text-xs font-bold transition-colors"
                >
                  <Plus className="w-3 h-3" />Add Row
                </button>
              </div>
              <div className="space-y-3">
                {contactInfo.hours.map((row, idx) => (
                  <div key={idx} className="flex gap-3 items-start">
                    <div className="flex-1">
                      <input
                        type="text"
                        value={row.days}
                        onChange={e => {
                          const updated = contactInfo.hours.map((h, i) => i === idx ? { ...h, days: e.target.value } : h);
                          updateContact({ hours: updated });
                        }}
                        className="w-full px-3 py-2 bg-muted border border-border rounded-xl text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
                        placeholder="e.g. Saturday – Thursday"
                      />
                    </div>
                    <div className="flex-1">
                      <input
                        type="text"
                        value={row.hours}
                        onChange={e => {
                          const updated = contactInfo.hours.map((h, i) => i === idx ? { ...h, hours: e.target.value } : h);
                          updateContact({ hours: updated });
                        }}
                        className="w-full px-3 py-2 bg-muted border border-border rounded-xl text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
                        placeholder="e.g. 10:00 AM – 10:00 PM"
                      />
                    </div>
                    <button
                      onClick={() => updateContact({ hours: contactInfo.hours.filter((_, i) => i !== idx) })}
                      className="p-2 hover:bg-destructive/20 text-destructive rounded-lg transition-colors mt-0.5"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                ))}
              </div>
            </div>

            <div className="flex items-center gap-2 px-4 py-3 bg-primary/10 border border-primary/30 rounded-xl text-primary text-sm">
              <Save className="w-4 h-4 flex-shrink-0" />
              All changes are saved automatically and appear on the Contact page and Footer instantly.
            </div>
          </div>
        )}

        {/* ── PRICING TAB ── */}
        {activeTab === "pricing" && (
          <div className="max-w-xl space-y-8">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-2xl font-bold mb-1 flex items-center gap-2">
                  <DollarSign className="w-6 h-6 text-primary" />Pricing
                </h2>
                <p className="text-foreground/60 text-sm">Set the price per gigabyte for game orders. This affects the cart, mini-cart, and PDF receipts.</p>
              </div>
              <button
                onClick={() => { resetPricing(); flash("Pricing reset to default (0.20 EGP/GB)", "success"); }}
                className="flex items-center gap-2 px-4 py-2 bg-muted border border-border hover:border-destructive/50 hover:text-destructive text-foreground/60 rounded-xl text-sm transition-colors"
              >
                <RotateCcw className="w-4 h-4" />Reset
              </button>
            </div>

            <div className="bg-card border border-border rounded-2xl p-6 space-y-6">
              <h3 className="text-sm font-bold text-foreground/50 uppercase tracking-wider">Game Pricing</h3>

              <div className="grid sm:grid-cols-2 gap-4">
                <div>
                  <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1.5 block">Price per GB</label>
                  <div className="relative">
                    <input
                      type="number"
                      min="0"
                      step="0.01"
                      value={pricing.pricePerGb}
                      onChange={(e) => updatePricing({ pricePerGb: parseFloat(e.target.value) || 0 })}
                      className="w-full px-3 py-2.5 bg-muted border border-border rounded-xl text-foreground text-sm font-bold focus:outline-none focus:ring-2 focus:ring-primary/50 font-nums"
                    />
                  </div>
                  <p className="text-xs text-foreground/40 mt-1.5">Current default: 0.20 EGP per GB</p>
                </div>
                <div>
                  <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1.5 block">Currency</label>
                  <input
                    type="text"
                    value={pricing.currency}
                    onChange={(e) => updatePricing({ currency: e.target.value })}
                    className="w-full px-3 py-2.5 bg-muted border border-border rounded-xl text-foreground text-sm font-bold focus:outline-none focus:ring-2 focus:ring-primary/50"
                    placeholder="EGP"
                  />
                </div>
              </div>

              <div className="bg-primary/10 border border-primary/30 rounded-xl p-4">
                <p className="text-sm font-bold text-primary mb-2">Price Preview</p>
                <div className="space-y-1 text-sm text-foreground/70">
                  <div className="flex justify-between">
                    <span>50 GB game</span>
                    <span className="font-bold text-green-400 font-nums">{(50 * pricing.pricePerGb).toFixed(2)} {pricing.currency}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>100 GB game</span>
                    <span className="font-bold text-green-400 font-nums">{(100 * pricing.pricePerGb).toFixed(2)} {pricing.currency}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>500 GB total</span>
                    <span className="font-bold text-green-400 font-nums">{(500 * pricing.pricePerGb).toFixed(2)} {pricing.currency}</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2 px-4 py-3 bg-primary/10 border border-primary/30 rounded-xl text-primary text-sm">
              <Save className="w-4 h-4 flex-shrink-0" />
              Pricing changes are saved automatically and take effect immediately for all visitors.
            </div>
          </div>
        )}

        {activeTab === "api_keys" && <ApiKeysTab onFlash={flash} />}
      </div>

      {/* ── EXCEL IMPORT MODAL ── */}
      {showImportModal && (
        <div className="fixed inset-0 z-[300] flex items-center justify-center p-4" onClick={closeImportModal}>
          <div className="absolute inset-0 bg-black/80 backdrop-blur-sm" />
          <div
            className="relative z-10 w-full max-w-4xl max-h-[90vh] flex flex-col bg-card border border-border rounded-2xl shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div className="flex items-center justify-between p-6 border-b border-border flex-shrink-0">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-secondary/15 flex items-center justify-center">
                  <FileSpreadsheet className="w-5 h-5 text-secondary" />
                </div>
                <div>
                  <h2 className="font-bold text-lg text-foreground">Import Games from Excel</h2>
                  <p className="text-xs text-foreground/50">
                    {importRows.length} row{importRows.length !== 1 ? "s" : ""} found
                    {validCount > 0 && <span className="text-green-400"> · {validCount} valid</span>}
                    {invalidCount > 0 && <span className="text-destructive"> · {invalidCount} invalid</span>}
                  </p>
                </div>
              </div>
              <button onClick={closeImportModal} disabled={importing} className="w-9 h-9 rounded-full bg-muted flex items-center justify-center hover:bg-muted/80 disabled:opacity-50 transition-colors">
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Progress bar (while importing) */}
            {importing && (
              <div className="px-6 py-3 border-b border-border flex-shrink-0">
                <div className="flex items-center justify-between text-sm mb-2">
                  <span className="text-foreground/60">Importing games…</span>
                  <span className="font-bold text-foreground">{importProgress.done} / {importProgress.total}</span>
                </div>
                <div className="h-2 bg-muted rounded-full overflow-hidden">
                  <div
                    className="h-full bg-primary transition-all duration-300 rounded-full"
                    style={{ width: `${importProgress.total ? (importProgress.done / importProgress.total) * 100 : 0}%` }}
                  />
                </div>
              </div>
            )}

            {/* Done banner */}
            {importDone && (
              <div className="px-6 py-3 bg-green-500/10 border-b border-green-500/20 flex-shrink-0">
                <div className="flex items-center gap-2 text-green-400 text-sm font-medium">
                  <CheckCircle className="w-4 h-4" />
                  Import complete — {importProgress.done - importProgress.errors} game{importProgress.done - importProgress.errors !== 1 ? "s" : ""} added successfully.
                  {importProgress.errors > 0 && <span className="text-destructive ml-1">({importProgress.errors} failed)</span>}
                </div>
              </div>
            )}

            {/* Table */}
            <div className="overflow-y-auto flex-1">
              <table className="w-full text-sm">
                <thead className="sticky top-0">
                  <tr className="border-b border-border bg-muted/80 backdrop-blur-sm">
                    <th className="px-4 py-3 text-left text-xs font-bold text-foreground/50 uppercase tracking-wider w-8">#</th>
                    <th className="px-4 py-3 text-left text-xs font-bold text-foreground/50 uppercase tracking-wider">Name</th>
                    <th className="px-4 py-3 text-left text-xs font-bold text-foreground/50 uppercase tracking-wider hidden sm:table-cell">ID</th>
                    <th className="px-4 py-3 text-left text-xs font-bold text-foreground/50 uppercase tracking-wider hidden md:table-cell">Size</th>
                    <th className="px-4 py-3 text-left text-xs font-bold text-foreground/50 uppercase tracking-wider hidden lg:table-cell">Source</th>
                    <th className="px-4 py-3 text-left text-xs font-bold text-foreground/50 uppercase tracking-wider">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {importRows.map((row, i) => (
                    <tr key={i} className={`transition-colors ${row._valid ? "hover:bg-muted/20" : "bg-destructive/5"}`}>
                      <td className="px-4 py-2.5 text-xs text-foreground/40">{i + 1}</td>
                      <td className="px-4 py-2.5 font-medium">{row.name || <span className="text-foreground/30 italic">—</span>}</td>
                      <td className="px-4 py-2.5 text-xs text-foreground/50 font-mono hidden sm:table-cell">{row.id || "—"}</td>
                      <td className="px-4 py-2.5 text-xs text-secondary font-bold hidden md:table-cell">{row.size || "—"}</td>
                      <td className="px-4 py-2.5 text-xs text-foreground/50 hidden lg:table-cell">{row.source || "—"}</td>
                      <td className="px-4 py-2.5">
                        {row._valid ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-green-500/15 border border-green-500/30 rounded-full text-[11px] font-medium text-green-400">
                            <CheckCircle className="w-3 h-3" />Ready
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-destructive/15 border border-destructive/30 rounded-full text-[11px] font-medium text-destructive" title={row._error}>
                            <AlertCircle className="w-3 h-3" />{row._error}
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Footer actions */}
            <div className="flex items-center justify-between gap-3 p-6 border-t border-border flex-shrink-0">
              <p className="text-xs text-foreground/40">
                {invalidCount > 0 && `${invalidCount} invalid row${invalidCount !== 1 ? "s" : ""} will be skipped.`}
              </p>
              <div className="flex gap-3">
                <button onClick={closeImportModal} disabled={importing} className="px-5 py-2.5 bg-muted border border-border hover:border-foreground/30 text-foreground font-medium rounded-xl text-sm transition-colors disabled:opacity-50">
                  {importDone ? "Close" : "Cancel"}
                </button>
                {!importDone && (
                  <button
                    onClick={handleImport}
                    disabled={importing || validCount === 0}
                    className="flex items-center gap-2 px-5 py-2.5 bg-secondary hover:bg-secondary/90 disabled:opacity-50 text-black font-bold rounded-xl text-sm transition-all"
                  >
                    {importing ? <Loader2 className="w-4 h-4 animate-spin" /> : <Upload className="w-4 h-4" />}
                    {importing ? `Importing ${importProgress.done}/${importProgress.total}…` : `Import ${validCount} Game${validCount !== 1 ? "s" : ""}`}
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
