import { apiUrl } from "@/lib/api";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface User {
  id: string;
  username?: string;
  email?: string;
  created_at?: string;
  user_metadata?: { username?: string };
}

export interface Game {
  id: string;
  name: string;
  image_url: string;
  size: string;
  source?: string;
  genre?: string;
  created_at?: string;
}

export interface HardDrive {
  id: string;
  name: string;
  image_url: string;
  capacity: string;
  type: string;
  speed: string;
  price: string;
  description?: string;
  created_at?: string;
}

export interface Accessory {
  id: string;
  name: string;
  image_url: string;
  category: string;
  price: string;
  description?: string;
  created_at?: string;
}

// ─── Mode detection ───────────────────────────────────────────────────────────
// Supabase mode: VITE_SUPABASE_URL + VITE_SUPABASE_ANON_KEY are set (Vercel)
// Express mode:  no Supabase env vars — uses the local Express backend (Replit)

const SB_URL = (import.meta.env.VITE_SUPABASE_URL as string | undefined)?.trim();
const SB_KEY = (import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined)?.trim();

export const isSupabaseMode = !!(SB_URL && SB_KEY);
export const isSupabaseConfigured = true;

export const supabase: SupabaseClient | null = isSupabaseMode
  ? createClient(SB_URL!, SB_KEY!)
  : null;

// ─── Helpers ──────────────────────────────────────────────────────────────────

const getAdminToken = () => sessionStorage.getItem("gh_admin_token") || "";

function normalizeUser(u: any): User {
  return {
    id: u.id,
    email: u.email,
    created_at: u.created_at,
    username: u.username || u.user_metadata?.username,
    user_metadata: { username: u.username || u.user_metadata?.username },
  };
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

export const signUp = async (email: string, password: string, username: string): Promise<User> => {
  if (isSupabaseMode) {
    const { data, error } = await supabase!.auth.signUp({ email, password, options: { data: { username } } });
    if (error) throw new Error(error.message);
    return normalizeUser({ ...data.user, username });
  }
  const res = await fetch(apiUrl("/api/auth/register"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ email, password, username }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Registration failed");
  return normalizeUser(data.user);
};

export const signIn = async (email: string, password: string): Promise<User> => {
  if (isSupabaseMode) {
    const { data, error } = await supabase!.auth.signInWithPassword({ email, password });
    if (error) throw new Error(error.message);
    return normalizeUser(data.user);
  }
  const res = await fetch(apiUrl("/api/auth/login"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ email, password }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Invalid login credentials");
  return normalizeUser(data.user);
};

export const signOut = async (): Promise<void> => {
  if (isSupabaseMode) {
    await supabase!.auth.signOut();
    return;
  }
  await fetch(apiUrl("/api/auth/logout"), { method: "POST", credentials: "include" });
};

export const getSession = async (): Promise<{ user: User } | null> => {
  if (isSupabaseMode) {
    const { data } = await supabase!.auth.getSession();
    if (!data.session?.user) return null;
    return { user: normalizeUser(data.session.user) };
  }
  const res = await fetch(apiUrl("/api/auth/me"), { credentials: "include" });
  if (!res.ok) return null;
  const data = await res.json();
  if (!data.user) return null;
  return { user: normalizeUser(data.user) };
};

export const onAuthStateChange = (callback: (user: User | null) => void): { subscription: { unsubscribe: () => void } } => {
  if (isSupabaseMode) {
    const { data } = supabase!.auth.onAuthStateChange((_event, session) => {
      callback(session?.user ? normalizeUser(session.user) : null);
    });
    return data;
  }
  return { subscription: { unsubscribe: () => {} } };
};

// ─── Favorites ────────────────────────────────────────────────────────────────

export const getFavoriteIds = async (): Promise<string[]> => {
  if (isSupabaseMode) {
    const { data: { user } } = await supabase!.auth.getUser();
    if (!user) return [];
    const { data } = await supabase!.from("favorites").select("game_id").eq("user_id", user.id);
    return (data || []).map((r: any) => r.game_id);
  }
  try {
    const res = await fetch(apiUrl("/api/favorites"), { credentials: "include" });
    if (!res.ok) return [];
    const data = await res.json();
    return data.data || [];
  } catch { return []; }
};

export const addFavorite = async (gameId: string): Promise<void> => {
  if (isSupabaseMode) {
    const { data: { user } } = await supabase!.auth.getUser();
    if (!user) throw new Error("Not logged in");
    await supabase!.from("favorites").insert({ user_id: user.id, game_id: gameId });
    return;
  }
  const res = await fetch(apiUrl(`/api/favorites/${encodeURIComponent(gameId)}`), { method: "POST", credentials: "include" });
  if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.error || "Failed to add favorite"); }
};

export const removeFavorite = async (gameId: string): Promise<void> => {
  if (isSupabaseMode) {
    const { data: { user } } = await supabase!.auth.getUser();
    if (!user) throw new Error("Not logged in");
    await supabase!.from("favorites").delete().eq("user_id", user.id).eq("game_id", gameId);
    return;
  }
  const res = await fetch(apiUrl(`/api/favorites/${encodeURIComponent(gameId)}`), { method: "DELETE", credentials: "include" });
  if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.error || "Failed to remove favorite"); }
};

export const getFavoriteGames = async (): Promise<Game[]> => {
  if (isSupabaseMode) {
    const ids = await getFavoriteIds();
    if (!ids.length) return [];
    const { data } = await supabase!.from("games").select("*").in("id", ids);
    return data || [];
  }
  try {
    const res = await fetch(apiUrl("/api/favorites/games"), { credentials: "include" });
    if (!res.ok) return [];
    const data = await res.json();
    return data.data || [];
  } catch { return []; }
};

// ─── Games ────────────────────────────────────────────────────────────────────

export const getGames = async (): Promise<Game[]> => {
  if (isSupabaseMode) {
    const { data, error } = await supabase!.from("games").select("*").order("created_at", { ascending: false });
    if (error) throw new Error(error.message);
    return data || [];
  }
  const res = await fetch(apiUrl("/api/store/games"));
  if (!res.ok) throw new Error("Failed to load games");
  const data = await res.json();
  return data.data || [];
};

export const addGame = async (game: Omit<Game, "created_at">): Promise<void> => {
  if (isSupabaseMode) {
    const { error } = await supabase!.from("games").insert({
      id: game.id, name: game.name, image_url: game.image_url,
      size: game.size, source: game.source || "", genre: game.genre || "",
    });
    if (error) throw new Error(error.message);
    return;
  }
  const token = getAdminToken();
  const res = await fetch(apiUrl("/api/store/games"), {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify({ ...game, genre: game.genre || "" }),
  });
  if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.error || "Failed to add game"); }
};

export const updateGame = async (id: string, updates: Partial<Game>): Promise<void> => {
  if (isSupabaseMode) {
    const { error } = await supabase!.from("games").update({ ...updates, genre: updates.genre || "" }).eq("id", id);
    if (error) throw new Error(error.message);
    return;
  }
  const token = getAdminToken();
  const res = await fetch(apiUrl(`/api/store/games/${encodeURIComponent(id)}`), {
    method: "PUT",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify(updates),
  });
  if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.error || "Failed to update game"); }
};

export const deleteGame = async (id: string): Promise<void> => {
  if (isSupabaseMode) {
    const { error } = await supabase!.from("games").delete().eq("id", id);
    if (error) throw new Error(error.message);
    return;
  }
  const token = getAdminToken();
  const res = await fetch(apiUrl(`/api/store/games/${encodeURIComponent(id)}`), {
    method: "DELETE",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.error || "Failed to delete game"); }
};

export const getGameById = async (id: string): Promise<Game | null> => {
  try { const games = await getGames(); return games.find((g) => g.id === id) || null; }
  catch { return null; }
};

// ─── Hard Drives ──────────────────────────────────────────────────────────────

export const getHardDrives = async (): Promise<HardDrive[]> => {
  if (isSupabaseMode) {
    const { data, error } = await supabase!.from("hard_drives").select("*").order("created_at", { ascending: false });
    if (error) throw new Error(error.message);
    return data || [];
  }
  const res = await fetch(apiUrl("/api/store/hard-drives"));
  if (!res.ok) throw new Error("Failed to load hard drives");
  const data = await res.json();
  return data.data || [];
};

export const addHardDrive = async (hd: Omit<HardDrive, "created_at">): Promise<void> => {
  if (isSupabaseMode) {
    const { error } = await supabase!.from("hard_drives").insert(hd);
    if (error) throw new Error(error.message);
    return;
  }
  const token = getAdminToken();
  const res = await fetch(apiUrl("/api/store/hard-drives"), {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify(hd),
  });
  if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.error || "Failed to add hard drive"); }
};

export const updateHardDrive = async (id: string, updates: Partial<HardDrive>): Promise<void> => {
  if (isSupabaseMode) {
    const { error } = await supabase!.from("hard_drives").update(updates).eq("id", id);
    if (error) throw new Error(error.message);
    return;
  }
  const token = getAdminToken();
  const res = await fetch(apiUrl(`/api/store/hard-drives/${encodeURIComponent(id)}`), {
    method: "PUT",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify(updates),
  });
  if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.error || "Failed to update hard drive"); }
};

export const deleteHardDrive = async (id: string): Promise<void> => {
  if (isSupabaseMode) {
    const { error } = await supabase!.from("hard_drives").delete().eq("id", id);
    if (error) throw new Error(error.message);
    return;
  }
  const token = getAdminToken();
  const res = await fetch(apiUrl(`/api/store/hard-drives/${encodeURIComponent(id)}`), {
    method: "DELETE",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.error || "Failed to delete hard drive"); }
};

// ─── Accessories ─────────────────────────────────────────────────────────────

export const getAccessories = async (): Promise<Accessory[]> => {
  if (isSupabaseMode) {
    const { data, error } = await supabase!.from("accessories").select("*").order("created_at", { ascending: false });
    if (error) throw new Error(error.message);
    return data || [];
  }
  const res = await fetch(apiUrl("/api/store/accessories"));
  if (!res.ok) throw new Error("Failed to load accessories");
  const data = await res.json();
  return data.data || [];
};

export const addAccessory = async (acc: Omit<Accessory, "created_at">): Promise<void> => {
  if (isSupabaseMode) {
    const { error } = await supabase!.from("accessories").insert(acc);
    if (error) throw new Error(error.message);
    return;
  }
  const token = getAdminToken();
  const res = await fetch(apiUrl("/api/store/accessories"), {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify(acc),
  });
  if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.error || "Failed to add accessory"); }
};

export const updateAccessory = async (id: string, updates: Partial<Accessory>): Promise<void> => {
  if (isSupabaseMode) {
    const { error } = await supabase!.from("accessories").update(updates).eq("id", id);
    if (error) throw new Error(error.message);
    return;
  }
  const token = getAdminToken();
  const res = await fetch(apiUrl(`/api/store/accessories/${encodeURIComponent(id)}`), {
    method: "PUT",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify(updates),
  });
  if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.error || "Failed to update accessory"); }
};

export const deleteAccessory = async (id: string): Promise<void> => {
  if (isSupabaseMode) {
    const { error } = await supabase!.from("accessories").delete().eq("id", id);
    if (error) throw new Error(error.message);
    return;
  }
  const token = getAdminToken();
  const res = await fetch(apiUrl(`/api/store/accessories/${encodeURIComponent(id)}`), {
    method: "DELETE",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.error || "Failed to delete accessory"); }
};
