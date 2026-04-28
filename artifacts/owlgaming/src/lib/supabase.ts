import { createClient, SupabaseClient, User } from "@supabase/supabase-js";

const ENV_URL = import.meta.env.VITE_SUPABASE_URL as string;
const ENV_KEY = import.meta.env.VITE_SUPABASE_ANON_KEY as string;

// Read active keys — localStorage overrides env vars (applied at page load)
const getActiveUrl = (): string => {
  try { return localStorage.getItem("gh_supabase_url") || ENV_URL; } catch { return ENV_URL; }
};
const getActiveKey = (): string => {
  try { return localStorage.getItem("gh_supabase_key") || ENV_KEY; } catch { return ENV_KEY; }
};

const activeUrl = getActiveUrl();
const activeKey = getActiveKey();

export const isSupabaseConfigured = !!(
  activeUrl && activeUrl.startsWith("https://") &&
  activeKey && activeKey.length > 10
);

export const supabase: SupabaseClient | null = isSupabaseConfigured
  ? createClient(activeUrl, activeKey)
  : null;

export type { User };

// ─── Auth ─────────────────────────────────────────────────────────────────────

export const signUp = async (email: string, password: string, username: string) => {
  if (!supabase) throw new Error("Supabase not configured");
  const { data, error } = await supabase.auth.signUp({
    email,
    password,
    options: { data: { username } },
  });
  if (error) throw error;
  return data.user;
};

export const signIn = async (email: string, password: string) => {
  if (!supabase) throw new Error("Supabase not configured");
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) throw error;
  return data.user;
};

export const signOut = async () => {
  if (!supabase) return;
  await supabase.auth.signOut();
};

export const getSession = async () => {
  if (!supabase) return null;
  const { data } = await supabase.auth.getSession();
  return data.session;
};

export const onAuthStateChange = (callback: (user: User | null) => void) => {
  if (!supabase) return { data: { subscription: { unsubscribe: () => {} } } };
  return supabase.auth.onAuthStateChange((_event, session) => {
    callback(session?.user ?? null);
  });
};

// ─── Favorites ────────────────────────────────────────────────────────────────

export const getFavoriteIds = async (): Promise<string[]> => {
  if (!supabase) return [];
  const { data, error } = await supabase
    .from("favorites")
    .select("game_id");
  if (error) return [];
  return (data || []).map((r: any) => r.game_id);
};

export const addFavorite = async (gameId: string): Promise<void> => {
  if (!supabase) throw new Error("Supabase not configured");
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) throw new Error("Not logged in");
  const { error } = await supabase.from("favorites").insert({ user_id: user.id, game_id: gameId });
  if (error && error.code !== "23505") throw error;
};

export const removeFavorite = async (gameId: string): Promise<void> => {
  if (!supabase) throw new Error("Supabase not configured");
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) throw new Error("Not logged in");
  const { error } = await supabase.from("favorites").delete().eq("game_id", gameId).eq("user_id", user.id);
  if (error) throw error;
};

export const getFavoriteGames = async (): Promise<Game[]> => {
  if (!supabase) return [];
  const { data, error } = await supabase
    .from("favorites")
    .select("games(*)")
    .order("created_at", { ascending: false });
  if (error) return [];
  return (data || []).map((r: any) => r.games).filter(Boolean);
};

// ─── Games ────────────────────────────────────────────────────────────────────

export interface Game {
  id: string;
  name: string;
  image_url: string;
  size: string;
  source?: string;
  created_at?: string;
}

export const getGames = async (): Promise<Game[]> => {
  if (!supabase) return [];
  const { data, error } = await supabase
    .from("games")
    .select("*")
    .order("created_at", { ascending: false });
  if (error) throw error;
  return data || [];
};

export const addGame = async (game: Omit<Game, "created_at">): Promise<void> => {
  if (!supabase) throw new Error("Supabase not configured");
  const { error } = await supabase.from("games").insert(game);
  if (error) throw error;
};

export const updateGame = async (id: string, updates: Partial<Game>): Promise<void> => {
  if (!supabase) throw new Error("Supabase not configured");
  const { error } = await supabase.from("games").update(updates).eq("id", id);
  if (error) throw error;
};

export const deleteGame = async (id: string): Promise<void> => {
  if (!supabase) throw new Error("Supabase not configured");
  const { error } = await supabase.from("games").delete().eq("id", id);
  if (error) throw error;
};

export const getGameById = async (id: string): Promise<Game | null> => {
  if (!supabase) return null;
  const { data, error } = await supabase
    .from("games")
    .select("*")
    .eq("id", id)
    .single();
  if (error) return null;
  return data;
};

// ─── Hard Drives ──────────────────────────────────────────────────────────────

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

export const getHardDrives = async (): Promise<HardDrive[]> => {
  if (!supabase) return [];
  const { data, error } = await supabase
    .from("hard_drives")
    .select("*")
    .order("created_at", { ascending: false });
  if (error) throw error;
  return data || [];
};

export const addHardDrive = async (hd: Omit<HardDrive, "created_at">): Promise<void> => {
  if (!supabase) throw new Error("Supabase not configured");
  const { error } = await supabase.from("hard_drives").insert(hd);
  if (error) throw error;
};

export const updateHardDrive = async (id: string, updates: Partial<HardDrive>): Promise<void> => {
  if (!supabase) throw new Error("Supabase not configured");
  const { error } = await supabase.from("hard_drives").update(updates).eq("id", id);
  if (error) throw error;
};

export const deleteHardDrive = async (id: string): Promise<void> => {
  if (!supabase) throw new Error("Supabase not configured");
  const { error } = await supabase.from("hard_drives").delete().eq("id", id);
  if (error) throw error;
};

// ─── Accessories ───────────────────────────────────────────────────────────────

export interface Accessory {
  id: string;
  name: string;
  image_url: string;
  category: string;
  price: string;
  description?: string;
  created_at?: string;
}

export const getAccessories = async (): Promise<Accessory[]> => {
  if (!supabase) return [];
  const { data, error } = await supabase
    .from("accessories")
    .select("*")
    .order("created_at", { ascending: false });
  if (error) throw error;
  return data || [];
};

export const addAccessory = async (acc: Omit<Accessory, "created_at">): Promise<void> => {
  if (!supabase) throw new Error("Supabase not configured");
  const { error } = await supabase.from("accessories").insert(acc);
  if (error) throw error;
};

export const updateAccessory = async (id: string, updates: Partial<Accessory>): Promise<void> => {
  if (!supabase) throw new Error("Supabase not configured");
  const { error } = await supabase.from("accessories").update(updates).eq("id", id);
  if (error) throw error;
};

export const deleteAccessory = async (id: string): Promise<void> => {
  if (!supabase) throw new Error("Supabase not configured");
  const { error } = await supabase.from("accessories").delete().eq("id", id);
  if (error) throw error;
};
