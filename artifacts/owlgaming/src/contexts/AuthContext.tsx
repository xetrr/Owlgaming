import { createContext, useContext, useState, useEffect, useCallback, ReactNode } from "react";
import {
  User, supabase,
  onAuthStateChange, signIn, signOut, signUp,
  getFavoriteIds, addFavorite, removeFavorite,
  isSupabaseConfigured,
} from "@/lib/supabase";

interface AuthContextValue {
  user: User | null;
  loading: boolean;
  favorites: Set<string>;
  showAuthModal: boolean;
  authModalTab: "login" | "signup";
  openAuthModal: (tab?: "login" | "signup") => void;
  closeAuthModal: () => void;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  register: (email: string, password: string, username: string) => Promise<void>;
  toggleFavorite: (gameId: string) => Promise<void>;
  isFavorite: (gameId: string) => boolean;
  refreshFavorites: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [favorites, setFavorites] = useState<Set<string>>(new Set());
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [authModalTab, setAuthModalTab] = useState<"login" | "signup">("login");

  const refreshFavorites = useCallback(async () => {
    if (!isSupabaseConfigured) return;
    const ids = await getFavoriteIds();
    setFavorites(new Set(ids));
  }, []);

  useEffect(() => {
    if (!isSupabaseConfigured) { setLoading(false); return; }

    supabase!.auth.getSession().then(({ data }) => {
      const u = data.session?.user ?? null;
      setUser(u);
      if (u) refreshFavorites();
      setLoading(false);
    });

    const { data: { subscription } } = onAuthStateChange((u) => {
      setUser(u);
      if (u) refreshFavorites();
      else setFavorites(new Set());
    });

    return () => subscription.unsubscribe();
  }, [refreshFavorites]);

  const openAuthModal = (tab: "login" | "signup" = "login") => {
    setAuthModalTab(tab);
    setShowAuthModal(true);
  };

  const closeAuthModal = () => setShowAuthModal(false);

  const login = async (email: string, password: string) => {
    await signIn(email, password);
    closeAuthModal();
  };

  const logout = async () => {
    await signOut();
    setFavorites(new Set());
  };

  const register = async (email: string, password: string, username: string) => {
    await signUp(email, password, username);
    closeAuthModal();
  };

  const toggleFavorite = async (gameId: string) => {
    if (!user) { openAuthModal("login"); return; }
    const already = favorites.has(gameId);
    const next = new Set(favorites);
    if (already) {
      next.delete(gameId);
      setFavorites(next);
      await removeFavorite(gameId).catch(() => {
        next.add(gameId);
        setFavorites(new Set(next));
      });
    } else {
      next.add(gameId);
      setFavorites(next);
      await addFavorite(gameId).catch(() => {
        next.delete(gameId);
        setFavorites(new Set(next));
      });
    }
  };

  const isFavorite = (gameId: string) => favorites.has(gameId);

  return (
    <AuthContext.Provider value={{
      user, loading, favorites, showAuthModal, authModalTab,
      openAuthModal, closeAuthModal,
      login, logout, register,
      toggleFavorite, isFavorite, refreshFavorites,
    }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
