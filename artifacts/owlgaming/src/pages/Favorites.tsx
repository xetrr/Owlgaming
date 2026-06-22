import { useState, useEffect } from "react";
import { Heart, Trash2, Eye, LogIn, Loader2, Gamepad2 } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";
import { getFavoriteGames, Game } from "@/lib/supabase";
import GamePreviewModal from "@/components/GamePreviewModal";
import { useLang } from "@/contexts/LanguageContext";

export default function Favorites() {
  const { user, loading: authLoading, openAuthModal, toggleFavorite, refreshFavorites } = useAuth();
  const { t } = useLang();
  const [games, setGames] = useState<Game[]>([]);
  const [loading, setLoading] = useState(false);
  const [previewGame, setPreviewGame] = useState<Game | null>(null);

  const loadFavorites = async () => {
    if (!user) return;
    setLoading(true);
    try {
      const data = await getFavoriteGames();
      setGames(data);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (user) loadFavorites();
    else setGames([]);
  }, [user]);

  const handleRemove = async (game: Game) => {
    await toggleFavorite(game.id);
    await refreshFavorites();
    setGames((prev) => prev.filter((g) => g.id !== game.id));
  };

  if (authLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  if (!user) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background px-4">
        <div className="h-16" />
        <div className="text-center space-y-5 max-w-sm">
          <div className="w-20 h-20 rounded-2xl bg-primary/15 flex items-center justify-center mx-auto">
            <Heart className="w-10 h-10 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-black text-foreground mb-2">{t("fav_title")}</h1>
            <p className="text-foreground/60 text-sm">{t("fav_signInPrompt")}</p>
          </div>
          <button
            onClick={() => openAuthModal("login")}
            className="inline-flex items-center gap-2 px-6 py-3 bg-primary hover:bg-primary/90 text-white font-bold rounded-xl transition-all"
          >
            <LogIn className="w-4 h-4" />
            {t("fav_signInBtn")}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="h-16" />
      <div className="container mx-auto px-4 py-10">
        <div className="flex items-center gap-3 mb-8">
          <div className="w-10 h-10 rounded-xl bg-primary/15 flex items-center justify-center">
            <Heart className="w-5 h-5 text-primary fill-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-black text-foreground">{t("fav_title")}</h1>
            <p className="text-sm text-foreground/50">
              {loading ? t("fav_loading") : `${games.length} ${games.length !== 1 ? t("fav_games") : t("fav_game")} ${t("fav_saved")}`}
            </p>
          </div>
        </div>

        {loading ? (
          <div className="flex justify-center py-20">
            <Loader2 className="w-8 h-8 animate-spin text-primary" />
          </div>
        ) : games.length === 0 ? (
          <div className="text-center py-20 space-y-4">
            <div className="w-16 h-16 rounded-2xl bg-muted flex items-center justify-center mx-auto">
              <Gamepad2 className="w-8 h-8 text-foreground/30" />
            </div>
            <p className="text-foreground/50 text-lg font-medium">{t("fav_empty_title")}</p>
            <p className="text-foreground/40 text-sm">{t("fav_empty_desc")}</p>
            <a href="/games" className="inline-flex items-center gap-2 px-5 py-2.5 bg-primary hover:bg-primary/90 text-white font-bold rounded-xl transition-all text-sm mt-2">
              {t("fav_browse")}
            </a>
          </div>
        ) : (
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-6 gap-4">
            {games.map((game) => (
              <div key={game.id} className="group relative bg-card border border-border rounded-xl overflow-hidden hover:border-primary/40 transition-all">
                <div className="aspect-video overflow-hidden">
                  <img
                    src={game.image_url}
                    alt={game.name}
                    loading="lazy"
                    decoding="async"
                    className="w-full h-full object-contain transition-transform duration-500 group-hover:scale-105"
                  />
                </div>

                <div className="absolute top-1.5 left-1.5 px-2 py-0.5 bg-black/80 border border-secondary/50 rounded-md">
                  <span className="text-[11px] font-black text-secondary">{game.size}</span>
                </div>

                <div className="absolute top-1.5 right-1.5 flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                  <button
                    onClick={() => setPreviewGame(game)}
                    className="w-7 h-7 bg-black/80 border border-white/10 rounded-lg flex items-center justify-center hover:bg-primary/50 transition-colors"
                    title="Preview"
                  >
                    <Eye className="w-3.5 h-3.5 text-white" />
                  </button>
                  <button
                    onClick={() => handleRemove(game)}
                    className="w-7 h-7 bg-black/80 border border-white/10 rounded-lg flex items-center justify-center hover:bg-destructive/50 transition-colors"
                    title="Remove from favorites"
                  >
                    <Trash2 className="w-3.5 h-3.5 text-white" />
                  </button>
                </div>

                <div className="p-2.5">
                  <p className="text-xs font-bold text-foreground truncate" dir="ltr">{game.name}</p>
                  {game.source && (
                    <p className="text-[10px] text-foreground/40 truncate mt-0.5">{game.source}</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {previewGame && (
        <GamePreviewModal
          game={{ id: previewGame.id, title: previewGame.name, image: previewGame.image_url, size: previewGame.size, source: previewGame.source }}
          onClose={() => setPreviewGame(null)}
        />
      )}
    </div>
  );
}
