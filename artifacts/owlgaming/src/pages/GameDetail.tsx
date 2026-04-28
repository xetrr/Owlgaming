import { useParams, Link, useLocation } from "react-router-dom";
import { useState, useEffect } from "react";
import {
  ArrowLeft, Star, HardDrive, Loader2, ShoppingCart,
  X, ChevronLeft, ChevronRight, Play,
} from "lucide-react";
import { useCart } from "@/contexts/CartContext";
import { getGameById as getGameFromDB } from "@/lib/supabase";
import { searchGameByName, getGameScreenshots, getGameMovies, RAWGGame, RAWGMovie } from "@/services/rawg";

const SAMPLE_GAMES = [
  { id: "resident-evil-2", name: "Resident Evil 2", image_url: "https://images.unsplash.com/photo-1578979881614-f4fb84857d11?w=400&h=225&fit=crop", size: "45GB" },
  { id: "resident-evil-3", name: "Resident Evil 3", image_url: "https://images.unsplash.com/photo-1585647347384-c0eb908cb4d8?w=400&h=225&fit=crop", size: "48GB" },
  { id: "resident-evil-4", name: "Resident Evil 4 Remake", image_url: "https://images.unsplash.com/photo-1534531173927-c81fca934829?w=400&h=225&fit=crop", size: "52GB" },
  { id: "resident-evil-village", name: "Resident Evil Village", image_url: "https://images.unsplash.com/photo-1492684223066-81342ee5ff30?w=400&h=225&fit=crop", size: "50GB" },
  { id: "alan-wake-2", name: "Alan Wake 2", image_url: "https://images.unsplash.com/photo-1552820728-8ac41f1ce891?w=400&h=225&fit=crop", size: "90GB" },
  { id: "the-witcher-3", name: "The Witcher 3: Wild Hunt", image_url: "https://images.unsplash.com/photo-1598488035139-bdbb2231ce04?w=400&h=225&fit=crop", size: "140GB" },
  { id: "cyberpunk-2077", name: "Cyberpunk 2077", image_url: "https://images.unsplash.com/photo-1561070791-2526d30994b5?w=400&h=225&fit=crop", size: "130GB" },
  { id: "elden-ring", name: "Elden Ring", image_url: "https://images.unsplash.com/photo-1552861561-340531ee7757?w=400&h=225&fit=crop", size: "60GB" },
  { id: "baldurs-gate-3", name: "Baldur's Gate 3", image_url: "https://images.unsplash.com/photo-1535889713233-33f3dda7b751?w=400&h=225&fit=crop", size: "150GB" },
  { id: "starfield", name: "Starfield", image_url: "https://images.unsplash.com/photo-1569163139394-de4798aa62b1?w=400&h=225&fit=crop", size: "125GB" },
  { id: "final-fantasy-16", name: "Final Fantasy XVI", image_url: "https://images.unsplash.com/photo-1614613535308-eb5fbd8f2c5c?w=400&h=225&fit=crop", size: "140GB" },
  { id: "tekken-8", name: "TEKKEN 8", image_url: "https://images.unsplash.com/photo-1577720643272-265a55e20cbb?w=400&h=225&fit=crop", size: "160GB" },
];

export default function GameDetail() {
  const { id } = useParams<{ id: string }>();
  const location = useLocation();
  const { addItem, removeItem, state } = useCart();

  const [gameInfo, setGameInfo] = useState<{ id: string; name: string; image_url: string; size: string } | null>(null);
  const [rawgData, setRawgData] = useState<RAWGGame | null>(null);
  const [screenshots, setScreenshots] = useState<string[]>([]);
  const [movies, setMovies] = useState<RAWGMovie[]>([]);
  const [loading, setLoading] = useState(true);
  const [lightboxIndex, setLightboxIndex] = useState<number | null>(null);

  const isInCart = state.items.some((item) => item.id === id);

  const handleToggleCart = () => {
    if (!gameInfo) return;
    if (isInCart) {
      removeItem(gameInfo.id);
    } else {
      addItem({ id: gameInfo.id, title: gameInfo.name, size: gameInfo.size, price: 0, image: gameInfo.image_url });
    }
  };

  useEffect(() => {
    if (!id) return;
    const load = async () => {
      setLoading(true);
      try {
        let info: { id: string; name: string; image_url: string; size: string } | null = null;

        const locState = location.state as { name?: string; image_url?: string; size?: string } | null;
        if (locState?.name) {
          info = { id, name: locState.name, image_url: locState.image_url || "", size: locState.size || "" };
        }

        if (!info) {
          const dbGame = await getGameFromDB(id);
          if (dbGame) info = { id: dbGame.id, name: dbGame.name, image_url: dbGame.image_url, size: dbGame.size };
        }

        if (!info) {
          const sample = SAMPLE_GAMES.find((g) => g.id === id);
          if (sample) info = sample;
        }

        if (!info) {
          const nameFallback = id.replace(/-/g, " ");
          info = { id, name: nameFallback, image_url: "", size: "Unknown" };
        }

        setGameInfo(info);

        const [rawg, shots, vids] = await Promise.all([
          searchGameByName(info.name),
          Promise.resolve([] as string[]),
          Promise.resolve([] as RAWGMovie[]),
        ]);

        setRawgData(rawg);

        if (rawg) {
          const [moreShots, moreVids] = await Promise.all([
            getGameScreenshots(rawg.id),
            getGameMovies(rawg.id),
          ]);
          setScreenshots(moreShots);
          setMovies(moreVids);
        }
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [id]);

  const allImages = gameInfo?.image_url ? [gameInfo.image_url, ...screenshots] : screenshots;

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center space-y-4">
          <Loader2 className="w-12 h-12 animate-spin text-primary mx-auto" />
          <p className="text-foreground/60">Loading game details...</p>
        </div>
      </div>
    );
  }

  if (!gameInfo) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center space-y-4">
          <p className="text-xl font-bold text-foreground">Game not found</p>
          <Link to="/games" className="text-primary hover:underline">← Back to Games</Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen">
      <div className="h-16" />

      {/* Lightbox */}
      {lightboxIndex !== null && (
        <div className="fixed inset-0 z-[100] bg-black/95 flex items-center justify-center" onClick={() => setLightboxIndex(null)}>
          <button className="absolute top-4 right-4 p-2 bg-white/10 rounded-full" onClick={() => setLightboxIndex(null)}>
            <X className="w-5 h-5 text-white" />
          </button>
          <button className="absolute left-4 p-2 bg-white/10 rounded-full" onClick={(e) => { e.stopPropagation(); setLightboxIndex(Math.max(0, lightboxIndex - 1)); }}>
            <ChevronLeft className="w-5 h-5 text-white" />
          </button>
          <img src={allImages[lightboxIndex]} decoding="async" className="max-w-[90vw] max-h-[85vh] object-contain rounded-xl" onClick={(e) => e.stopPropagation()} />
          <button className="absolute right-4 p-2 bg-white/10 rounded-full" onClick={(e) => { e.stopPropagation(); setLightboxIndex(Math.min(allImages.length - 1, lightboxIndex + 1)); }}>
            <ChevronRight className="w-5 h-5 text-white" />
          </button>
          <p className="absolute bottom-4 text-white/50 text-sm">{lightboxIndex + 1} / {allImages.length}</p>
        </div>
      )}

      {/* Hero */}
      {rawgData?.background_image || gameInfo.image_url ? (
        <div className="relative h-64 md:h-80 overflow-hidden">
          <img src={rawgData?.background_image || gameInfo.image_url} alt={gameInfo.name} loading="lazy" decoding="async" className="w-full h-full object-cover" />
          <div className="absolute inset-0 bg-gradient-to-t from-background via-background/60 to-transparent" />
        </div>
      ) : (
        <div className="h-32 bg-gradient-to-r from-primary/20 to-secondary/20" />
      )}

      <div className="container mx-auto px-4 py-6 -mt-16 relative z-10">
        <Link to="/games" className="inline-flex items-center gap-2 text-sm text-foreground/60 hover:text-foreground mb-6 transition-colors">
          <ArrowLeft className="w-4 h-4" /> Back to Games
        </Link>

        <div className="grid lg:grid-cols-3 gap-8">
          {/* Left / Main info */}
          <div className="lg:col-span-2 space-y-6">
            <div>
              <h1 className="text-3xl md:text-4xl font-black text-foreground mb-3">{gameInfo.name}</h1>
              <div className="flex flex-wrap gap-3">
                <div className="flex items-center gap-1.5 px-3 py-1.5 bg-card border border-border rounded-lg text-sm">
                  <HardDrive className="w-4 h-4 text-secondary" />
                  <span className="font-black text-secondary text-base tracking-wide font-nums">
                    {/\d/.test(gameInfo.size) && !/[a-zA-Z]/.test(gameInfo.size) ? `${gameInfo.size} GB` : gameInfo.size}
                  </span>
                </div>
                {rawgData?.rating ? (
                  <div className="flex items-center gap-1.5 px-3 py-1.5 bg-card border border-border rounded-lg text-sm">
                    <Star className="w-4 h-4 text-yellow-400 fill-yellow-400" />
                    <span className="font-bold text-foreground font-nums">{rawgData.rating.toFixed(1)} / 5</span>
                  </div>
                ) : null}
                {rawgData?.metacritic ? (
                  <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-sm font-bold ${rawgData.metacritic >= 75 ? "bg-green-500/15 border-green-500/30 text-green-400" : rawgData.metacritic >= 50 ? "bg-yellow-500/15 border-yellow-500/30 text-yellow-400" : "bg-red-500/15 border-red-500/30 text-red-400"}`}>
                    Metacritic {rawgData.metacritic}
                  </div>
                ) : null}
                {rawgData?.released ? (
                  <div className="px-3 py-1.5 bg-card border border-border rounded-lg text-sm text-foreground/60">
                    {new Date(rawgData.released).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })}
                  </div>
                ) : null}
              </div>
            </div>

            {/* Genres */}
            {rawgData?.genres?.length ? (
              <div className="flex flex-wrap gap-2">
                {rawgData.genres.map((g) => (
                  <span key={g.id} className="px-2.5 py-1 bg-primary/15 border border-primary/25 rounded-full text-xs font-medium text-primary">{g.name}</span>
                ))}
              </div>
            ) : null}

            {/* Description */}
            {rawgData?.description_raw ? (
              <div>
                <h2 className="text-lg font-bold mb-3">About</h2>
                <p className="text-sm text-foreground/70 leading-relaxed line-clamp-6">{rawgData.description_raw}</p>
              </div>
            ) : null}

            {/* Trailer */}
            {movies.length > 0 && (
              <div>
                <h2 className="text-lg font-bold mb-3">Trailer</h2>
                <div className="relative rounded-xl overflow-hidden bg-black aspect-video">
                  <video
                    controls
                    poster={movies[0].preview}
                    className="w-full h-full"
                    key={movies[0].id}
                  >
                    <source src={movies[0].data?.max || movies[0].data?.["480"]} type="video/mp4" />
                  </video>
                  {!movies[0].data?.max && !movies[0].data?.["480"] && (
                    <div className="absolute inset-0 flex items-center justify-center bg-black/60">
                      <Play className="w-12 h-12 text-white/50" />
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Screenshots */}
            {allImages.length > 1 && (
              <div>
                <h2 className="text-lg font-bold mb-3">Screenshots</h2>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                  {allImages.slice(1, 7).map((img, i) => (
                    <div key={i} className="relative aspect-video rounded-lg overflow-hidden cursor-pointer border border-border hover:border-primary/50 transition-colors" onClick={() => setLightboxIndex(i + 1)}>
                      <img src={img} alt={`Screenshot ${i + 1}`} loading="lazy" decoding="async" className="w-full h-full object-cover hover:scale-105 transition-transform duration-300" />
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Right sidebar */}
          <div className="lg:col-span-1">
            <div className="bg-card border border-border rounded-xl p-6 sticky top-24 space-y-5">
              <div className="w-full aspect-video rounded-lg overflow-hidden border border-border">
                <img src={gameInfo.image_url || rawgData?.background_image} alt={gameInfo.name} loading="lazy" decoding="async" className="w-full h-full object-cover" />
              </div>

              <div className="space-y-2">
                <h3 className="font-bold text-lg">{gameInfo.name}</h3>
                <div className="flex items-center gap-2 text-secondary">
                  <HardDrive className="w-4 h-4" />
                  <span className="font-black text-base tracking-wide">
                    {/\d/.test(gameInfo.size) && !/[a-zA-Z]/.test(gameInfo.size) ? `${gameInfo.size} GB` : gameInfo.size}
                  </span>
                </div>
              </div>

              <button
                onClick={handleToggleCart}
                className={`w-full py-3 font-bold rounded-xl flex items-center justify-center gap-2 ${isInCart ? "bg-destructive/80 hover:bg-destructive border border-destructive text-white transition-all" : "btn-gradient"}`}
              >
                {isInCart ? <X className="w-4 h-4" /> : <ShoppingCart className="w-4 h-4" />}
                {isInCart ? "Remove from Cart" : "Add to Cart"}
              </button>

              {rawgData && (
                <div className="space-y-2 text-sm border-t border-border pt-4">
                  {rawgData.developers?.length ? (
                    <div className="flex justify-between">
                      <span className="text-foreground/50">Developer</span>
                      <span className="font-medium text-right">{rawgData.developers.map(d => d.name).join(", ")}</span>
                    </div>
                  ) : null}
                  {rawgData.publishers?.length ? (
                    <div className="flex justify-between">
                      <span className="text-foreground/50">Publisher</span>
                      <span className="font-medium text-right">{rawgData.publishers.map(p => p.name).join(", ")}</span>
                    </div>
                  ) : null}
                  {rawgData.playtime ? (
                    <div className="flex justify-between">
                      <span className="text-foreground/50">Avg. Playtime</span>
                      <span className="font-medium">{rawgData.playtime}h</span>
                    </div>
                  ) : null}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
