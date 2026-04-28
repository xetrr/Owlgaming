import { useEffect, useState } from "react";
import {
  X, HardDrive, Loader2, ShoppingCart, MessageCircle, Star,
  Calendar, Package, Monitor,
} from "lucide-react";
import { useCart } from "@/contexts/CartContext";
import { useLang } from "@/contexts/LanguageContext";
import { searchGameByName, getGameScreenshots, getGameMovies, RAWGGame, RAWGMovie } from "@/services/rawg";
import { searchIGDBGame, IGDBGame } from "@/services/igdb";

interface GamePreviewModalProps {
  game: { id: string; title: string; image: string; size: string; source?: string } | null;
  onClose: () => void;
}

export default function GamePreviewModal({ game, onClose }: GamePreviewModalProps) {
  const { addItem, removeItem, state } = useCart();
  const { lang } = useLang();
  const [rawg, setRawg] = useState<RAWGGame | null>(null);
  const [igdb, setIgdb] = useState<IGDBGame | null>(null);
  const [screenshots, setScreenshots] = useState<string[]>([]);
  const [movies, setMovies] = useState<RAWGMovie[]>([]);
  const [loading, setLoading] = useState(false);
  const [activeShot, setActiveShot] = useState<string | null>(null);

  const isInCart = game ? state.items.some((item) => item.id === game.id) : false;

  const isAr = lang === "ar";

  const handleToggleCart = () => {
    if (!game) return;
    if (isInCart) removeItem(game.id);
    else addItem({ id: game.id, title: game.title, size: game.size, price: 0, image: game.image });
  };

  useEffect(() => {
    if (!game) return;
    setRawg(null);
    setIgdb(null);
    setScreenshots([]);
    setMovies([]);
    setActiveShot(null);
    setLoading(true);

    const load = async () => {
      try {
        const [rawgData, igdbData] = await Promise.all([
          searchGameByName(game.title),
          searchIGDBGame(game.title),
        ]);
        setRawg(rawgData);
        setIgdb(igdbData);
        if (rawgData) {
          const [shots, vids] = await Promise.all([
            getGameScreenshots(rawgData.id),
            getGameMovies(rawgData.id),
          ]);
          const igdbShots = igdbData?.screenshots || [];
          const merged = [...new Set([...shots, ...igdbShots])];
          setScreenshots(merged);
          setMovies(vids);
        } else if (igdbData?.screenshots?.length) {
          setScreenshots(igdbData.screenshots);
        }
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [game?.id]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
    };
  }, [onClose]);

  if (!game) return null;

  const coverImage = activeShot ?? rawg?.background_image ?? igdb?.coverUrl ?? game.image;

  const releaseDate = rawg?.released
    ? new Date(rawg.released).toLocaleDateString(isAr ? "ar-EG" : "en-US", {
        year: "numeric", month: "long", day: "numeric",
      })
    : igdb?.releaseYear
    ? String(igdb.releaseYear)
    : null;

  const description = rawg?.description_raw ?? igdb?.summary ?? null;
  const genres = rawg?.genres?.map(g => g.name) ?? igdb?.genres ?? [];
  const rating = rawg?.rating ?? igdb?.rating ?? null;
  const sysReqs = rawg?.pc_requirements ?? null;

  const hasAnyDetails =
    !!description ||
    genres.length > 0 ||
    !!rating ||
    !!releaseDate ||
    screenshots.length > 0 ||
    movies.length > 0 ||
    !!sysReqs;

  const sectionHeader = (label: string) => (
    <h3 className="text-sm font-bold text-primary tracking-wider mb-3" dir="auto">
      {label}
    </h3>
  );

  return (
    <div
      className="fixed inset-0 z-[200] flex items-center justify-center p-3 sm:p-4"
      onClick={onClose}
    >
      <div className="absolute inset-0 bg-black/85 backdrop-blur-sm" />

      <div
        className="relative z-10 w-full max-w-lg max-h-[92vh] overflow-y-auto rounded-2xl shadow-2xl"
        style={{ background: "hsl(228 19% 10%)", border: "1px solid hsl(228 16% 20%)" }}
        onClick={(e) => e.stopPropagation()}
        dir={isAr ? "rtl" : "ltr"}
      >
        {/* Close button */}
        <button
          onClick={onClose}
          className="absolute top-3 right-3 z-20 w-8 h-8 rounded-full bg-black/60 border border-white/15 flex items-center justify-center hover:bg-black/80 transition-colors"
          aria-label="Close"
        >
          <X className="w-4 h-4 text-white" />
        </button>

        {/* Cover image */}
        <div className="relative w-full overflow-hidden rounded-t-2xl" style={{ aspectRatio: "16/9" }}>
          {coverImage ? (
            <img
              src={coverImage}
              alt={game.title}
              loading="lazy"
              decoding="async"
              className="w-full h-full object-cover"
            />
          ) : (
            <div className="w-full h-full flex items-center justify-center bg-muted">
              <HardDrive className="w-12 h-12 text-foreground/20" />
            </div>
          )}
          <div className="absolute inset-0 bg-gradient-to-t from-[hsl(228_19%_10%)] via-transparent to-transparent" />
        </div>

        {/* Content */}
        <div className="px-5 pb-5 space-y-4 -mt-1">

          {/* Title */}
          <div>
            <h2 className="text-xl font-black text-white leading-tight mb-2" dir="auto">
              {game.title}
            </h2>

            {/* Release date */}
            {releaseDate && (
              <div className="flex items-center gap-1.5 text-sm text-foreground/50 mb-3">
                <Calendar className="w-3.5 h-3.5 flex-shrink-0" />
                <span>
                  {isAr ? "تاريخ الإصدار: " : "Released: "}
                  <span className="text-foreground/70">{releaseDate}</span>
                </span>
              </div>
            )}

            {/* Badges row */}
            <div className="flex flex-wrap gap-2">
              {/* Size badge */}
              <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-bold"
                style={{ background: "hsl(228 19% 15%)", border: "1px solid hsl(228 16% 22%)" }}>
                <HardDrive className="w-3.5 h-3.5 text-secondary" />
                <span className="text-white font-nums">{game.size}</span>
              </div>

              {/* Source badge */}
              {game.source && (
                <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-bold"
                  style={{ background: "hsl(228 19% 15%)", border: "1px solid hsl(228 16% 22%)" }}>
                  <Package className="w-3.5 h-3.5 text-foreground/50" />
                  <span className="text-foreground/80">
                    {game.source.startsWith("http")
                      ? game.source.replace(/^https?:\/\//, "").split("/")[0]
                      : game.source}
                  </span>
                </div>
              )}

              {/* Rating */}
              {rating ? (
                <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-bold bg-yellow-500/10 border border-yellow-500/25">
                  <Star className="w-3.5 h-3.5 text-yellow-400 fill-yellow-400" />
                  <span className="text-yellow-300">{rating.toFixed(1)}</span>
                </div>
              ) : null}

              {/* Metacritic */}
              {rawg?.metacritic ? (
                <div className={`px-3 py-1.5 rounded-lg text-sm font-bold border ${
                  rawg.metacritic >= 75
                    ? "bg-green-500/15 border-green-500/30 text-green-400"
                    : rawg.metacritic >= 50
                    ? "bg-yellow-500/15 border-yellow-500/30 text-yellow-400"
                    : "bg-red-500/15 border-red-500/30 text-red-400"
                }`}>
                  MC {rawg.metacritic}
                </div>
              ) : null}
            </div>

            {/* Genres */}
            {genres.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mt-3">
                {genres.map((name) => (
                  <span key={name} className="px-2.5 py-1 bg-primary/10 border border-primary/20 rounded-full text-xs font-medium text-primary">
                    {name}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Loading */}
          {loading && (
            <div className="flex items-center gap-2 text-foreground/40 text-sm">
              <Loader2 className="w-4 h-4 animate-spin" />
              <span>{isAr ? "جاري تحميل تفاصيل اللعبة…" : "Fetching game details…"}</span>
            </div>
          )}

          {/* Description */}
          {description && (
            <div>
              {sectionHeader(isAr ? "الوصف" : "About")}
              <p className="text-sm text-foreground/65 leading-relaxed line-clamp-5" dir="auto">
                {description}
              </p>
            </div>
          )}

          {/* Screenshots */}
          {screenshots.length > 0 && (
            <div>
              {sectionHeader(isAr ? "لقطات الشاشة" : "Screenshots")}
              <div className="grid grid-cols-3 gap-2">
                {screenshots.slice(0, 6).map((shot, i) => (
                  <button
                    key={i}
                    onClick={() => setActiveShot(shot === activeShot ? null : shot)}
                    className={`aspect-video overflow-hidden rounded-lg border-2 transition-all ${
                      activeShot === shot ? "border-primary" : "border-transparent hover:border-primary/50"
                    }`}
                  >
                    <img src={shot} alt={`Screenshot ${i + 1}`} loading="lazy" decoding="async" className="w-full h-full object-cover" />
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Trailer */}
          {movies.length > 0 && movies[0].data && (
            <div>
              {sectionHeader(isAr ? "الإعلان الرسمي" : "Trailer")}
              <div className="relative rounded-xl overflow-hidden bg-black aspect-video">
                <video controls poster={movies[0].preview} className="w-full h-full" key={movies[0].id}>
                  <source src={movies[0].data.max || movies[0].data["480"]} type="video/mp4" />
                </video>
              </div>
            </div>
          )}

          {/* System Requirements */}
          {sysReqs && (sysReqs.minimum || sysReqs.recommended) && (
            <div>
              {sectionHeader(isAr ? "متطلبات النظام" : "System Requirements")}
              <div className="grid grid-cols-2 gap-3">
                {/* Minimum */}
                {sysReqs.minimum && (
                  <div
                    className="rounded-xl p-3 text-xs leading-relaxed"
                    style={{ background: "hsl(228 19% 13%)", border: "1px solid hsl(228 16% 20%)" }}
                  >
                    <div className="flex items-center gap-1.5 mb-2">
                      <Monitor className="w-3.5 h-3.5 text-foreground/40" />
                      <span className="font-bold text-foreground/60">
                        {isAr ? "الحد الأدنى" : "Minimum"}
                      </span>
                    </div>
                    <p className="text-foreground/55 whitespace-pre-line" dir="ltr">
                      {sysReqs.minimum.replace(/^Minimum:\s*/i, "")}
                    </p>
                  </div>
                )}

                {/* Recommended */}
                {sysReqs.recommended && (
                  <div
                    className="rounded-xl p-3 text-xs leading-relaxed"
                    style={{ background: "hsl(160 40% 12%)", border: "1px solid hsl(160 40% 22%)" }}
                  >
                    <div className="flex items-center gap-1.5 mb-2">
                      <Monitor className="w-3.5 h-3.5 text-emerald-400" />
                      <span className="font-bold text-emerald-400">
                        {isAr ? "موصى به" : "Recommended"}
                      </span>
                    </div>
                    <p className="text-foreground/60 whitespace-pre-line" dir="ltr">
                      {sysReqs.recommended.replace(/^Recommended:\s*/i, "")}
                    </p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Dev / Publisher */}
          {(() => {
            const devs = rawg?.developers?.map(d => d.name) ?? igdb?.developers ?? [];
            const pubs = rawg?.publishers?.map(p => p.name) ?? igdb?.publishers ?? [];
            if (!devs.length && !pubs.length) return null;
            return (
              <div className="grid grid-cols-2 gap-3 text-sm pt-1 border-t border-border">
                {devs.length ? (
                  <div>
                    <p className="text-foreground/35 text-xs mb-1">{isAr ? "المطور" : "Developer"}</p>
                    <p className="font-medium text-foreground/75">{devs.join(", ")}</p>
                  </div>
                ) : null}
                {pubs.length ? (
                  <div>
                    <p className="text-foreground/35 text-xs mb-1">{isAr ? "الناشر" : "Publisher"}</p>
                    <p className="font-medium text-foreground/75">{pubs.join(", ")}</p>
                  </div>
                ) : null}
              </div>
            );
          })()}

          {/* Action buttons */}
          <div className="flex gap-3 pt-1">
            <button
              onClick={handleToggleCart}
              className={`flex-1 py-3 font-bold rounded-xl transition-all flex items-center justify-center gap-2 text-sm ${
                isInCart
                  ? "bg-destructive/80 hover:bg-destructive border border-destructive text-white"
                  : "btn-gradient hover:opacity-90"
              }`}
            >
              {isInCart ? <X className="w-4 h-4" /> : <ShoppingCart className="w-4 h-4" />}
              {isInCart
                ? (isAr ? "إزالة من السلة" : "Remove from Cart")
                : (isAr ? "أضف إلى السلة" : "Add to Cart")}
            </button>

            <button
              onClick={() => window.open("https://wa.me/201559665337", "_blank")}
              className="w-12 h-12 rounded-xl bg-green-500/15 border border-green-500/40 flex items-center justify-center hover:bg-green-500/25 transition-all flex-shrink-0"
              aria-label="WhatsApp"
            >
              <MessageCircle className="w-5 h-5 text-green-500" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
