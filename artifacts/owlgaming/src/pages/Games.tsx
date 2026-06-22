import GameCard from "@/components/GameCard";
import { Search, Gamepad2, HardDrive, X } from "lucide-react";
import { useState, useEffect, useRef, useMemo } from "react";
import { getGames, Game } from "@/lib/supabase";
import { useHardDrive } from "@/contexts/HardDriveContext";
import { useLang } from "@/contexts/LanguageContext";
import { useBrand } from "@/hooks/useBrand";
import { roundUpGameSizeGB } from "@/lib/sizeUtils";
import { usePricing } from "@/hooks/usePricing";

const ALL_GENRE = "__all__";

function GameCardSkeleton() {
  return (
    <div className="rounded-xl overflow-hidden motion-safe:animate-pulse">
      <div className="bg-muted/60" style={{ aspectRatio: "16/9" }} />
      <div className="bg-card border border-t-0 border-border rounded-b-xl px-2.5 pt-2 pb-2.5 space-y-2">
        <div className="h-3 bg-muted/80 rounded w-3/4" />
        <div className="h-7 bg-muted/60 rounded-lg" />
      </div>
    </div>
  );
}

export default function Games() {
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedGenre, setSelectedGenre] = useState(ALL_GENRE);
  const [games, setGames] = useState<Game[]>([]);
  const [loading, setLoading] = useState(true);
  const { openPicker, selectedDriveGB, isUnlimited } = useHardDrive();
  const { t, isRTL } = useLang();
  const { brand } = useBrand();
  const { pricing } = usePricing();
  const searchRef = useRef<HTMLInputElement>(null);

  const hasDriveSelected = selectedDriveGB !== null || isUnlimited;

  useEffect(() => {
    const loadGames = async () => {
      setLoading(true);
      try {
        setGames(await getGames());
      } catch {
        setGames([]);
      } finally {
        setLoading(false);
      }
    };
    loadGames();
  }, []);

  const genres = useMemo(() => {
    const set = new Set<string>();
    for (const g of games) {
      if (g.genre?.trim()) set.add(g.genre.trim());
    }
    return Array.from(set).sort();
  }, [games]);

  const filteredGames = useMemo(() => {
    return games.filter((g) => {
      const matchSearch = g.name.toLowerCase().includes(searchQuery.toLowerCase());
      const matchGenre = selectedGenre === ALL_GENRE || g.genre?.trim() === selectedGenre;
      return matchSearch && matchGenre;
    });
  }, [games, searchQuery, selectedGenre]);

  return (
    <div className="min-h-screen">
      {/* ── Hero banner ──────────────────────────────────────────────── */}
      <div className="relative overflow-hidden bg-card border-b border-border">
        <div className="hidden md:block absolute -top-24 -left-24 w-96 h-96 bg-primary/10 rounded-full blur-3xl pointer-events-none" />
        <div className="hidden md:block absolute -top-16 -right-16 w-72 h-72 bg-secondary/8 rounded-full blur-3xl pointer-events-none" />
        <div
          className="hidden md:block absolute inset-0 opacity-[0.04] pointer-events-none"
          style={{
            backgroundImage: "radial-gradient(circle, hsl(var(--foreground)) 1px, transparent 1px)",
            backgroundSize: "28px 28px",
          }}
        />

        <div className="relative container mx-auto px-4 pt-24 pb-10">
          {/* Title row */}
          <div className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-4 mb-6">
            <div>
              <div className="flex items-center gap-2 mb-2">
                <div className="w-8 h-8 rounded-lg bg-primary/20 border border-primary/30 flex items-center justify-center">
                  <Gamepad2 className="w-4 h-4 text-primary" />
                </div>
                <span className="text-xs font-bold text-primary/70 uppercase tracking-widest">{brand.name}</span>
              </div>
              <h1 className="text-3xl sm:text-4xl font-black text-foreground leading-tight">
                {t("games_title")}
              </h1>
              {!loading && games.length > 0 && (
                <p className="text-sm text-foreground/40 mt-1 font-nums">
                  {searchQuery || selectedGenre !== ALL_GENRE
                    ? `${filteredGames.length} / ${games.length}`
                    : games.length}{" "}
                  {t("games_title").toLowerCase()}
                </p>
              )}
            </div>

            <button
              onClick={() => openPicker()}
              className={`flex items-center gap-2 px-5 py-2.5 rounded-xl font-bold text-sm transition-all self-start sm:self-auto flex-shrink-0 ${
                hasDriveSelected
                  ? "bg-primary/15 border border-primary/40 text-primary hover:bg-primary/25"
                  : "btn-gradient"
              }`}
            >
              <HardDrive className="w-4 h-4" />
              {hasDriveSelected ? t("games_changeDrive") : t("games_orderHardDrive")}
            </button>
          </div>

          {/* Search bar */}
          <div className="relative max-w-2xl mb-4">
            <Search
              className={`absolute top-1/2 -translate-y-1/2 w-5 h-5 text-foreground/35 pointer-events-none ${
                isRTL ? "right-4" : "left-4"
              }`}
            />
            <input
              ref={searchRef}
              type="text"
              placeholder={t("games_search")}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className={`w-full py-3.5 bg-background/60 backdrop-blur-sm border border-border rounded-2xl text-foreground placeholder:text-foreground/35 focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary/50 transition-all text-sm ${
                isRTL ? "pr-12 pl-12" : "pl-12 pr-12"
              }`}
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery("")}
                className={`absolute top-1/2 -translate-y-1/2 text-foreground/40 hover:text-foreground transition-colors ${
                  isRTL ? "left-4" : "right-4"
                }`}
              >
                <X className="w-4 h-4" />
              </button>
            )}
          </div>

          {/* Genre filter pills — horizontal scroll on mobile, wrap on larger screens */}
          {!loading && genres.length > 0 && (
            <div className="flex gap-2 overflow-x-auto pb-1 sm:flex-wrap sm:overflow-visible sm:pb-0 [scrollbar-width:none] [-ms-overflow-style:none] [&::-webkit-scrollbar]:hidden">
              <button
                onClick={() => setSelectedGenre(ALL_GENRE)}
                className={`flex-shrink-0 px-3.5 py-1.5 rounded-full text-xs font-bold transition-all ${
                  selectedGenre === ALL_GENRE
                    ? "bg-primary text-white shadow-[0_0_12px_rgba(166,108,255,0.4)]"
                    : "bg-muted border border-border text-foreground/60 hover:border-primary/40 hover:text-foreground"
                }`}
              >
                {isRTL ? "الكل" : "All"}
              </button>
              {genres.map((genre) => (
                <button
                  key={genre}
                  onClick={() => setSelectedGenre(selectedGenre === genre ? ALL_GENRE : genre)}
                  className={`flex-shrink-0 px-3.5 py-1.5 rounded-full text-xs font-bold transition-all ${
                    selectedGenre === genre
                      ? "bg-primary text-white shadow-[0_0_12px_rgba(166,108,255,0.4)]"
                      : "bg-muted border border-border text-foreground/60 hover:border-primary/40 hover:text-foreground"
                  }`}
                >
                  {genre}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* ── Game grid ────────────────────────────────────────────────── */}
      <div className={`container mx-auto px-4 py-8 ${hasDriveSelected ? "pb-44 lg:pb-28" : "pb-24 lg:pb-8"}`}>
        {loading ? (
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4 md:gap-6">
            {Array.from({ length: 8 }).map((_, i) => (
              <GameCardSkeleton key={i} />
            ))}
          </div>
        ) : games.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-32 gap-6 text-center">
            <div className="relative">
              <div className="w-24 h-24 rounded-3xl bg-card border border-border flex items-center justify-center">
                <Gamepad2 className="w-12 h-12 text-foreground/15" />
              </div>
              <div className="hidden md:block absolute inset-0 rounded-3xl bg-primary/5 blur-2xl -z-10" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-foreground/50 mb-2">{t("games_empty_title")}</h2>
              <p className="text-sm text-foreground/30 max-w-xs leading-relaxed">{t("games_empty_desc")}</p>
            </div>
          </div>
        ) : filteredGames.length > 0 ? (
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4 md:gap-6">
            {filteredGames.map((game) => {
              const sizeGB = roundUpGameSizeGB(game.size);
              return (
                <GameCard
                  key={game.id}
                  id={game.id}
                  title={game.name}
                  image={game.image_url}
                  size={`${sizeGB}GB`}
                  downloads={0}
                  price={sizeGB * pricing.pricePerGb}
                  source={game.source}
                  genre={game.genre}
                />
              );
            })}
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-24 gap-4 text-center">
            <div className="w-16 h-16 rounded-2xl bg-muted border border-border flex items-center justify-center">
              <Search className="w-8 h-8 text-foreground/20" />
            </div>
            <div>
              <p className="text-foreground/60 font-semibold">
                {t("games_noResults")} "{searchQuery || selectedGenre}"
              </p>
              <button
                onClick={() => { setSearchQuery(""); setSelectedGenre(ALL_GENRE); }}
                className="mt-2 text-sm text-primary/70 hover:text-primary transition-colors"
              >
                {isRTL ? "مسح الفلتر" : "Clear filter"}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
