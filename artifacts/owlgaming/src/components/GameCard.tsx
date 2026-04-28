import { memo, useState } from "react";
import { Heart, Plus, Eye, X, Check, HardDrive } from "lucide-react";
import { useCart } from "@/contexts/CartContext";
import { useAuth } from "@/contexts/AuthContext";
import { useHardDrive } from "@/contexts/HardDriveContext";
import { useLang } from "@/contexts/LanguageContext";
import GamePreviewModal from "./GamePreviewModal";
import { roundUpGameSizeGB } from "@/lib/sizeUtils";

interface GameCardProps {
  id: string;
  title: string;
  image: string;
  size: string;
  downloads: number;
  price: number;
  source?: string;
}

function GameCardImpl({ id, title, image, size, downloads, price, source }: GameCardProps) {
  const { addItem, removeItem, itemIds, usedGB } = useCart();
  const { isFavorite, toggleFavorite } = useAuth();
  const { selectedDriveGB, isUnlimited } = useHardDrive();
  const { t } = useLang();
  const [showPreview, setShowPreview] = useState(false);
  const [favAnimating, setFavAnimating] = useState(false);
  const [imgError, setImgError] = useState(false);

  const isInCart = itemIds.has(id);
  const fav = isFavorite(id);

  const gameSizeGB = roundUpGameSizeGB(size);
  const displaySize = `${gameSizeGB}GB`;

  const remainingGB = selectedDriveGB !== null ? selectedDriveGB - usedGB : Infinity;
  const wouldExceed = !isInCart && selectedDriveGB !== null && !isUnlimited && gameSizeGB > remainingGB;

  const handleToggleCart = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (isInCart) removeItem(id);
    else if (!wouldExceed) addItem({ id, title, size: displaySize, price, image });
  };

  const handlePreview = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setShowPreview(true);
  };

  const handleFavorite = async (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setFavAnimating(true);
    await toggleFavorite(id);
    setTimeout(() => setFavAnimating(false), 400);
  };

  return (
    <>
      <div
        role="button"
        tabIndex={0}
        onClick={() => setShowPreview(true)}
        onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") setShowPreview(true); }}
        className="block group focus:outline-none focus-visible:ring-2 focus-visible:ring-primary/70 rounded-xl game-card-cv cursor-pointer"
      >
        <div
          className={`rounded-xl overflow-hidden flex flex-col transition-all duration-300 ${
            wouldExceed
              ? "opacity-50"
              : isInCart
              ? "ring-2 ring-[#17a876]/70 shadow-[0_0_20px_rgba(23,168,118,0.2)]"
              : "hover:ring-1 hover:ring-primary/50 hover:shadow-[0_6px_24px_rgba(166,108,255,0.18)]"
          }`}
        >
          {/* ── Image ─────────────────────────────────────────── */}
          <div className="relative w-full overflow-hidden bg-[#0d0f1a]" style={{ aspectRatio: "16/9" }}>
            <img
              src={imgError ? `https://placehold.co/640x360/1a1d2e/a66cff?text=${encodeURIComponent(title)}` : image}
              alt={title}
              loading="lazy"
              decoding="async"
              onError={() => setImgError(true)}
              className="w-full h-full object-cover transition-transform duration-500 group-hover:scale-105"
            />

            {/* Size badge — top-left */}
            <div className="absolute top-2 left-2 px-2 py-0.5 rounded-md bg-black/75 backdrop-blur-sm border border-white/15">
              <span className="text-[11px] font-black tracking-wide text-white font-nums">{displaySize}</span>
            </div>

            {/* Favorite + Preview — top-right */}
            <div className="absolute top-2 right-2 flex gap-1">
              <button
                onClick={handleFavorite}
                className={`w-7 h-7 rounded-lg backdrop-blur-sm border flex items-center justify-center transition-all duration-200 ${
                  fav
                    ? "bg-primary/30 border-primary/70"
                    : "bg-black/60 border-white/15 hover:border-primary/50"
                } ${favAnimating ? "scale-125" : "hover:scale-110"}`}
                aria-label={fav ? "Remove from favorites" : "Add to favorites"}
              >
                <Heart className={`w-3.5 h-3.5 transition-all ${fav ? "text-primary fill-primary" : "text-white"}`} />
              </button>
              <button
                onClick={handlePreview}
                className="w-7 h-7 rounded-lg bg-black/60 backdrop-blur-sm border border-white/15 flex items-center justify-center hover:bg-primary/50 hover:border-primary/60 transition-all hover:scale-110"
                aria-label="Preview"
              >
                <Eye className="w-3.5 h-3.5 text-white" />
              </button>
            </div>

            {/* Selected banner — bottom so it doesn't cover size badge */}
            {isInCart && (
              <div className="absolute bottom-0 left-0 right-0 flex items-center justify-center gap-1.5 py-1 bg-[#17a876]/90 pointer-events-none">
                <Check className="w-3 h-3 text-white" strokeWidth={3} />
                <span className="text-white text-[10px] font-bold tracking-wide">{t("card_selected")}</span>
              </div>
            )}

            {/* No space banner — bottom */}
            {wouldExceed && !isInCart && (
              <div className="absolute bottom-0 left-0 right-0 flex items-center justify-center gap-1 py-1 bg-red-500/80 pointer-events-none">
                <HardDrive className="w-3 h-3 text-white" />
                <span className="text-white text-[10px] font-bold">{t("card_noSpace")}</span>
              </div>
            )}
          </div>

          {/* ── Title + Actions ────────────────────────────────── */}
          <div className="bg-card border border-t-0 border-border rounded-b-xl px-2.5 pt-2 pb-2.5 flex flex-col gap-2">
            <h3 className="text-xs font-bold text-foreground leading-snug line-clamp-1" dir="ltr">
              {title}
            </h3>

            <div className="flex items-center gap-1.5">
              {/* Add / Remove button */}
              <button
                onClick={handleToggleCart}
                disabled={wouldExceed && !isInCart}
                className={`flex-1 py-1.5 rounded-lg transition-all text-white text-[11px] font-black flex items-center justify-center gap-1 ${
                  isInCart
                    ? "bg-[#17a876]/20 border border-[#17a876]/50 text-[#17a876]"
                    : wouldExceed
                    ? "bg-red-500/10 border border-red-500/30 text-red-400/70 cursor-not-allowed"
                    : "btn-gradient hover:opacity-90"
                }`}
              >
                {isInCart ? (
                  <><X className="w-3 h-3" />{t("card_added")}</>
                ) : wouldExceed ? (
                  <><HardDrive className="w-3 h-3" />{t("card_noSpace")}</>
                ) : (
                  <><Plus className="w-3 h-3" />{t("card_addToCart")}</>
                )}
              </button>

              {/* Remove from cart shortcut */}
              {isInCart && (
                <button
                  onClick={handleToggleCart}
                  className="w-8 h-8 rounded-lg bg-red-500/15 border border-red-500/40 flex items-center justify-center hover:bg-red-500/30 transition-colors flex-shrink-0"
                  aria-label="Remove from cart"
                >
                  <X className="w-3.5 h-3.5 text-red-400" />
                </button>
              )}
            </div>
          </div>
        </div>
      </div>

      {showPreview && (
        <GamePreviewModal
          game={{ id, title, image, size: displaySize, source }}
          onClose={() => setShowPreview(false)}
        />
      )}
    </>
  );
}

const GameCard = memo(GameCardImpl);
export default GameCard;
