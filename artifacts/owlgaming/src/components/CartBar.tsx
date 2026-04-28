import { memo } from "react";
import { useCart } from "@/contexts/CartContext";
import { useLang } from "@/contexts/LanguageContext";
import { usePricing } from "@/hooks/usePricing";
import { useHardDrive } from "@/contexts/HardDriveContext";
import { HardDrive, RotateCcw, ShoppingBag, Gamepad2 } from "lucide-react";
import { useNavigate } from "react-router-dom";

const DEFAULT_DRIVE_GB = 931; // Actual usable space of a 1TB HDD

const SEGMENT_COLORS: Array<[string, string]> = [
  ["#f59e0b", "#f97316"],
  ["#f97316", "#fb7185"],
  ["#fb7185", "#ec4899"],
  ["#ec4899", "#e879a0"],
  ["#e879a0", "#d946ef"],
  ["#d946ef", "#c026d3"],
  ["#c026d3", "#a855f7"],
  ["#a855f7", "#8b5cf6"],
  ["#8b5cf6", "#818cf8"],
  ["#818cf8", "#6366f1"],
];

function colorAt(t: number): [string, string] {
  const max = SEGMENT_COLORS.length - 1;
  const i = Math.min(max, Math.max(0, Math.floor(t * max)));
  return SEGMENT_COLORS[i];
}

function SegmentedBarImpl({ pct }: { pct: number }) {
  // 20 fine-grained segments + per-segment partial fill so the bar
  // visibly reacts to every single game added (no waiting for a 10% chunk).
  const N = 20;
  const safePct = Math.max(0, Math.min(100, pct));
  return (
    <div className="flex gap-[2px] h-3 sm:h-3.5 w-full sm:w-80 min-w-0">
      {Array.from({ length: N }).map((_, i) => {
        const segStart = (i / N) * 100;
        const segEnd = ((i + 1) / N) * 100;
        const fillRatio =
          safePct >= segEnd ? 1 : safePct <= segStart ? 0 : (safePct - segStart) / (segEnd - segStart);
        const [c1, c2] = colorAt(i / (N - 1));
        return (
          <div
            key={i}
            className="flex-1 h-full rounded-[2px] overflow-hidden relative"
            style={{
              background: "rgba(255,255,255,0.07)",
              transform: "skewX(-8deg)",
            }}
          >
            <div
              className="absolute inset-y-0 left-0 transition-[width] duration-150 ease-out"
              style={{
                width: `${fillRatio * 100}%`,
                background: `linear-gradient(90deg, ${c1}, ${c2})`,
              }}
            />
          </div>
        );
      })}
    </div>
  );
}
const SegmentedBar = memo(SegmentedBarImpl);

export default function CartBar() {
  const { clearCart, usedGB, getTotalItems } = useCart();
  const { openPicker, selectedDriveGB, isUnlimited } = useHardDrive();
  const { pricing } = usePricing();
  const { t } = useLang();
  const navigate = useNavigate();

  const totalItems = getTotalItems();

  // Use 931 GB as default when no drive selected (= real usable 1 TB HDD)
  const effectiveDriveGB: number | null = isUnlimited
    ? null
    : (selectedDriveGB ?? DEFAULT_DRIVE_GB);

  const netGB = effectiveDriveGB !== null ? Math.max(effectiveDriveGB - usedGB, 0) : null;
  const pct = effectiveDriveGB ? Math.min((usedGB / effectiveDriveGB) * 100, 100) : 0;
  const price = usedGB * pricing.pricePerGb;

  const gbColor =
    pct >= 90 ? "text-red-400" : pct >= 70 ? "text-yellow-400" : "text-foreground/70";

  if (totalItems === 0 && selectedDriveGB === null && !isUnlimited) return null;

  return (
    <div
      className="fixed bottom-16 lg:bottom-0 left-0 right-0 z-40 border-t border-white/8 backdrop-blur-xl"
      style={{ background: "rgba(9, 11, 23, 0.97)" }}
      dir="ltr"
    >
      {/* Thin rainbow top line */}
      <div className="h-[2px] w-full" style={{
        background: "linear-gradient(90deg, #f59e0b, #fb7185, #a855f7, #6366f1)"
      }} />

      {/* Pill — full width on mobile, centered compact on desktop */}
      <div className="flex justify-center px-2 py-2 lg:py-2.5">
        <div
          className="flex items-center gap-2 lg:gap-3 px-2.5 lg:px-4 py-1.5 lg:py-2 rounded-xl lg:rounded-2xl border border-white/10 w-full lg:w-auto max-w-full"
          style={{ background: "rgba(255,255,255,0.04)" }}
        >
          {/* Drive picker icon button */}
          <button
            onClick={() => openPicker()}
            title="Change drive size"
            className="flex-shrink-0 w-8 h-8 rounded-xl bg-primary/15 border border-primary/35 flex items-center justify-center hover:bg-primary/25 transition-colors"
          >
            <HardDrive className="w-4 h-4 text-primary" />
          </button>

          {/* Segmented bar + size labels — flexible width */}
          <div className="flex flex-col gap-1 flex-1 min-w-0">
            <SegmentedBar pct={pct} />
            {/* Used / Remaining / Total labels */}
            <div className="flex justify-between font-nums tabular-nums px-0.5 gap-1">
              <span className="text-[10px] sm:text-xs font-black truncate">
                <span className={gbColor}>{usedGB.toFixed(0)}</span>
                <span className="text-white/40 font-normal hidden sm:inline"> GB used</span>
                <span className="text-white/40 font-normal sm:hidden">GB</span>
              </span>
              <span className="text-[10px] sm:text-xs font-bold text-white/60 truncate">
                {isUnlimited ? "∞" : `${netGB?.toFixed(0)}${" "}GB`}
                <span className="hidden sm:inline"> free</span>
              </span>
              <span className="text-[10px] sm:text-xs font-bold text-white/40 truncate">
                {isUnlimited ? "∞ GB" : `${effectiveDriveGB} GB`}
              </span>
            </div>
          </div>

          {/* Games count badge */}
          {totalItems > 0 && (
            <span className="flex-shrink-0 inline-flex items-center gap-1 text-xs sm:text-sm font-bold text-primary bg-primary/15 border border-primary/30 px-2 sm:px-2.5 py-1 rounded-xl">
              <Gamepad2 className="w-3.5 h-3.5" />
              <span className="font-nums">{totalItems}</span>
            </span>
          )}

          {/* Price */}
          {totalItems > 0 && (
            <span className="flex-shrink-0 text-xs sm:text-sm font-black text-green-400 font-nums tabular-nums whitespace-nowrap">
              {price.toFixed(2)}
              <span className="text-green-400/55 font-normal text-[10px] sm:text-xs ml-0.5">{pricing.currency}</span>
            </span>
          )}

          {/* Drive change button — desktop only (icon button on mobile already opens picker) */}
          <button
            onClick={() => openPicker()}
            className="hidden lg:inline-flex flex-shrink-0 px-3 py-1.5 text-xs font-bold border border-primary/35 text-primary/80 rounded-xl hover:bg-primary/10 hover:border-primary/60 transition-all"
          >
            {selectedDriveGB ? t("games_changeDrive") : t("games_orderHardDrive")}
          </button>

          {totalItems > 0 && <div className="hidden lg:block h-6 w-px bg-white/12 flex-shrink-0" />}

          {/* Reset */}
          {totalItems > 0 && (
            <button
              onClick={() => clearCart()}
              className="flex-shrink-0 flex items-center gap-1.5 px-2 sm:px-3 py-1.5 rounded-xl text-xs font-bold text-red-400 border border-red-500/25 hover:bg-red-500/10 hover:border-red-500/50 transition-all"
              aria-label={t("minicart_reset")}
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">{t("minicart_reset")}</span>
            </button>
          )}

          {/* Checkout */}
          {totalItems > 0 && (
            <button
              onClick={() => navigate("/cart")}
              className="flex-shrink-0 flex items-center gap-1.5 px-3 sm:px-4 py-1.5 rounded-xl text-xs font-black text-white btn-gradient shadow hover:opacity-90 transition-all"
              aria-label={t("minicart_checkout")}
            >
              <ShoppingBag className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">{t("minicart_checkout")}</span>
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
