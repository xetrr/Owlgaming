import { useHardDrive } from "@/contexts/HardDriveContext";
import { useCart } from "@/contexts/CartContext";
import { useLang } from "@/contexts/LanguageContext";
import { HardDrive, Trash2 } from "lucide-react";

export default function StorageTrackerBar() {
  const { selectedDriveGB, isUnlimited, clearDrive, openPicker } = useHardDrive();
  const { usedGB } = useCart();
  const { t } = useLang();

  if (!selectedDriveGB && !isUnlimited) return null;

  const totalGB = selectedDriveGB ?? 0;
  const remainingGB = isUnlimited ? Infinity : totalGB - usedGB;
  const pct = isUnlimited ? 0 : Math.min((usedGB / totalGB) * 100, 100);

  const barColor =
    pct >= 90 ? "bg-red-500" : pct >= 70 ? "bg-yellow-500" : "bg-primary";

  return (
    <div
      className="fixed bottom-0 left-0 right-0 z-40 border-t border-border/60 backdrop-blur-xl"
      style={{ background: "rgba(15,18,37,0.95)" }}
    >
      <div className="container mx-auto px-3 py-3">
        <div className="flex items-center gap-2 sm:gap-3">
          <button
            onClick={() => openPicker()}
            className="flex-shrink-0 w-8 h-8 rounded-xl bg-primary/10 border border-primary/30 flex items-center justify-center hover:bg-primary/20 transition-colors"
            title="Change drive"
          >
            <HardDrive className="w-4 h-4 text-primary" />
          </button>

          <div className="flex-1 min-w-0">
            {isUnlimited ? (
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-foreground/60">{t("tracker_unlimited")}</span>
                <span className="text-xs text-foreground/40">—</span>
                <span className="text-xs text-foreground/50">
                  {t("tracker_used")} <span className="font-black text-foreground/80">{usedGB}GB</span>
                </span>
              </div>
            ) : (
              <div className="space-y-1">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-bold text-foreground/60">
                    {t("tracker_remaining")}
                  </span>
                  <span className="text-xs font-black text-foreground/80 font-nums">
                    {remainingGB < 0 ? (
                      <span className="text-red-400">{t("tracker_exceeded")} {Math.abs(remainingGB)}GB</span>
                    ) : (
                      `${remainingGB}GB`
                    )}
                  </span>
                  <span className="text-xs text-foreground/40">{totalGB}GB</span>
                </div>
                <div className="h-3 bg-white/10 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-[width] duration-150 ease-out ${barColor}`}
                    style={{ width: `${pct}%` }}
                  />
                </div>
              </div>
            )}
          </div>

          <button
            onClick={clearDrive}
            className="flex-shrink-0 flex items-center gap-1.5 px-2 py-1.5 sm:px-3 rounded-xl bg-white/5 border border-border hover:border-red-500/40 hover:bg-red-500/10 text-foreground/50 hover:text-red-400 transition-all text-xs font-bold"
            aria-label={t("tracker_removeDrive")}
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span className="hidden md:inline">{t("tracker_removeDrive")}</span>
          </button>
        </div>
      </div>
    </div>
  );
}
