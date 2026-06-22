import { useCart } from "@/contexts/CartContext";
import { useLang } from "@/contexts/LanguageContext";
import { usePricing } from "@/hooks/usePricing";
import { ShoppingCart, RotateCcw, ArrowRight, HardDrive } from "lucide-react";
import { useNavigate } from "react-router-dom";

export default function FloatingCartWidget() {
  const { state, clearCart, getTotalItems, getTotalSizeGB } = useCart();
  const { t, isRTL } = useLang();
  const { pricing } = usePricing();
  const navigate = useNavigate();

  const totalItems = getTotalItems();
  if (totalItems === 0) return null;

  const totalGB = getTotalSizeGB();
  const totalPrice = totalGB * pricing.pricePerGb;

  return (
    <div
      className={`fixed bottom-20 z-[150] ${isRTL ? "left-4" : "right-4"} md:bottom-6`}
      dir={isRTL ? "rtl" : "ltr"}
    >
      <div className="bg-card border border-primary/40 rounded-2xl shadow-2xl shadow-black/50 p-5 min-w-[260px] backdrop-blur-sm">
        <div className="flex items-center gap-2 mb-3">
          <div className="w-9 h-9 rounded-lg bg-primary/20 flex items-center justify-center">
            <ShoppingCart className="w-5 h-5 text-primary" />
          </div>
          <span className="font-bold text-base text-foreground">{t("minicart_title")}</span>
          <span className="ms-auto bg-primary text-primary-foreground text-sm font-black px-2.5 py-0.5 rounded-full font-nums">
            {totalItems}
          </span>
        </div>

        <div className="space-y-2 border-t border-border pt-3 mb-4">
          <div className="flex items-center justify-between text-foreground/60">
            <span className="flex items-center gap-1.5 text-sm">
              <HardDrive className="w-3.5 h-3.5 text-primary" />
              {t("minicart_size")}
            </span>
            <span className="font-bold text-base text-primary font-nums">{totalGB.toFixed(2)} GB</span>
          </div>
          <div className="flex items-center justify-between text-foreground/60">
            <span className="text-sm">{t("minicart_price")}</span>
            <span className="font-bold text-base text-green-400 font-nums">
              {totalPrice.toFixed(2)} {pricing.currency}
            </span>
          </div>
        </div>

        <div className="flex gap-2">
          <button
            onClick={() => clearCart()}
            className="flex items-center justify-center gap-1 px-2.5 py-1.5 bg-destructive/10 hover:bg-destructive/20 border border-destructive/30 hover:border-destructive/50 text-destructive rounded-xl text-[11px] font-bold transition-all"
          >
            <RotateCcw className="w-3 h-3" />
            {t("minicart_reset")}
          </button>
          <button
            onClick={() => navigate("/cart")}
            className="flex-1 flex items-center justify-center gap-1 px-3 py-1.5 btn-gradient rounded-xl text-[11px] font-bold text-white transition-all"
          >
            {t("minicart_checkout")}
            <ArrowRight className="w-3 h-3" />
          </button>
        </div>
      </div>
    </div>
  );
}
