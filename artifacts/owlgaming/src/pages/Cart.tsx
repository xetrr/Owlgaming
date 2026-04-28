import { useCart } from "@/contexts/CartContext";
import { usePricing } from "@/hooks/usePricing";
import { Link } from "react-router-dom";
import { Trash2, ArrowRight, ShoppingCart, HardDrive, User, Phone, X, FileDown, MessageCircle, Package } from "lucide-react";
import { useState } from "react";
import { generatePDF, buildWhatsAppMessage, PDFConfig } from "@/lib/pdf-export";
import { useLang } from "@/contexts/LanguageContext";
import { useContactInfo } from "@/hooks/useContactInfo";
import { useBrand } from "@/hooks/useBrand";

interface CustomerInfo {
  name: string;
  phone: string;
}

const WA_NUMBER = "201559665337";

export default function Cart() {
  const { state, removeItem, getTotalSize, getTotalSizeGB, clearCart } = useCart();
  const { pricing } = usePricing();
  const { t } = useLang();
  const { info: contactInfo } = useContactInfo();
  const { brand } = useBrand();
  const [isProcessingPdf, setIsProcessingPdf] = useState(false);
  const [showCheckoutModal, setShowCheckoutModal] = useState(false);
  const [customer, setCustomer] = useState<CustomerInfo>({ name: "", phone: "" });
  const [errors, setErrors] = useState<Partial<CustomerInfo>>({});

  const totalGB = getTotalSizeGB();
  const totalPrice = totalGB * pricing.pricePerGb;

  const validate = () => {
    const newErrors: Partial<CustomerInfo> = {};
    if (!customer.name.trim()) newErrors.name = t("checkout_nameRequired");
    if (!customer.phone.trim()) newErrors.phone = t("checkout_phoneRequired");
    else if (!/^[0-9+\-\s()]{7,20}$/.test(customer.phone.trim()))
      newErrors.phone = t("checkout_phoneInvalid");
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const buildConfig = (): PDFConfig => ({
    companyName: brand.name || contactInfo.brandName || "GAMEARLY",
    companyEmail: contactInfo.email,
    companyPhone: contactInfo.phone,
    customerName: customer.name,
    customerPhone: customer.phone,
    invoiceNumber: `ORD-${Date.now().toString().slice(-6)}`,
    taxRate: 0,
    currency: pricing.currency,
    pricePerGb: pricing.pricePerGb,
    footerText: brand.invoiceFooter,
    invoiceLabel: brand.invoiceLabel,
  });

  const handleDownloadPDF = async () => {
    if (!validate()) return;
    setIsProcessingPdf(true);
    try {
      await generatePDF(state.items, getTotalSize(), totalPrice, buildConfig());
      clearCart();
      setShowCheckoutModal(false);
      setCustomer({ name: "", phone: "" });
    } catch (error) {
      console.error("Error generating PDF:", error);
      alert("Failed to generate PDF. Please try again.");
    } finally {
      setIsProcessingPdf(false);
    }
  };

  const handleWhatsApp = () => {
    if (!validate()) return;
    const config = buildConfig();
    const msg = buildWhatsAppMessage(state.items, getTotalSize(), totalPrice, config);
    const url = `https://wa.me/${WA_NUMBER}?text=${encodeURIComponent(msg)}`;
    window.open(url, "_blank");
    clearCart();
    setShowCheckoutModal(false);
    setCustomer({ name: "", phone: "" });
  };

  if (state.items.length === 0) {
    return (
      <div className="min-h-screen">
        <div className="h-16" />
        <div className="container mx-auto px-4 py-20">
          <div className="text-center space-y-6">
            <ShoppingCart className="w-16 h-16 mx-auto text-foreground/30" />
            <h1 className="text-4xl md:text-5xl font-bold text-foreground">{t("cart_empty_title")}</h1>
            <p className="text-lg text-foreground/70 max-w-2xl mx-auto">{t("cart_empty_desc")}</p>
            <Link
              to="/games"
              className="inline-flex items-center justify-center gap-2 px-8 py-3 bg-primary hover:bg-primary/90 text-primary-foreground font-bold rounded-lg transition-all hover:shadow-lg hover:shadow-primary/20"
            >
              {t("cart_browse")}
              <ArrowRight className="w-5 h-5" />
            </Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen">
      <div className="h-16" />

      <div className="container mx-auto px-4 py-8">
        <h1 className="text-4xl font-bold text-foreground mb-8">{t("cart_title")}</h1>

        <div className="grid lg:grid-cols-3 gap-8 pb-44 lg:pb-8">
          <div className="lg:col-span-2 space-y-4">
            {state.items.map((item) => (
              <div key={item.id} className="bg-card border border-border rounded-xl p-4 flex gap-4">
                <div className="w-20 h-20 rounded-lg overflow-hidden border border-border/50 flex-shrink-0">
                  <img src={item.image} alt={item.title} loading="lazy" decoding="async" className="w-full h-full object-contain" />
                </div>
                <div className="flex-1 min-w-0">
                  <h3 className="font-bold text-foreground truncate">{item.title}</h3>
                  <div className="flex items-center gap-1 mt-1">
                    <HardDrive className="w-3 h-3 text-primary" />
                    <span className="text-xs font-semibold text-primary font-nums">{item.size}</span>
                  </div>
                  <div className="text-xs text-green-400 font-nums mt-0.5">
                    {(parseFloat(item.size.replace(/[^0-9.]/g, "")) * pricing.pricePerGb).toFixed(2)} {pricing.currency}
                  </div>
                </div>
                <button
                  onClick={() => removeItem(item.id)}
                  className="p-2 hover:bg-destructive/20 text-destructive rounded-lg transition-colors self-start"
                  aria-label="Remove item"
                >
                  <Trash2 className="w-5 h-5" />
                </button>
              </div>
            ))}
          </div>

          <div className="lg:col-span-1">
            <div className="bg-card border border-border rounded-xl p-6 sticky top-24 space-y-4">
              <h2 className="text-xl font-bold text-foreground">{t("cart_summary")}</h2>

              <div className="space-y-3 border-t border-border pt-4">
                <div className="flex justify-between text-sm text-foreground/70">
                  <span>{t("cart_games")}</span>
                  <span className="font-nums">{state.items.length}</span>
                </div>
                <div className="flex justify-between text-sm font-bold text-foreground">
                  <span className="flex items-center gap-1">
                    <HardDrive className="w-3.5 h-3.5 text-primary" />
                    {t("cart_totalSize")}
                  </span>
                  <span className="text-primary font-nums">{getTotalSize()}</span>
                </div>
                <div className="flex justify-between text-sm font-bold text-foreground border-t border-border pt-3">
                  <span>{t("minicart_price")}</span>
                  <span className="text-green-400 font-nums">
                    {totalPrice.toFixed(2)} {pricing.currency}
                  </span>
                </div>
              </div>

              <button
                onClick={() => setShowCheckoutModal(true)}
                disabled={isProcessingPdf}
                className="w-full px-6 py-3 btn-gradient disabled:opacity-50 font-bold rounded-lg disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                <Package className="w-4 h-4" />
                {t("cart_placeOrder")}
              </button>

              <Link
                to="/games"
                className="block w-full px-6 py-3 bg-card border border-border hover:border-primary/50 text-foreground font-bold rounded-lg transition-all text-center"
              >
                {t("cart_continueShopping")}
              </Link>

              <div className="bg-muted/50 border border-border/50 rounded-lg p-4 space-y-2 text-xs text-foreground/60">
                <p className="font-medium">{t("cart_orderIncludes")}</p>
                <ul className="space-y-1 list-disc list-inside">
                  <li>{t("cart_include1")}</li>
                  <li>{t("cart_include2")}</li>
                  <li>{t("cart_include3")}</li>
                </ul>
                <p className="text-foreground/40 pt-1">{t("cart_sendVia")}</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Checkout Modal */}
      {showCheckoutModal && (
        <div className="fixed inset-0 z-[200] flex items-center justify-center p-4" onClick={() => !isProcessingPdf && setShowCheckoutModal(false)}>
          <div className="absolute inset-0 bg-black/80 backdrop-blur-sm" />
          <div
            className="relative z-10 w-full max-w-md bg-card border border-border rounded-2xl shadow-2xl p-6 space-y-5"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xl font-bold text-foreground">{t("checkout_title")}</h2>
                <p className="text-xs text-foreground/50 mt-0.5">{t("checkout_subtitle")}</p>
              </div>
              <button
                onClick={() => !isProcessingPdf && setShowCheckoutModal(false)}
                className="w-8 h-8 rounded-full bg-muted flex items-center justify-center hover:bg-muted/80 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="bg-muted/50 border border-border rounded-xl p-3 flex justify-between items-center text-sm">
              <span className="text-foreground/60">{t("minicart_price")}</span>
              <span className="font-black text-green-400 font-nums text-base">
                {totalPrice.toFixed(2)} {pricing.currency}
              </span>
            </div>

            <div className="space-y-4">
              <div>
                <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1.5 block">
                  {t("checkout_fullName")}
                </label>
                <div className="relative">
                  <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-foreground/40" />
                  <input
                    type="text"
                    placeholder={t("checkout_namePlaceholder")}
                    value={customer.name}
                    onChange={(e) => { setCustomer({ ...customer, name: e.target.value }); setErrors({ ...errors, name: "" }); }}
                    className={`w-full pl-10 pr-4 py-2.5 bg-muted border rounded-xl text-foreground placeholder:text-foreground/40 focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all text-sm ${errors.name ? "border-destructive" : "border-border"}`}
                  />
                </div>
                {errors.name && <p className="text-xs text-destructive mt-1">{errors.name}</p>}
              </div>

              <div>
                <label className="text-xs font-bold text-foreground/60 uppercase tracking-wider mb-1.5 block">
                  {t("checkout_phoneLabel")}
                </label>
                <div className="relative">
                  <Phone className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-foreground/40" />
                  <input
                    type="tel"
                    placeholder={t("checkout_phonePlaceholder")}
                    value={customer.phone}
                    onChange={(e) => { setCustomer({ ...customer, phone: e.target.value }); setErrors({ ...errors, phone: "" }); }}
                    className={`w-full pl-10 pr-4 py-2.5 bg-muted border rounded-xl text-foreground placeholder:text-foreground/40 focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all text-sm ${errors.phone ? "border-destructive" : "border-border"}`}
                  />
                </div>
                {errors.phone && <p className="text-xs text-destructive mt-1">{errors.phone}</p>}
              </div>
            </div>

            <div className="flex items-center gap-3">
              <div className="flex-1 h-px bg-border" />
              <span className="text-xs text-foreground/40 font-medium">{t("checkout_chooseSend")}</span>
              <div className="flex-1 h-px bg-border" />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <button
                onClick={handleDownloadPDF}
                disabled={isProcessingPdf}
                className="flex flex-col items-center gap-2 py-4 px-3 bg-muted border border-border hover:border-primary/50 hover:bg-primary/10 text-foreground rounded-xl text-sm font-medium transition-all disabled:opacity-50 disabled:cursor-not-allowed group"
              >
                <FileDown className="w-6 h-6 text-primary group-hover:scale-110 transition-transform" />
                <span className="font-bold text-foreground/80">
                  {isProcessingPdf ? t("checkout_generating") : t("checkout_downloadPDF")}
                </span>
                <span className="text-[10px] text-foreground/40 text-center leading-tight">{t("checkout_pdfNote")}</span>
              </button>

              <button
                onClick={handleWhatsApp}
                disabled={isProcessingPdf}
                className="flex flex-col items-center gap-2 py-4 px-3 bg-muted border border-border hover:border-green-500/50 hover:bg-green-500/10 text-foreground rounded-xl text-sm font-medium transition-all disabled:opacity-50 disabled:cursor-not-allowed group"
              >
                <MessageCircle className="w-6 h-6 text-green-400 group-hover:scale-110 transition-transform" />
                <span className="font-bold text-foreground/80">{t("checkout_whatsapp")}</span>
                <span className="text-[10px] text-foreground/40 text-center leading-tight">{t("checkout_waNote")}</span>
              </button>
            </div>

            <button
              onClick={() => !isProcessingPdf && setShowCheckoutModal(false)}
              disabled={isProcessingPdf}
              className="w-full py-2 bg-transparent border border-border hover:border-foreground/30 text-foreground/50 font-medium rounded-xl text-sm transition-colors disabled:opacity-50"
            >
              {t("checkout_cancel")}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
