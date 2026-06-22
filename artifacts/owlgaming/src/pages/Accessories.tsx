import { useState, useEffect } from "react";
import { Package, Loader2, MessageCircle, Tag } from "lucide-react";
import { getAccessories, Accessory, isSupabaseConfigured } from "@/lib/supabase";
import { useLang } from "@/contexts/LanguageContext";

const CATEGORY_COLORS: Record<string, string> = {
  "Controllers":        "text-blue-400 bg-blue-400/10 border-blue-400/30",
  "Headsets":           "text-purple-400 bg-purple-400/10 border-purple-400/30",
  "Keyboards":          "text-green-400 bg-green-400/10 border-green-400/30",
  "Mice":               "text-orange-400 bg-orange-400/10 border-orange-400/30",
  "Monitors":           "text-cyan-400 bg-cyan-400/10 border-cyan-400/30",
  "Chairs":             "text-pink-400 bg-pink-400/10 border-pink-400/30",
  "Mousepads":          "text-yellow-400 bg-yellow-400/10 border-yellow-400/30",
  "Cables & Adapters":  "text-red-400 bg-red-400/10 border-red-400/30",
  "Other":              "text-foreground/60 bg-muted border-border",
};

function AccImage({ src, alt }: { src: string; alt: string }) {
  const [failed, setFailed] = useState(false);
  if (!src || failed) {
    return (
      <div className="w-full h-full flex items-center justify-center bg-muted">
        <Package className="w-12 h-12 text-foreground/20" />
      </div>
    );
  }
  return (
    <img
      src={src}
      alt={alt}
      loading="lazy"
      decoding="async"
      className="w-full h-full object-contain transition-transform duration-500 group-hover:scale-105"
      onError={() => setFailed(true)}
    />
  );
}

export default function Accessories() {
  const [items, setItems] = useState<Accessory[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeCategory, setActiveCategory] = useState("All");
  const { t } = useLang();

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        if (isSupabaseConfigured) {
          setItems(await getAccessories());
        } else {
          setItems([]);
        }
      } catch {
        setItems([]);
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  const categories = ["All", ...Array.from(new Set(items.map(i => i.category)))];
  const filtered = activeCategory === "All" ? items : items.filter(i => i.category === activeCategory);

  return (
    <div className="min-h-screen">
      <div className="h-16" />

      <div className="container mx-auto px-4 py-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-foreground">{t("acc_title")}</h1>
          <p className="text-foreground/50 mt-1 text-sm">{t("acc_subtitle")}</p>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-20">
            <div className="text-center space-y-4">
              <Loader2 className="w-12 h-12 animate-spin text-primary mx-auto" />
              <p className="text-foreground/60">{t("acc_loading")}</p>
            </div>
          </div>
        ) : items.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-24 gap-5 text-center">
            <div className="w-20 h-20 rounded-2xl bg-muted flex items-center justify-center">
              <Package className="w-10 h-10 text-foreground/20" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-foreground/60 mb-2">{t("acc_empty_title")}</h2>
              <p className="text-sm text-foreground/40 max-w-xs">{t("acc_empty_desc")}</p>
            </div>
          </div>
        ) : (
          <>
            {categories.length > 2 && (
              <div className="flex flex-wrap gap-2 mb-6">
                {categories.map(cat => (
                  <button
                    key={cat}
                    onClick={() => setActiveCategory(cat)}
                    className={`px-4 py-1.5 rounded-full text-sm font-medium border transition-colors ${
                      activeCategory === cat
                        ? "bg-primary text-primary-foreground border-primary"
                        : "bg-muted border-border text-foreground/60 hover:text-foreground"
                    }`}
                  >
                    {cat}
                  </button>
                ))}
              </div>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 pb-20 lg:pb-8">
              {filtered.map((acc) => (
                <div
                  key={acc.id}
                  className="group bg-card border border-border hover:border-primary/50 rounded-2xl overflow-hidden transition-all duration-300 hover:shadow-lg hover:shadow-primary/10 flex flex-col relative"
                >
                  <div className="absolute top-0 left-0 right-0 h-[2px] opacity-0 group-hover:opacity-100 transition-opacity duration-300 bg-gradient-to-r from-primary via-secondary to-transparent" />

                  <div className="relative aspect-video overflow-hidden bg-muted">
                    <AccImage src={acc.image_url} alt={acc.name} />
                    <div className={`absolute top-2.5 left-2.5 px-2.5 py-1 rounded-lg border text-xs font-bold backdrop-blur-sm ${CATEGORY_COLORS[acc.category] || CATEGORY_COLORS["Other"]}`}>
                      {acc.category}
                    </div>
                  </div>

                  <div className="p-4 flex flex-col gap-3 flex-grow">
                    <h3 className="font-bold text-foreground text-base">{acc.name}</h3>

                    {acc.description && (
                      <p className="text-xs text-foreground/60 leading-relaxed">{acc.description}</p>
                    )}

                    <div className="flex items-center gap-2 mt-auto">
                      <div className="flex items-center gap-1.5 px-3 py-1.5 bg-green-500/10 border border-green-500/30 rounded-lg">
                        <Tag className="w-3.5 h-3.5 text-green-400" />
                        <span className="text-sm font-bold text-green-400">{acc.price}</span>
                      </div>
                    </div>

                    <a
                      href="https://wa.me/201559665337"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center justify-center gap-2 w-full py-2.5 bg-green-500/15 border border-green-500/40 hover:bg-green-500/25 text-green-400 font-bold rounded-xl text-sm transition-all"
                    >
                      <MessageCircle className="w-4 h-4" />
                      {t("hd_order_whatsapp")}
                    </a>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
