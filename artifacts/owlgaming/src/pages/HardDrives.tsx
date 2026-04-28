import { useState, useEffect } from "react";
import { HardDrive as HardDriveIcon, Loader2, MessageCircle, Zap, Database, Tag, Package } from "lucide-react";
import { getHardDrives, HardDrive, isSupabaseConfigured } from "@/lib/supabase";
import { useHardDrive } from "@/contexts/HardDriveContext";
import { useLang } from "@/contexts/LanguageContext";

function DriveImage({ src, alt }: { src: string; alt: string }) {
  const [failed, setFailed] = useState(false);
  if (!src || failed) {
    return (
      <div className="w-full h-full flex items-center justify-center bg-muted">
        <HardDriveIcon className="w-12 h-12 text-foreground/20" />
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

const typeColors: Record<string, string> = {
  "HDD": "text-blue-400 bg-blue-400/10 border-blue-400/30",
  "SATA SSD": "text-green-400 bg-green-400/10 border-green-400/30",
  "NVMe SSD": "text-purple-400 bg-purple-400/10 border-purple-400/30",
};

function parseDriveCapacityGB(capacity: string): number | undefined {
  if (!capacity) return undefined;
  const tb = capacity.match(/([\d.]+)\s*TB/i);
  if (tb) return Math.round(parseFloat(tb[1]) * 1024 * 0.93);
  const gb = capacity.match(/([\d.]+)\s*GB?/i);
  if (gb) return Math.round(parseFloat(gb[1]) * 0.93);
  return undefined;
}

export default function HardDrives() {
  const [drives, setDrives] = useState<HardDrive[]>([]);
  const [loading, setLoading] = useState(true);
  const { openPicker } = useHardDrive();
  const { t } = useLang();

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        if (isSupabaseConfigured) {
          const dbDrives = await getHardDrives();
          setDrives(dbDrives);
        } else {
          setDrives([]);
        }
      } catch {
        setDrives([]);
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  return (
    <div className="min-h-screen">
      <div className="h-16" />

      <div className="container mx-auto px-4 py-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-foreground">{t("hd_title")}</h1>
          <p className="text-foreground/50 mt-1 text-sm">{t("hd_subtitle")}</p>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-20">
            <div className="text-center space-y-4">
              <Loader2 className="w-12 h-12 animate-spin text-primary mx-auto" />
              <p className="text-foreground/60">{t("hd_loading")}</p>
            </div>
          </div>
        ) : drives.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-24 gap-5 text-center">
            <div className="w-20 h-20 rounded-2xl bg-muted flex items-center justify-center">
              <HardDriveIcon className="w-10 h-10 text-foreground/20" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-foreground/60 mb-2">{t("hd_empty_title")}</h2>
              <p className="text-sm text-foreground/40 max-w-xs">{t("hd_empty_desc")}</p>
            </div>
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 pb-20 lg:pb-8">
            {drives.map((drive) => (
              <div
                key={drive.id}
                className="group bg-card border border-border hover:border-primary/50 rounded-2xl overflow-hidden transition-all duration-300 hover:shadow-lg hover:shadow-primary/10 flex flex-col"
              >
                <div className="relative aspect-video overflow-hidden bg-muted">
                  <DriveImage src={drive.image_url} alt={drive.name} />
                  <div className={`absolute top-2.5 left-2.5 px-2.5 py-1 rounded-lg border text-xs font-bold backdrop-blur-sm ${typeColors[drive.type] || "text-foreground/70 bg-black/70 border-white/15"}`}>
                    {drive.type}
                  </div>
                </div>

                <div className="p-4 flex flex-col gap-3 flex-grow">
                  <h3 className="font-bold text-foreground text-base">{drive.name}</h3>

                  {drive.description && (
                    <p className="text-xs text-foreground/60 leading-relaxed">{drive.description}</p>
                  )}

                  <div className="grid grid-cols-3 gap-2">
                    <div className="bg-muted/50 rounded-lg p-2 text-center">
                      <Database className="w-3.5 h-3.5 text-secondary mx-auto mb-1" />
                      <p className="text-[10px] text-foreground/50">{t("hd_capacity")}</p>
                      <p className="text-xs font-bold text-secondary font-nums">{drive.capacity}</p>
                    </div>
                    <div className="bg-muted/50 rounded-lg p-2 text-center">
                      <Zap className="w-3.5 h-3.5 text-primary mx-auto mb-1" />
                      <p className="text-[10px] text-foreground/50">{t("hd_speed")}</p>
                      <p className="text-xs font-bold text-primary leading-tight font-nums">{drive.speed}</p>
                    </div>
                    <div className="bg-muted/50 rounded-lg p-2 text-center">
                      <Tag className="w-3.5 h-3.5 text-green-400 mx-auto mb-1" />
                      <p className="text-[10px] text-foreground/50">{t("hd_price")}</p>
                      <p className="text-xs font-bold text-green-400 font-nums">{drive.price}</p>
                    </div>
                  </div>

                  <div className="flex gap-2 mt-auto">
                    <a
                      href="https://wa.me/201559665337"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex-1 flex items-center justify-center gap-2 py-2.5 bg-green-500/15 border border-green-500/40 hover:bg-green-500/25 text-green-400 font-bold rounded-xl text-sm transition-all"
                    >
                      <MessageCircle className="w-4 h-4" />
                      {t("hd_order_whatsapp")}
                    </a>
                    <button
                      onClick={() => openPicker(parseDriveCapacityGB(drive.capacity))}
                      className="flex items-center justify-center gap-1.5 px-3 py-2.5 btn-gradient rounded-xl text-sm font-bold"
                      title={t("games_orderHardDrive")}
                    >
                      <Package className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
