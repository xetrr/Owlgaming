import { useState } from "react";
import { X, HardDrive, Package, Unlock } from "lucide-react";
import { useHardDrive } from "@/contexts/HardDriveContext";
import { useLang } from "@/contexts/LanguageContext";

const PRESETS = [
  { label: "500GB", rawGB: 500, netGB: 465 },
  { label: "480GB", rawGB: 480, netGB: 447 },
  { label: "250GB", rawGB: 250, netGB: 232 },
  { label: "2TB", rawGB: 2048, netGB: 1810 },
  { label: "1TB", rawGB: 1024, netGB: 931 },
  { label: "512GB", rawGB: 512, netGB: 477 },
  { label: "8TB", rawGB: 8192, netGB: 7280 },
  { label: "4TB", rawGB: 4096, netGB: 3630 },
  { label: "3TB", rawGB: 3072, netGB: 2710 },
];

export default function HardDrivePickerModal() {
  const { showPicker, closePicker, selectDrive, setUnlimited, preselectedGB } = useHardDrive();
  const { t, isRTL } = useLang();
  const [customGB, setCustomGB] = useState(preselectedGB ? String(preselectedGB) : "");
  const [selected, setSelected] = useState<number | null>(
    preselectedGB
      ? (PRESETS.find((p) => p.netGB === preselectedGB || p.rawGB === preselectedGB)?.netGB ?? null)
      : null
  );

  if (!showPicker) return null;

  const handlePreset = (netGB: number) => {
    setSelected(netGB);
    setCustomGB("");
  };

  const handleConfirmCustom = () => {
    const val = parseInt(customGB, 10);
    if (!isNaN(val) && val > 0) {
      selectDrive(val);
    }
  };

  const handleConfirmPreset = () => {
    if (selected !== null) selectDrive(selected);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: "rgba(0,0,0,0.75)", backdropFilter: "blur(6px)" }}
      onClick={(e) => { if (e.target === e.currentTarget) closePicker(); }}
    >
      <div
        className="relative w-full max-w-md rounded-2xl border border-border/60 shadow-2xl overflow-hidden"
        style={{ background: "linear-gradient(160deg, #1a1f3a 0%, #0f1225 100%)" }}
        dir={isRTL ? "rtl" : "ltr"}
      >
        <button
          onClick={closePicker}
          className="absolute top-4 right-4 w-8 h-8 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center hover:bg-white/10 transition-colors z-10"
        >
          <X className="w-4 h-4 text-foreground/70" />
        </button>

        <div className="flex flex-col items-center px-6 pt-8 pb-6 gap-4">
          <div className="w-16 h-16 rounded-2xl bg-primary/10 border border-primary/20 flex items-center justify-center">
            <Package className="w-8 h-8 text-primary" />
          </div>

          <div className="text-center">
            <h2 className="text-2xl font-black text-foreground mb-1">{t("picker_title")}</h2>
            <p className="text-sm text-foreground/50">{t("picker_subtitle")}</p>
          </div>

          <div className="grid grid-cols-3 gap-2 w-full mt-2">
            {PRESETS.map((preset) => (
              <button
                key={preset.label}
                onClick={() => handlePreset(preset.netGB)}
                className={`flex flex-col items-center justify-center py-3 px-2 rounded-xl border transition-all text-center ${
                  selected === preset.netGB
                    ? "border-primary bg-primary/15 text-primary"
                    : "border-border bg-white/3 hover:border-primary/40 hover:bg-white/5 text-foreground"
                }`}
              >
                <span className="text-sm font-black">{preset.label}</span>
                <span className="text-[10px] text-foreground/50 mt-0.5">{t("picker_net")}: {preset.netGB}G</span>
              </button>
            ))}
          </div>

          <div className="w-full bg-white/5 border border-border rounded-xl p-4">
            <p className="text-xs text-foreground/50 text-center mb-3">{t("picker_customLabel")}</p>
            <div className="flex gap-2">
              <button
                onClick={handleConfirmCustom}
                disabled={!customGB || isNaN(parseInt(customGB, 10)) || parseInt(customGB, 10) <= 0}
                className="px-4 py-2.5 btn-gradient rounded-xl text-sm font-black disabled:opacity-40 disabled:cursor-not-allowed whitespace-nowrap"
              >
                {t("picker_confirm")}
              </button>
              <input
                type="number"
                value={customGB}
                onChange={(e) => { setCustomGB(e.target.value); setSelected(null); }}
                placeholder={t("picker_customPlaceholder")}
                min={1}
                className="flex-1 bg-white/5 border border-border rounded-xl px-3 py-2 text-foreground text-sm placeholder:text-foreground/30 focus:outline-none focus:ring-2 focus:ring-primary/40"
              />
            </div>
          </div>

          {selected !== null && (
            <button
              onClick={handleConfirmPreset}
              className="w-full py-3 btn-gradient rounded-xl font-black text-sm flex items-center justify-center gap-2"
            >
              <HardDrive className="w-4 h-4" />
              {t("picker_confirmPreset")} — {PRESETS.find(p => p.netGB === selected)?.label}
            </button>
          )}

          <button
            onClick={setUnlimited}
            className="w-full py-3 bg-white/5 border border-border hover:border-primary/30 rounded-xl text-sm text-foreground/70 hover:text-foreground font-bold transition-all flex items-center justify-center gap-2"
          >
            {t("picker_unlimited")}
          </button>

          <button
            onClick={closePicker}
            className="text-sm text-foreground/40 hover:text-foreground/70 transition-colors"
          >
            {t("picker_cancel")}
          </button>
        </div>
      </div>
    </div>
  );
}
