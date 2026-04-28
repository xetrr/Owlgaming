import { Link } from "react-router-dom";
import { ArrowRight, Gamepad2, HardDrive, Package, Zap, Crown } from "lucide-react";
import { useHomeContent } from "@/hooks/useHomeContent";
import { useHardDrive } from "@/contexts/HardDriveContext";
import { useLang } from "@/contexts/LanguageContext";
import { useBrand } from "@/hooks/useBrand";

export default function Index() {
  const { content } = useHomeContent();
  const { openPicker } = useHardDrive();
  const { t, lang } = useLang();
  const { brand } = useBrand();
  const heroTitle = lang === "ar" ? brand.heroTitleAr : brand.heroTitleEn;
  const heroDescription =
    lang === "ar" ? brand.heroDescriptionAr : brand.heroDescriptionEn;

  return (
    <div className="min-h-screen bg-background relative" dir="ltr">

      {/* Full-bleed background image with overlays */}
      <div className="absolute inset-x-0 top-0 h-[620px] z-0 pointer-events-none">
        <img
          src={content.backgroundImage}
          alt=""
          fetchPriority="high"
          decoding="async"
          className="w-full h-full object-cover object-top"
        />
        <div className="absolute inset-0 bg-gradient-to-r from-background via-background/85 to-background/20" />
        <div className="absolute inset-0 bg-gradient-to-t from-background via-background/55 to-transparent" />
        <div className="absolute inset-0 bg-background/20" />
      </div>

      <div className="h-16 relative z-10" />

      {/* Ambient glow — hidden on mobile (huge GPU blur kills perf on phones) */}
      <div className="hidden lg:block pointer-events-none fixed top-1/4 right-0 w-96 h-96 bg-secondary/8 rounded-full blur-[120px] z-0" />
      <div className="hidden lg:block pointer-events-none fixed top-1/3 right-1/4 w-64 h-64 bg-primary/6 rounded-full blur-[80px] z-0" />

      {/* ── HERO ─────────────────────────────────────────────── */}
      <section className="relative overflow-hidden py-20 md:py-32 z-10">
        <div className="container mx-auto px-4">
          <div className="grid lg:grid-cols-2 gap-12 items-center">

            {/* Text column — always on left */}
            <div className="space-y-6 z-10 text-left">

              {/* Badge */}
              <div
                className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-bold mb-2 border border-primary/30"
                style={{ background: "rgba(166,108,255,0.10)" }}
              >
                <Crown className="w-3.5 h-3.5 text-primary" />
                <span className="gradient-text" dir="auto">{content.badgeText}</span>
              </div>

              {/* Heading */}
              <div className="space-y-3">
                <h1 className="text-4xl md:text-5xl lg:text-6xl font-black text-foreground leading-tight font-heading" dir="auto">
                  {heroTitle}{" "}
                  <span className="gradient-text font-heading tracking-widest">{brand.name}</span>
                </h1>
                <p className="text-lg text-foreground/55 md:text-xl leading-relaxed" dir="auto">
                  {heroDescription}
                </p>
              </div>

              {/* CTAs */}
              <div className="flex flex-col sm:flex-row gap-4 pt-4">
                <Link
                  to="/games"
                  className="inline-flex items-center justify-center gap-2 px-7 py-3 btn-gradient font-bold rounded-xl text-sm"
                >
                  <span dir="auto">{t("hero_browseGames")}</span>
                  <ArrowRight className="w-4 h-4" />
                </Link>
                <button
                  onClick={() => openPicker()}
                  className="inline-flex items-center justify-center gap-2 px-7 py-3 bg-white/4 border border-white/10 hover:border-primary/40 text-foreground font-bold rounded-xl transition-all text-sm hover:bg-white/6"
                >
                  <HardDrive className="w-4 h-4 text-primary" />
                  <span dir="auto">{t("hero_orderHardDrive")}</span>
                </button>
              </div>

              {/* Stats */}
              <div className="grid grid-cols-3 gap-3 pt-8">
                {[
                  { value: content.stat1Value, label: content.stat1Label, color: "from-primary/20 to-transparent", glow: "rgba(166,108,255,0.15)" },
                  { value: content.stat2Value, label: content.stat2Label, color: "from-secondary/20 to-transparent", glow: "rgba(95,156,255,0.15)" },
                  { value: content.stat3Value, label: content.stat3Label, color: "from-[#4fd1c5]/20 to-transparent", glow: "rgba(79,209,197,0.15)" },
                ].map(({ value, label, color, glow }) => (
                  <div
                    key={label}
                    className="relative rounded-2xl p-4 border border-white/7 overflow-hidden text-left"
                    style={{ background: "rgba(255,255,255,0.03)" }}
                  >
                    <div className={`absolute inset-0 bg-gradient-to-br ${color} pointer-events-none`} />
                    <div
                      className="absolute -bottom-4 -right-4 w-16 h-16 rounded-full blur-xl pointer-events-none"
                      style={{ background: glow }}
                    />
                    <p className="text-2xl md:text-3xl font-black text-foreground font-nums relative z-10">{value}</p>
                    <p className="text-xs text-foreground/50 mt-1 relative z-10" dir="auto">{label}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Hero image — always on right */}
            <div className="relative hidden lg:block">
              <div className="relative rounded-2xl overflow-hidden border border-white/8 shadow-2xl glow-accent">
                <img
                  src={content.heroImage}
                  alt={content.heroImageLabel}
                  loading="lazy"
                  decoding="async"
                  className="w-full h-[380px] object-cover object-top"
                />
                <div className="absolute inset-0 bg-gradient-to-t from-background/70 via-transparent to-transparent" />
                <div
                  className="absolute bottom-4 left-4 px-3 py-1.5 rounded-xl border border-white/10 backdrop-blur-md"
                  style={{ background: "rgba(15,17,23,0.75)" }}
                >
                  <p className="text-sm font-bold text-white">{content.heroImageLabel}</p>
                </div>
              </div>
              <div className="absolute -inset-6 bg-primary/6 rounded-3xl blur-3xl -z-10" />
              <div className="absolute -inset-6 bg-secondary/4 rounded-3xl blur-3xl -z-10" />
            </div>
          </div>
        </div>
      </section>

      {/* ── FEATURES ─────────────────────────────────────────── */}
      <section className="relative z-10 py-20 border-t border-white/5">
        <div className="container mx-auto px-4">
          <div className="text-center mb-14">
            <h2 className="text-3xl md:text-4xl font-black text-foreground mb-4 font-heading" dir="auto">
              {t("features_title")}
            </h2>
            <p className="text-foreground/45 max-w-xl mx-auto" dir="auto">
              {t("features_subtitle")}
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-5">
            {[
              {
                icon: Gamepad2,
                titleKey: "features_games_title" as const,
                descKey: "features_games_desc" as const,
                href: "/games",
                iconGrad: "from-primary/30 to-primary/5",
                iconColor: "text-primary",
                glow: "rgba(166,108,255,0.08)",
              },
              {
                icon: HardDrive,
                titleKey: "features_drives_title" as const,
                descKey: "features_drives_desc" as const,
                href: "/harddisks",
                iconGrad: "from-secondary/30 to-secondary/5",
                iconColor: "text-secondary",
                glow: "rgba(95,156,255,0.08)",
              },
              {
                icon: Package,
                titleKey: "features_accessories_title" as const,
                descKey: "features_accessories_desc" as const,
                href: "/accessories",
                iconGrad: "from-[#4fd1c5]/30 to-[#4fd1c5]/5",
                iconColor: "text-[#4fd1c5]",
                glow: "rgba(79,209,197,0.08)",
              },
            ].map(({ icon: Icon, titleKey, descKey, href, iconGrad, iconColor, glow }) => (
              <Link
                key={href}
                to={href}
                className="group relative rounded-2xl p-6 border border-white/6 transition-all duration-300 hover:border-primary/35 hover:-translate-y-1 card-accent-top overflow-hidden text-left"
                style={{ background: "rgba(255,255,255,0.03)" }}
              >
                <div
                  className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none rounded-2xl"
                  style={{ boxShadow: `0 20px 60px ${glow}` }}
                />
                <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${iconGrad} border border-white/8 flex items-center justify-center mb-5`}>
                  <Icon className={`w-6 h-6 ${iconColor}`} />
                </div>
                <h3 className="text-base font-black text-foreground mb-2" dir="auto">{t(titleKey)}</h3>
                <p className="text-sm text-foreground/50 leading-relaxed" dir="auto">{t(descKey)}</p>
                <div className="mt-5 flex items-center gap-1 text-sm font-bold opacity-0 group-hover:opacity-100 transition-opacity"
                  style={{ color: "hsl(var(--primary))" }}>
                  <span dir="auto">{t("explore")}</span>
                  <ArrowRight className="w-4 h-4" />
                </div>
              </Link>
            ))}
          </div>
        </div>
      </section>

      {/* ── WHY GAMEARLY ─────────────────────────────────────── */}
      <section className="relative z-10 py-20 border-t border-white/5">
        <div className="container mx-auto px-4">
          <div className="grid md:grid-cols-2 gap-12 items-center">
            <div className="text-left">
              <h2 className="text-3xl md:text-4xl font-black text-foreground mb-8 font-heading" dir="auto">
                {t("whyus_title")} <span className="gradient-text font-heading">{brand.name}</span>
              </h2>
              <div className="space-y-3">
                {[
                  { icon: Zap,     titleKey: "whyus_fast_title" as const,     descKey: "whyus_fast_desc" as const },
                  { icon: Crown,   titleKey: "whyus_premium_title" as const,   descKey: "whyus_premium_desc" as const },
                  { icon: Package, titleKey: "whyus_allinone_title" as const,  descKey: "whyus_allinone_desc" as const },
                ].map(({ icon: Icon, titleKey, descKey }) => (
                  <div
                    key={titleKey}
                    className="flex gap-4 p-4 rounded-xl border border-white/6 hover:border-primary/30 transition-colors"
                    style={{ background: "rgba(255,255,255,0.025)" }}
                  >
                    <div className="w-10 h-10 rounded-xl bg-primary/15 border border-primary/20 flex items-center justify-center flex-shrink-0">
                      <Icon className="w-5 h-5 text-primary" />
                    </div>
                    <div>
                      <h4 className="font-bold text-foreground mb-1" dir="auto">{t(titleKey)}</h4>
                      <p className="text-sm text-foreground/50" dir="auto">{t(descKey)}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="relative hidden md:block">
              <div className="rounded-2xl overflow-hidden border border-white/8">
                <img
                  src={content.secondaryImage}
                  alt="Gaming setup"
                  loading="lazy"
                  decoding="async"
                  className="w-full h-64 object-cover object-top"
                />
              </div>
              <div className="absolute -inset-4 bg-primary/5 rounded-3xl blur-2xl -z-10" />
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
