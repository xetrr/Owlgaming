import { Link } from "react-router-dom";
import { Gamepad2, HardDrive, Package, Heart, Phone, Mail, MapPin, Facebook, MessageCircle } from "lucide-react";
import { useContactInfo } from "@/hooks/useContactInfo";
import { useLang } from "@/contexts/LanguageContext";
import { useBrand } from "@/hooks/useBrand";

export default function Footer() {
  const currentYear = new Date().getFullYear();
  const { info } = useContactInfo();
  const { t, lang } = useLang();
  const { brand } = useBrand();
  const tagline = lang === "ar" ? brand.footerTaglineAr : brand.footerTaglineEn;
  const rights = lang === "ar" ? brand.footerRightsAr : brand.footerRightsEn;
  const passion = lang === "ar" ? brand.footerPassionAr : brand.footerPassionEn;

  return (
    <footer
      className="mt-20 border-t border-white/5"
      style={{ background: "rgba(6,8,18,0.98)" }}
      dir="ltr"
    >
      {/* Top rainbow divider */}
      <div className="h-px w-full" style={{
        background: "linear-gradient(90deg, transparent 0%, #f97316 20%, #ec4899 45%, #a66cff 70%, #5f9cff 90%, transparent 100%)"
      }} />

      <div className="container mx-auto px-4 py-14">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-10 mb-12">

          {/* Brand */}
          <div className="text-left">
            <Link to="/" className="mb-5 w-fit flex items-center">
              <h3 className="text-base font-black logo-gradient-text font-heading tracking-widest uppercase">{brand.name}</h3>
            </Link>

            <p className="text-sm text-foreground/45 mb-6 leading-relaxed" dir="auto">
              {tagline}
            </p>

            <div>
              <p className="text-[10px] font-black tracking-[0.25em] uppercase text-primary/70 mb-3">
                {t("footer_followUs")}
              </p>
              <div className="flex gap-3">
                <a
                  href={info.facebook}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="group p-2.5 rounded-xl border border-[#1877F2]/30 bg-[#1877F2]/10 hover:bg-[#1877F2]/20 hover:border-[#1877F2]/60 transition-all"
                  aria-label="Facebook"
                >
                  <Facebook className="w-4 h-4 text-[#1877F2] group-hover:scale-110 transition-transform" />
                </a>
                <a
                  href={`https://wa.me/${info.whatsapp}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="group p-2.5 rounded-xl border border-[#25D366]/30 bg-[#25D366]/10 hover:bg-[#25D366]/20 hover:border-[#25D366]/60 transition-all"
                  aria-label="WhatsApp"
                >
                  <MessageCircle className="w-4 h-4 text-[#25D366] group-hover:scale-110 transition-transform" />
                </a>
              </div>
            </div>
          </div>

          {/* Navigation */}
          <div className="text-left">
            <h3 className="text-[10px] font-black tracking-[0.25em] uppercase text-primary/70 mb-6">
              {t("footer_navigation")}
            </h3>
            <ul className="space-y-3">
              {[
                { to: "/games",       icon: <Gamepad2 className="w-3.5 h-3.5 text-primary/60" />,     label: t("footer_gameData") },
                { to: "/harddisks",   icon: <HardDrive className="w-3.5 h-3.5 text-secondary/60" />,   label: t("footer_hardDrives") },
                { to: "/accessories", icon: <Package className="w-3.5 h-3.5 text-[#4fd1c5]/60" />,     label: t("nav_accessories") },
                { to: "/favorites",   icon: <Heart className="w-3.5 h-3.5 text-pink-500/60" />,        label: t("footer_myFavorites") },
                { to: "/contact",     icon: <Phone className="w-3.5 h-3.5 text-primary/60" />,         label: t("footer_contactUs") },
              ].map(({ to, icon, label }) => (
                <li key={to}>
                  <Link
                    to={to}
                    className="text-xs font-medium text-foreground/45 hover:text-foreground transition-colors flex items-center gap-2"
                  >
                    {icon}
                    <span dir="auto">{label}</span>
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Contact */}
          <div className="text-left">
            <h3 className="text-[10px] font-black tracking-[0.25em] uppercase text-primary/70 mb-6">
              {t("footer_getInTouch")}
            </h3>
            <ul className="space-y-3.5">
              <li>
                <a
                  href={`https://wa.me/${info.whatsapp}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="group flex items-center gap-2.5"
                >
                  <span className="w-7 h-7 rounded-lg bg-[#25D366]/10 border border-[#25D366]/25 flex items-center justify-center flex-shrink-0">
                    <MessageCircle className="w-3.5 h-3.5 text-[#25D366]" />
                  </span>
                  <span className="text-xs font-medium text-foreground/45 group-hover:text-foreground transition-colors font-nums">
                    {info.phone}
                  </span>
                </a>
              </li>
              <li>
                <a
                  href={`mailto:${info.email}`}
                  className="group flex items-center gap-2.5"
                >
                  <span className="w-7 h-7 rounded-lg bg-primary/10 border border-primary/25 flex items-center justify-center flex-shrink-0">
                    <Mail className="w-3.5 h-3.5 text-primary" />
                  </span>
                  <span className="text-xs font-medium text-foreground/45 group-hover:text-foreground transition-colors">
                    {info.email}
                  </span>
                </a>
              </li>
              <li>
                <a
                  href={info.mapUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="group flex items-center gap-2.5"
                >
                  <span className="w-7 h-7 rounded-lg bg-secondary/10 border border-secondary/25 flex items-center justify-center flex-shrink-0">
                    <MapPin className="w-3.5 h-3.5 text-secondary" />
                  </span>
                  <span className="text-xs font-medium text-foreground/45 group-hover:text-foreground transition-colors" dir="auto">
                    {info.location}
                  </span>
                </a>
              </li>
            </ul>
          </div>
        </div>

        {/* Bottom bar */}
        <div className="border-t border-white/5 pt-8 flex flex-col sm:flex-row justify-between items-center gap-3 text-xs text-foreground/25">
          <p>© {currentYear} {brand.name}. {rights}</p>
          <p className="flex items-center gap-1.5">
            <span dir="auto">{passion}</span>
            <Heart className="w-3 h-3 text-pink-500/60" />
          </p>
        </div>
      </div>
    </footer>
  );
}
