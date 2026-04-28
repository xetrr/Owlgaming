import { Phone, MessageCircle, Facebook, MapPin, Clock } from "lucide-react";
import { useContactInfo } from "@/hooks/useContactInfo";
import { useLang } from "@/contexts/LanguageContext";
import { useBrand } from "@/hooks/useBrand";

export default function Contact() {
  const { info } = useContactInfo();
  const { t } = useLang();
  const { brand } = useBrand();

  return (
    <div className="min-h-screen">
      <div className="h-16" />

      <div className="container mx-auto px-4 py-12">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <h1 className="text-4xl md:text-5xl font-bold text-foreground mb-4">{t("contact_title")}</h1>
            <p className="text-lg text-foreground/60 max-w-xl mx-auto">
              {t("contact_subtitle")}
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-6 mb-10">
            {/* WhatsApp */}
            <a
              href={`https://wa.me/${info.whatsapp}`}
              target="_blank"
              rel="noopener noreferrer"
              className="group bg-card border border-border hover:border-green-500/50 rounded-2xl p-6 flex items-start gap-4 transition-all hover:shadow-lg hover:shadow-green-500/10"
            >
              <div className="w-12 h-12 rounded-xl bg-green-500/15 border border-green-500/30 flex items-center justify-center flex-shrink-0 group-hover:bg-green-500/25 transition-colors">
                <MessageCircle className="w-6 h-6 text-green-500" />
              </div>
              <div>
                <h3 className="font-bold text-foreground text-lg mb-1">WhatsApp</h3>
                <p className="text-foreground/60 text-sm mb-2">{t("contact_whatsapp_desc")}</p>
                <span className="text-green-500 font-bold text-base font-nums">{info.phone}</span>
              </div>
            </a>

            {/* Phone */}
            <a
              href={`tel:${info.phone}`}
              className="group bg-card border border-border hover:border-primary/50 rounded-2xl p-6 flex items-start gap-4 transition-all hover:shadow-lg hover:shadow-primary/10"
            >
              <div className="w-12 h-12 rounded-xl bg-primary/15 border border-primary/30 flex items-center justify-center flex-shrink-0 group-hover:bg-primary/25 transition-colors">
                <Phone className="w-6 h-6 text-primary" />
              </div>
              <div>
                <h3 className="font-bold text-foreground text-lg mb-1">Phone</h3>
                <p className="text-foreground/60 text-sm mb-2">{t("contact_phone_desc")}</p>
                <span className="text-primary font-bold text-base font-nums">{info.phone}</span>
              </div>
            </a>

            {/* Facebook */}
            <a
              href={info.facebook}
              target="_blank"
              rel="noopener noreferrer"
              className="group bg-card border border-border hover:border-blue-500/50 rounded-2xl p-6 flex items-start gap-4 transition-all hover:shadow-lg hover:shadow-blue-500/10"
            >
              <div className="w-12 h-12 rounded-xl bg-blue-500/15 border border-blue-500/30 flex items-center justify-center flex-shrink-0 group-hover:bg-blue-500/25 transition-colors">
                <Facebook className="w-6 h-6 text-blue-500" />
              </div>
              <div>
                <h3 className="font-bold text-foreground text-lg mb-1">Facebook</h3>
                <p className="text-foreground/60 text-sm mb-2">{t("contact_facebook_desc")}</p>
                <span className="font-bold text-base logo-gradient-text font-heading">{brand.name}</span>
              </div>
            </a>

            {/* Location */}
            <a
              href={info.mapUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="group bg-card border border-border hover:border-secondary/50 rounded-2xl p-6 flex items-start gap-4 transition-all hover:shadow-lg hover:shadow-secondary/10"
            >
              <div className="w-12 h-12 rounded-xl bg-secondary/15 border border-secondary/30 flex items-center justify-center flex-shrink-0 group-hover:bg-secondary/25 transition-colors">
                <MapPin className="w-6 h-6 text-secondary" />
              </div>
              <div>
                <h3 className="font-bold text-foreground text-lg mb-1">Location</h3>
                <p className="text-foreground/60 text-sm mb-2">{t("contact_location_desc")}</p>
                <span className="text-secondary font-bold text-base">{info.location}</span>
              </div>
            </a>
          </div>

          {/* Business Hours */}
          <div className="bg-card border border-border rounded-2xl p-6">
            <div className="flex items-center gap-3 mb-5">
              <div className="w-10 h-10 rounded-xl bg-primary/15 flex items-center justify-center">
                <Clock className="w-5 h-5 text-primary" />
              </div>
              <h3 className="font-bold text-foreground text-xl">{t("contact_hours_title")}</h3>
            </div>
            <div className="grid sm:grid-cols-2 gap-3">
              {info.hours.map(({ days, hours }) => (
                <div key={days} className="bg-muted/50 rounded-xl p-4 flex justify-between items-center">
                  <span className="text-sm font-medium text-foreground/70">{days}</span>
                  <span className="text-sm font-bold text-primary">{hours}</span>
                </div>
              ))}
            </div>
            <p className="text-xs text-foreground/40 mt-4 text-center">
              {t("contact_hours_note")}
            </p>
          </div>

          <div className="mt-8 text-center">
            <a
              href={`https://wa.me/${info.whatsapp}`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-3 px-8 py-4 bg-green-500 hover:bg-green-600 text-white font-bold rounded-2xl transition-all hover:shadow-lg hover:shadow-green-500/30 text-lg"
            >
              <MessageCircle className="w-6 h-6" />
              {t("contact_chat_btn")}
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}
