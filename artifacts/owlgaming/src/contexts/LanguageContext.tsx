import React, { createContext, useContext, useState, useEffect, ReactNode } from "react";
import { translations, Lang, TranslationKey } from "@/lib/translations";

interface LanguageContextType {
  lang: Lang;
  setLang: (l: Lang) => void;
  t: (key: TranslationKey, vars?: Record<string, string>) => string;
  dir: "ltr" | "rtl";
  isRTL: boolean;
}

const LanguageContext = createContext<LanguageContextType | undefined>(undefined);

export const LanguageProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [lang, setLangState] = useState<Lang>(() => {
    try { return (localStorage.getItem("owl_lang") as Lang) || "ar"; } catch { return "ar"; }
  });

  const isRTL = lang === "ar";
  const dir = isRTL ? "rtl" : "ltr";

  const setLang = (l: Lang) => {
    setLangState(l);
    try { localStorage.setItem("owl_lang", l); } catch {}
  };

  useEffect(() => {
    document.documentElement.dir = dir;
    document.documentElement.lang = lang;
  }, [lang, dir]);

  const t = (key: TranslationKey, vars?: Record<string, string>): string => {
    const raw = translations[lang][key] as string;
    if (!vars) return raw;
    return raw.replace(/\{(\w+)\}/g, (_, k: string) =>
      Object.prototype.hasOwnProperty.call(vars, k) ? vars[k] : `{${k}}`,
    );
  };

  return (
    <LanguageContext.Provider value={{ lang, setLang, t, dir, isRTL }}>
      {children}
    </LanguageContext.Provider>
  );
};

export const useLang = (): LanguageContextType => {
  const ctx = useContext(LanguageContext);
  if (!ctx) throw new Error("useLang must be used within LanguageProvider");
  return ctx;
};
