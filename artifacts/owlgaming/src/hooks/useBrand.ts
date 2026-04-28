import { useState, useCallback, useEffect } from "react";
import { supabase, isSupabaseConfigured } from "@/lib/supabase";

export interface Brand {
  /** Brand name shown in headings, footer, hero, invoice, etc. */
  name: string;
  /** Browser tab title (defaults to brand name when empty). */
  browserTitle: string;
  /** Short tagline shown next to the brand in footers / meta. */
  taglineEn: string;
  taglineAr: string;
  /** Hero copy on home page. */
  heroTitleEn: string;
  heroTitleAr: string;
  heroDescriptionEn: string;
  heroDescriptionAr: string;
  /** Footer copy. */
  footerTaglineEn: string;
  footerTaglineAr: string;
  footerRightsEn: string;
  footerRightsAr: string;
  footerPassionEn: string;
  footerPassionAr: string;
  /** Auth modal copy. */
  authJoinEn: string;
  authJoinAr: string;
  /** Logo + favicon URLs (empty -> show text only). */
  logoUrl: string;
  faviconUrl: string;
  /** Bill / invoice copy. */
  invoiceFooter: string;
  invoiceLabel: string;
  /** Theme accent (CSS hex), optional. */
  accentColor: string;
}

export const DEFAULT_BRAND: Brand = {
  name: "GAMEARLY",
  browserTitle: "GAMEARLY — Games, Hard Drives & Accessories",
  taglineEn: "Your gaming paradise",
  taglineAr: "جنتك في الألعاب",
  heroTitleEn: "Welcome to",
  heroTitleAr: "مرحباً بك في",
  heroDescriptionEn:
    "Your ultimate destination for game data, hard drives, and gaming accessories. Experience gaming like never before with our premium collection.",
  heroDescriptionAr:
    "وجهتك المثالية لبيانات الألعاب والهاردات وإكسسوارات الألعاب. استمتع بتجربة ألعاب لا مثيل لها مع مجموعتنا المميزة.",
  footerTaglineEn:
    "Your premier destination for game data, hard drives, and gaming accessories. Gaming paradise awaits.",
  footerTaglineAr:
    "وجهتك المثالية لبيانات الألعاب والهاردات وإكسسوارات الألعاب. جنتك في الألعاب بانتظارك.",
  footerRightsEn: "All rights reserved.",
  footerRightsAr: "جميع الحقوق محفوظة.",
  footerPassionEn: "Made with passion for gaming",
  footerPassionAr: "صُنع بشغف للألعاب",
  authJoinEn: "Join {brand}",
  authJoinAr: "انضم إلى {brand}",
  logoUrl: "/owl-logo.png",
  faviconUrl: "/favicon.svg",
  invoiceFooter:
    "Thank you for your order! Contact us on WhatsApp for download details.",
  invoiceLabel: "ORDER RECEIPT",
  accentColor: "",
};

const SETTING_KEY = "brand";

async function fetchBrand(): Promise<Brand | null> {
  if (!isSupabaseConfigured || !supabase) return null;
  try {
    const { data, error } = await supabase
      .from("site_settings")
      .select("value")
      .eq("key", SETTING_KEY)
      .single();
    if (error || !data) return null;
    return { ...DEFAULT_BRAND, ...data.value };
  } catch {
    return null;
  }
}

async function persistBrand(brand: Brand): Promise<void> {
  if (!isSupabaseConfigured || !supabase) return;
  try {
    await supabase
      .from("site_settings")
      .upsert({ key: SETTING_KEY, value: brand }, { onConflict: "key" });
  } catch {
    /* ignore */
  }
}

export function useBrand() {
  const [brand, setBrand] = useState<Brand>(DEFAULT_BRAND);

  useEffect(() => {
    fetchBrand().then((saved) => {
      if (saved) setBrand(saved);
    });
  }, []);

  // Live updates whenever the brand row changes elsewhere.
  useEffect(() => {
    if (!isSupabaseConfigured || !supabase) return;
    // Unique channel name per mount so HMR / StrictMode double-mount can't
    // collide with an already-subscribed channel.
    const channelName = `brand-changes-${Math.random().toString(36).slice(2, 10)}`;
    const channel = supabase.channel(channelName);
    channel
      .on(
        "postgres_changes",
        {
          event: "*",
          schema: "public",
          table: "site_settings",
          filter: `key=eq.${SETTING_KEY}`,
        },
        (payload) => {
          const next = (payload.new as any)?.value;
          if (next) setBrand({ ...DEFAULT_BRAND, ...next });
        },
      )
      .subscribe();
    return () => {
      try {
        supabase!.removeChannel(channel);
      } catch {
        /* noop */
      }
    };
  }, []);

  const updateBrand = useCallback((updates: Partial<Brand>) => {
    setBrand((prev) => {
      const next = { ...prev, ...updates };
      persistBrand(next);
      return next;
    });
  }, []);

  const resetBrand = useCallback(() => {
    setBrand(DEFAULT_BRAND);
    persistBrand(DEFAULT_BRAND);
  }, []);

  return { brand, updateBrand, resetBrand };
}

/** Replace `{brand}` placeholder inside a translation string. */
export function withBrand(tpl: string, brandName: string): string {
  return tpl.replace(/\{brand\}/g, brandName);
}
