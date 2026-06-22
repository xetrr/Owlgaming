import { useState, useCallback, useEffect } from "react";
import { apiUrl } from "@/lib/api";

export interface Brand {
  name: string;
  browserTitle: string;
  taglineEn: string;
  taglineAr: string;
  heroTitleEn: string;
  heroTitleAr: string;
  heroDescriptionEn: string;
  heroDescriptionAr: string;
  footerTaglineEn: string;
  footerTaglineAr: string;
  footerRightsEn: string;
  footerRightsAr: string;
  footerPassionEn: string;
  footerPassionAr: string;
  authJoinEn: string;
  authJoinAr: string;
  logoUrl: string;
  faviconUrl: string;
  invoiceFooter: string;
  invoiceLabel: string;
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
  try {
    const res = await fetch(apiUrl("/api/site-settings"));
    if (!res.ok) return null;
    const data = await res.json();
    const val = data?.data?.[SETTING_KEY];
    if (!val) return null;
    return { ...DEFAULT_BRAND, ...val };
  } catch {
    return null;
  }
}

async function persistBrand(brand: Brand): Promise<void> {
  try {
    const token = sessionStorage.getItem("gh_admin_token") || "";
    await fetch(apiUrl("/api/site-settings"), {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ [SETTING_KEY]: brand }),
    });
  } catch { /* ignore */ }
}

export function useBrand() {
  const [brand, setBrand] = useState<Brand>(DEFAULT_BRAND);

  useEffect(() => {
    fetchBrand().then((saved) => {
      if (saved) setBrand(saved);
    });
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

export function withBrand(tpl: string, brandName: string): string {
  return tpl.replace(/\{brand\}/g, brandName);
}
