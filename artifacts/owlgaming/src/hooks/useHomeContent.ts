import { useState, useCallback, useEffect } from "react";
import { apiUrl } from "@/lib/api";

export interface HomeContent {
  heroTitle: string;
  heroSubtitle: string;
  heroDescription: string;
  heroImage: string;
  heroImageLabel: string;
  stat1Value: string;
  stat1Label: string;
  stat2Value: string;
  stat2Label: string;
  stat3Value: string;
  stat3Label: string;
  badgeText: string;
  secondaryImage: string;
  backgroundImage: string;
}

export const DEFAULT_HOME_CONTENT: HomeContent = {
  heroTitle: "مرحباً بك في",
  heroSubtitle: "GAMEARLY",
  heroDescription:
    "وجهتك المثالية لبيانات الألعاب والهاردات وإكسسوارات الألعاب. استمتع بتجربة ألعاب لا مثيل لها مع مجموعتنا المميزة.",
  heroImage: "https://cdn.cloudflare.steamstatic.com/steam/apps/3321460/library_hero.jpg",
  heroImageLabel: "Crimson Desert",
  stat1Value: "500+",
  stat1Label: "لعبة متاحة",
  stat2Value: "10K+",
  stat2Label: "عميل سعيد",
  stat3Value: "24/7",
  stat3Label: "دعم فني",
  badgeText: "جنتك في الألعاب",
  secondaryImage:
    "https://cdn.cloudflare.steamstatic.com/steam/apps/3764200/library_hero.jpg",
  backgroundImage:
    "https://cdn.cloudflare.steamstatic.com/steam/apps/814380/library_hero.jpg",
};

const SETTING_KEY = "home_content";

async function fetchSettings(): Promise<HomeContent | null> {
  try {
    const res = await fetch(apiUrl("/api/site-settings"));
    if (!res.ok) return null;
    const data = await res.json();
    const val = data?.data?.[SETTING_KEY];
    if (!val) return null;
    return { ...DEFAULT_HOME_CONTENT, ...val };
  } catch {
    return null;
  }
}

async function persistSettings(homeContent: HomeContent): Promise<void> {
  try {
    const token = sessionStorage.getItem("gh_admin_token") || "";
    await fetch(apiUrl("/api/site-settings"), {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ [SETTING_KEY]: homeContent }),
    });
  } catch {}
}

export function useHomeContent() {
  const [content, setContent] = useState<HomeContent>(DEFAULT_HOME_CONTENT);

  useEffect(() => {
    fetchSettings().then((saved) => {
      if (saved) setContent(saved);
    });
  }, []);

  useEffect(() => {
    const interval = setInterval(() => {
      fetchSettings().then((saved) => {
        if (saved) setContent(saved);
      });
    }, 60_000);
    return () => clearInterval(interval);
  }, []);

  const updateContent = useCallback((updates: Partial<HomeContent>) => {
    setContent((prev) => {
      const next = { ...prev, ...updates };
      persistSettings(next);
      return next;
    });
  }, []);

  const resetContent = useCallback(() => {
    setContent(DEFAULT_HOME_CONTENT);
    persistSettings(DEFAULT_HOME_CONTENT);
  }, []);

  return { content, updateContent, resetContent };
}
