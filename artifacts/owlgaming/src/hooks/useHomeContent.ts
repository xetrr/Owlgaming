import { useState, useCallback, useEffect } from "react";
import { supabase, isSupabaseConfigured } from "@/lib/supabase";

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

  // Crimson Desert — Pearl Abyss open-world action RPG (Steam App 3321460, released Mar 2026)
  heroImage: "https://cdn.cloudflare.steamstatic.com/steam/apps/3321460/library_hero.jpg",
  heroImageLabel: "Crimson Desert",

  stat1Value: "500+",
  stat1Label: "لعبة متاحة",
  stat2Value: "10K+",
  stat2Label: "عميل سعيد",
  stat3Value: "24/7",
  stat3Label: "دعم فني",
  badgeText: "جنتك في الألعاب",

  // Resident Evil Requiem (RE9) — Capcom survival horror (Steam App 3764200, released Feb 2026)
  secondaryImage:
    "https://cdn.cloudflare.steamstatic.com/steam/apps/3764200/library_hero.jpg",

  // Sekiro: Shadows Die Twice — high-quality library hero art (Steam App 814380)
  backgroundImage:
    "https://cdn.cloudflare.steamstatic.com/steam/apps/814380/library_hero.jpg",
};

const SETTING_KEY = "home_content";

async function fetchSettings(): Promise<HomeContent | null> {
  if (!isSupabaseConfigured || !supabase) return null;
  try {
    const { data, error } = await supabase
      .from("site_settings")
      .select("value")
      .eq("key", SETTING_KEY)
      .single();
    if (error || !data) return null;
    return { ...DEFAULT_HOME_CONTENT, ...data.value };
  } catch {
    return null;
  }
}

async function persistSettings(homeContent: HomeContent): Promise<void> {
  if (!isSupabaseConfigured || !supabase) return;
  try {
    await supabase
      .from("site_settings")
      .upsert({ key: SETTING_KEY, value: homeContent }, { onConflict: "key" });
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
    if (!isSupabaseConfigured || !supabase) return;
    const sb = supabase;
    const channelName = `home-content-changes-${Math.random().toString(36).slice(2)}`;
    let channel: ReturnType<typeof sb.channel> | null = null;
    try {
      channel = sb
        .channel(channelName)
        .on(
          "postgres_changes",
          { event: "*", schema: "public", table: "site_settings", filter: `key=eq.${SETTING_KEY}` },
          (payload) => {
            const newValue = (payload.new as any)?.value;
            if (newValue) setContent({ ...DEFAULT_HOME_CONTENT, ...newValue });
          }
        )
        .subscribe();
    } catch (err) {
      console.warn("[useHomeContent] realtime subscription failed:", err);
    }
    return () => {
      if (channel) {
        try { sb.removeChannel(channel); } catch { /* noop */ }
      }
    };
  }, []);

  useEffect(() => {
    if (!isSupabaseConfigured) return;
    const interval = setInterval(() => {
      fetchSettings().then((saved) => {
        if (saved) setContent(saved);
      });
    }, 5_000);
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
