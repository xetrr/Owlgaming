import { useState, useCallback, useEffect } from "react";
import { supabase, isSupabaseConfigured } from "@/lib/supabase";

export interface Pricing {
  pricePerGb: number;
  currency: string;
}

export const DEFAULT_PRICING: Pricing = {
  pricePerGb: 0.20,
  currency: "EGP",
};

const SETTING_KEY = "pricing";

async function fetchPricing(): Promise<Pricing | null> {
  if (!isSupabaseConfigured || !supabase) return null;
  try {
    const { data, error } = await supabase
      .from("site_settings")
      .select("value")
      .eq("key", SETTING_KEY)
      .single();
    if (error || !data) return null;
    return { ...DEFAULT_PRICING, ...data.value };
  } catch {
    return null;
  }
}

async function persistPricing(pricing: Pricing): Promise<void> {
  if (!isSupabaseConfigured || !supabase) return;
  try {
    await supabase
      .from("site_settings")
      .upsert({ key: SETTING_KEY, value: pricing }, { onConflict: "key" });
  } catch {}
}

export function usePricing() {
  const [pricing, setPricingState] = useState<Pricing>(DEFAULT_PRICING);

  useEffect(() => {
    fetchPricing().then((saved) => {
      if (saved) setPricingState(saved);
    });
  }, []);

  useEffect(() => {
    if (!isSupabaseConfigured || !supabase) return;
    const sb = supabase;
    const channelName = `pricing-changes-${Math.random().toString(36).slice(2)}`;
    let channel: ReturnType<typeof sb.channel> | null = null;
    try {
      channel = sb
        .channel(channelName)
        .on(
          "postgres_changes",
          { event: "*", schema: "public", table: "site_settings", filter: `key=eq.${SETTING_KEY}` },
          (payload) => {
            const newValue = (payload.new as any)?.value;
            if (newValue) setPricingState({ ...DEFAULT_PRICING, ...newValue });
          }
        )
        .subscribe();
    } catch (err) {
      console.warn("[usePricing] realtime subscription failed:", err);
    }
    return () => {
      if (channel) {
        try { sb.removeChannel(channel); } catch { /* noop */ }
      }
    };
  }, []);

  const updatePricing = useCallback((updates: Partial<Pricing>) => {
    setPricingState((prev) => {
      const next = { ...prev, ...updates };
      persistPricing(next);
      return next;
    });
  }, []);

  const resetPricing = useCallback(() => {
    persistPricing(DEFAULT_PRICING);
    setPricingState(DEFAULT_PRICING);
  }, []);

  return { pricing, updatePricing, resetPricing };
}
