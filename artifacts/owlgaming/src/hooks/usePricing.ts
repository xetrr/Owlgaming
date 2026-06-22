import { useState, useCallback, useEffect } from "react";
import { apiUrl } from "@/lib/api";

export interface Pricing {
  pricePerGb: number;
  currency: string;
}

export const DEFAULT_PRICING: Pricing = {
  pricePerGb: 0.3,
  currency: "EGP",
};

const SETTING_KEY = "pricing";
const LS_KEY = "gamearly:pricing";

// ── Local storage helpers (synchronous, no race conditions) ──────────────────

function loadFromStorage(): Pricing {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (!raw) return DEFAULT_PRICING;
    const parsed = JSON.parse(raw);
    return { ...DEFAULT_PRICING, ...parsed };
  } catch {
    return DEFAULT_PRICING;
  }
}

function saveToStorage(pricing: Pricing) {
  try {
    localStorage.setItem(LS_KEY, JSON.stringify(pricing));
  } catch {}
}

// ── Server sync (best-effort, non-blocking) ──────────────────────────────────

async function fetchFromServer(): Promise<Pricing | null> {
  try {
    const res = await fetch(apiUrl("/api/site-settings"));
    if (!res.ok) return null;
    const data = await res.json();
    const val = data?.data?.[SETTING_KEY];
    if (!val) return null;
    return { ...DEFAULT_PRICING, ...val };
  } catch {
    return null;
  }
}

async function saveToServer(pricing: Pricing): Promise<void> {
  try {
    const token = sessionStorage.getItem("gh_admin_token") || "";
    await fetch(apiUrl("/api/site-settings"), {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ [SETTING_KEY]: pricing }),
    });
  } catch {}
}

// ── Hook ─────────────────────────────────────────────────────────────────────

export function usePricing() {
  // Initialize synchronously from localStorage — no async, no flash, no race.
  const [pricing, setPricingState] = useState<Pricing>(loadFromStorage);

  // On first mount, pull the latest from the server and sync localStorage.
  // This keeps multiple devices in sync without breaking the in-session value.
  useEffect(() => {
    fetchFromServer().then((server) => {
      if (!server) return;
      // Only apply the server value if it differs, to avoid clobbering
      // a just-saved admin change on slow connections.
      const local = loadFromStorage();
      if (
        server.pricePerGb !== local.pricePerGb ||
        server.currency !== local.currency
      ) {
        saveToStorage(server);
        setPricingState(server);
      }
    });
  }, []);

  const updatePricing = useCallback((updates: Partial<Pricing>) => {
    setPricingState((prev) => {
      const next = { ...prev, ...updates };
      saveToStorage(next);   // instant, synchronous
      saveToServer(next);    // background, best-effort
      return next;
    });
  }, []);

  const resetPricing = useCallback(() => {
    saveToStorage(DEFAULT_PRICING);
    saveToServer(DEFAULT_PRICING);
    setPricingState(DEFAULT_PRICING);
  }, []);

  return { pricing, updatePricing, resetPricing };
}
