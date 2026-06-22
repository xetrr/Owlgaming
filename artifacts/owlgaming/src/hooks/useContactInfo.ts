import { useState, useCallback, useEffect } from "react";
import { apiUrl } from "@/lib/api";

export interface BusinessHour {
  days: string;
  hours: string;
}

export interface ContactInfo {
  brandName: string;
  phone: string;
  whatsapp: string;
  facebook: string;
  location: string;
  email: string;
  mapUrl: string;
  hours: BusinessHour[];
}

export const DEFAULT_CONTACT: ContactInfo = {
  brandName: "GAMEARLY",
  phone: "01559665337",
  whatsapp: "201559665337",
  facebook: "https://facebook.com/gamearly",
  location: "Cairo, Egypt",
  email: "gamearly@gmail.com",
  mapUrl: "https://maps.app.goo.gl/9WUL7GCnYtNTj23U7",
  hours: [
    { days: "Saturday – Thursday", hours: "10:00 AM – 10:00 PM" },
    { days: "Friday", hours: "2:00 PM – 10:00 PM" },
  ],
};

const SETTING_KEY = "contact_info";

async function fetchContactInfo(): Promise<ContactInfo | null> {
  try {
    const res = await fetch(apiUrl("/api/site-settings"));
    if (!res.ok) return null;
    const data = await res.json();
    const val = data?.data?.[SETTING_KEY];
    if (!val) return null;
    return {
      ...DEFAULT_CONTACT,
      ...val,
      hours: val.hours ?? DEFAULT_CONTACT.hours,
    };
  } catch {
    return null;
  }
}

async function persistContactInfo(info: ContactInfo): Promise<void> {
  try {
    const token = sessionStorage.getItem("gh_admin_token") || "";
    await fetch(apiUrl("/api/site-settings"), {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ [SETTING_KEY]: info }),
    });
  } catch {}
}

export function useContactInfo() {
  const [info, setInfo] = useState<ContactInfo>(DEFAULT_CONTACT);

  useEffect(() => {
    fetchContactInfo().then((saved) => {
      if (saved) setInfo(saved);
    });
  }, []);

  const updateInfo = useCallback((updates: Partial<ContactInfo>) => {
    setInfo((prev) => {
      const next = { ...prev, ...updates };
      persistContactInfo(next);
      return next;
    });
  }, []);

  const resetInfo = useCallback(() => {
    persistContactInfo(DEFAULT_CONTACT);
    setInfo(DEFAULT_CONTACT);
  }, []);

  return { info, updateInfo, resetInfo };
}
