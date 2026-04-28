import { useEffect } from "react";
import { useBrand } from "@/hooks/useBrand";

/**
 * Reflect the brand name into the browser tab <title>.
 * Renders nothing.
 */
export default function BrandHead() {
  const { brand } = useBrand();

  useEffect(() => {
    const title = (brand.name || "").trim();
    if (title) document.title = title;
  }, [brand.name]);

  return null;
}
