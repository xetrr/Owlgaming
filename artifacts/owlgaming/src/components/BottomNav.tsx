import { Link, useLocation } from "react-router-dom";
import { Home, Gamepad2, Heart, Package, ShoppingCart } from "lucide-react";
import { cn } from "@/lib/utils";
import { useAuth } from "@/contexts/AuthContext";
import { useLang } from "@/contexts/LanguageContext";

export default function BottomNav() {
  const location = useLocation();
  const { favorites } = useAuth();
  const { t } = useLang();

  const navItems = [
    { href: "/", icon: Home, label: t("nav_home") },
    { href: "/games", icon: Gamepad2, label: t("nav_games") },
    { href: "/favorites", icon: Heart, label: t("nav_favorites"), badge: favorites.size },
    { href: "/accessories", icon: Package, label: t("nav_accessories") },
    { href: "/cart", icon: ShoppingCart, label: "Cart" },
  ];

  return (
    <nav className="lg:hidden fixed bottom-0 left-0 right-0 z-50 bg-background/95 backdrop-blur-xl border-t border-border/50 h-16">
      <div className="flex items-center justify-around h-full">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = location.pathname === item.href;

          return (
            <Link
              key={item.href}
              to={item.href}
              className={cn(
                "flex flex-col items-center justify-center w-full h-full gap-1 transition-colors relative",
                isActive ? "text-primary" : "text-foreground/50 hover:text-foreground/70"
              )}
            >
              <div className="relative">
                <Icon className={cn("w-5 h-5 transition-all", isActive && item.href === "/favorites" ? "fill-primary" : "")} />
                {item.badge && item.badge > 0 ? (
                  <span className="absolute -top-1.5 -right-1.5 w-4 h-4 bg-primary text-white text-[9px] font-black rounded-full flex items-center justify-center leading-none">
                    {item.badge > 9 ? "9+" : item.badge}
                  </span>
                ) : null}
              </div>
              <span className="text-[10px] font-medium">{item.label}</span>
              {isActive && <span className="absolute top-0 left-1/2 -translate-x-1/2 w-4 h-0.5 bg-primary rounded-full" />}
            </Link>
          );
        })}
      </div>
    </nav>
  );
}
