import { Link, useNavigate, useLocation } from "react-router-dom";
import { Menu, ShoppingCart, Heart, User, LogOut, X, Gamepad2, Globe } from "lucide-react";
import { useState } from "react";
import { cn } from "@/lib/utils";
import { useCart } from "@/contexts/CartContext";
import { useAuth } from "@/contexts/AuthContext";
import { useLang } from "@/contexts/LanguageContext";
import { useBrand } from "@/hooks/useBrand";

export default function Header() {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const { getTotalItems } = useCart();
  const { user, logout, openAuthModal, favorites } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const { t, lang, setLang } = useLang();
  const { brand } = useBrand();

  const navLinks = [
    { href: "/", label: t("nav_home") },
    { href: "/games", label: t("nav_games") },
    { href: "/harddisks", label: t("nav_harddrives") },
    { href: "/accessories", label: t("nav_accessories") },
    { href: "/contact", label: t("nav_contact") },
  ];

  const isActive = (href: string) =>
    href === "/" ? location.pathname === "/" : location.pathname.startsWith(href);

  const handleLogout = async () => {
    await logout();
    setShowUserMenu(false);
    navigate("/");
  };

  const username = user?.user_metadata?.username || user?.email?.split("@")[0] || "Gamer";

  return (
    <header
      className="fixed top-0 left-0 right-0 z-50 bg-background/60 backdrop-blur-xl border-b border-white/5 transition-all duration-300"
      dir="ltr"
    >
      <div className="container mx-auto px-4 h-16 flex items-center justify-between">

        {/* Brand — name only, always on the left */}
        <Link to="/" className="group flex items-center">
          <span className="text-xl font-black tracking-widest logo-gradient-text group-hover:opacity-90 transition-opacity font-heading uppercase">
            {brand.name}
          </span>
        </Link>

        {/* Desktop Navigation — always LTR, center */}
        <nav className="hidden lg:flex items-center gap-6">
          {navLinks.map((link) => {
            const active = isActive(link.href);
            return (
              <Link
                key={link.href}
                to={link.href}
                className={cn(
                  "text-sm font-medium transition-colors relative py-1",
                  active ? "text-foreground" : "text-foreground/50 hover:text-foreground"
                )}
              >
                {link.label}
                {active && <span className="nav-active-indicator" />}
                {!active && (
                  <span className="absolute -bottom-0.5 left-0 w-0 h-0.5 bg-gradient-to-r from-primary to-secondary group-hover:w-full transition-all duration-300 rounded-full" />
                )}
              </Link>
            );
          })}
        </nav>

        {/* Right actions — always on the right */}
        <div className="flex items-center gap-1.5">
          {/* Language Toggle */}
          <button
            onClick={() => setLang(lang === "en" ? "ar" : "en")}
            className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 bg-white/5 border border-white/8 hover:border-primary/40 rounded-xl text-xs font-bold text-foreground/60 hover:text-foreground transition-all"
            title="Switch Language"
          >
            <Globe className="w-3.5 h-3.5" />
            {lang === "en" ? "العربية" : "English"}
          </button>

          {/* Favorites */}
          <Link
            to="/favorites"
            className="relative p-2 hover:bg-white/5 rounded-xl transition-colors"
            aria-label={t("nav_favorites")}
          >
            <Heart className={cn("w-5 h-5 transition-colors", favorites.size > 0 ? "text-primary fill-primary" : "text-foreground/50")} />
            {favorites.size > 0 && (
              <span className="absolute top-0 right-0 inline-flex items-center justify-center px-1.5 py-0.5 text-[10px] font-bold text-white bg-primary rounded-full translate-x-1 -translate-y-1 leading-none">
                {favorites.size > 99 ? "99+" : favorites.size}
              </span>
            )}
          </Link>

          {/* Cart */}
          <Link
            to="/cart"
            className="relative p-2 hover:bg-white/5 rounded-xl transition-colors"
            aria-label="Cart"
          >
            <ShoppingCart className="w-5 h-5 text-foreground/50" />
            {getTotalItems() > 0 && (
              <span className="absolute top-0 right-0 inline-flex items-center justify-center px-1.5 py-0.5 text-[10px] font-bold leading-none text-white bg-primary rounded-full translate-x-1 -translate-y-1">
                {getTotalItems()}
              </span>
            )}
          </Link>

          {/* Auth */}
          {user ? (
            <div className="relative">
              <button
                onClick={() => setShowUserMenu(!showUserMenu)}
                className="flex items-center gap-2 px-3 py-1.5 bg-white/5 border border-white/8 hover:border-primary/40 rounded-xl transition-colors"
              >
                <div className="w-6 h-6 rounded-full bg-primary/30 flex items-center justify-center">
                  <User className="w-3.5 h-3.5 text-primary" />
                </div>
                <span className="text-sm font-medium text-foreground/80 max-w-[100px] truncate hidden sm:block">{username}</span>
              </button>

              {showUserMenu && (
                <>
                  <div className="fixed inset-0 z-40" onClick={() => setShowUserMenu(false)} />
                  <div className="absolute right-0 top-full mt-2 z-50 w-48 bg-card/90 backdrop-blur-xl border border-white/8 rounded-2xl shadow-2xl overflow-hidden">
                    <div className="px-4 py-3 border-b border-white/6 bg-white/3">
                      <p className="text-xs font-bold text-foreground truncate">{username}</p>
                      <p className="text-[11px] text-foreground/40 truncate">{user.email}</p>
                    </div>
                    <Link to="/favorites" onClick={() => setShowUserMenu(false)} className="flex items-center gap-2.5 px-4 py-2.5 text-sm text-foreground/60 hover:text-foreground hover:bg-white/4 transition-colors">
                      <Heart className="w-4 h-4 text-primary" />
                      {t("nav_myFavorites")}
                      {favorites.size > 0 && <span className="ml-auto text-[11px] font-bold text-primary">{favorites.size}</span>}
                    </Link>
                    <button onClick={handleLogout} className="w-full flex items-center gap-2.5 px-4 py-2.5 text-sm text-destructive hover:bg-destructive/10 transition-colors">
                      <LogOut className="w-4 h-4" />
                      {t("nav_signOut")}
                    </button>
                  </div>
                </>
              )}
            </div>
          ) : (
            <button
              onClick={() => openAuthModal("login")}
              className="hidden sm:flex items-center gap-2 px-4 py-1.5 btn-gradient text-sm font-bold rounded-xl"
            >
              <Gamepad2 className="w-4 h-4" />
              {t("nav_signIn")}
            </button>
          )}

          {/* Hamburger */}
          <button
            onClick={() => setIsMenuOpen(!isMenuOpen)}
            className="lg:hidden p-2 hover:bg-white/5 rounded-xl transition-colors"
            aria-label="Open menu"
          >
            {isMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
      </div>

      {/* Mobile menu — always LTR layout */}
      {isMenuOpen && (
        <div className="lg:hidden border-t border-white/5 bg-background/90 backdrop-blur-xl">
          <nav className="container mx-auto px-4 py-4 flex flex-col gap-1">
            {navLinks.map((link) => {
              const active = isActive(link.href);
              return (
                <Link
                  key={link.href}
                  to={link.href}
                  onClick={() => setIsMenuOpen(false)}
                  className={cn(
                    "text-sm font-medium transition-colors py-2.5 px-3 rounded-xl",
                    active
                      ? "text-foreground bg-primary/10 border border-primary/25"
                      : "text-foreground/55 hover:text-foreground hover:bg-white/4"
                  )}
                >
                  {link.label}
                </Link>
              );
            })}
            <Link to="/favorites" onClick={() => setIsMenuOpen(false)} className="text-sm font-medium text-foreground/55 hover:text-foreground transition-colors py-2.5 px-3 rounded-xl hover:bg-white/4 flex items-center gap-2">
              <Heart className="w-4 h-4 text-primary" />{t("nav_favorites")}
            </Link>
            <button
              onClick={() => setLang(lang === "en" ? "ar" : "en")}
              className="flex items-center gap-2 py-2.5 px-3 rounded-xl hover:bg-white/4 text-sm font-medium text-foreground/55 hover:text-foreground transition-colors text-left"
            >
              <Globe className="w-4 h-4" />
              {lang === "en" ? "العربية" : "English"}
            </button>
            {!user && (
              <button onClick={() => { setIsMenuOpen(false); openAuthModal("login"); }} className="mt-2 w-full py-2.5 btn-gradient font-bold rounded-xl text-sm">
                {t("nav_signIn")}
              </button>
            )}
            {user && (
              <button onClick={() => { setIsMenuOpen(false); handleLogout(); }} className="mt-2 w-full py-2.5 bg-destructive/10 text-destructive font-bold rounded-xl text-sm">
                {t("nav_signOut")}
              </button>
            )}
          </nav>
        </div>
      )}
    </header>
  );
}
