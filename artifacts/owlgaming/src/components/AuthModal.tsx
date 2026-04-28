import { useState } from "react";
import { X, Eye, EyeOff, LogIn, UserPlus, Gamepad2, AlertCircle, CheckCircle } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";
import { isSupabaseConfigured } from "@/lib/supabase";
import { useLang } from "@/contexts/LanguageContext";
import { useBrand } from "@/hooks/useBrand";

export default function AuthModal() {
  const { showAuthModal, closeAuthModal, authModalTab, login, register, openAuthModal } = useAuth();
  const { t } = useLang();
  const { brand } = useBrand();
  const [tab, setTab] = useState<"login" | "signup">(authModalTab);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [username, setUsername] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  if (!showAuthModal) return null;

  const reset = () => { setEmail(""); setPassword(""); setUsername(""); setError(null); setSuccess(null); };

  const switchTab = (t: "login" | "signup") => { setTab(t); reset(); };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim() || !password.trim()) { setError(t("auth_emailPassRequired")); return; }
    if (tab === "signup" && !username.trim()) { setError(t("auth_usernameRequired")); return; }
    if (password.length < 6) { setError(t("auth_passwordShort")); return; }

    setLoading(true);
    setError(null);
    try {
      if (tab === "login") {
        await login(email.trim(), password);
      } else {
        await register(email.trim(), password, username.trim());
        setSuccess(t("auth_accountCreated"));
        switchTab("login");
        return;
      }
    } catch (err: any) {
      const msg = err?.message || "Something went wrong";
      if (msg.includes("Invalid login")) setError(t("auth_wrongCreds"));
      else if (msg.includes("already registered")) setError(t("auth_emailInUse"));
      else if (msg.includes("confirmation")) setError(t("auth_confirmEmail"));
      else setError(msg);
    } finally {
      setLoading(false);
    }
  };

  const inp = "w-full px-4 py-3 bg-muted border border-border rounded-xl text-sm text-foreground placeholder:text-foreground/30 focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all";

  return (
    <div className="fixed inset-0 z-[400] flex items-center justify-center p-4" onClick={closeAuthModal}>
      <div className="absolute inset-0 bg-black/80 backdrop-blur-sm" />
      <div
        className="relative z-10 w-full max-w-md bg-card border border-border rounded-2xl shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="relative px-6 pt-6 pb-4 border-b border-border">
          <div className="flex items-center gap-3 mb-1">
            <div className="w-9 h-9 rounded-xl bg-primary/20 flex items-center justify-center">
              <Gamepad2 className="w-5 h-5 text-primary" />
            </div>
            <div>
              <h2 className="font-black text-lg text-foreground">
                {tab === "login" ? t("auth_welcomeBack") : t("auth_joinUs", { brand: brand.name })}
              </h2>
              <p className="text-xs text-foreground/50">
                {tab === "login" ? t("auth_loginSubtitle") : t("auth_signupSubtitle")}
              </p>
            </div>
          </div>
          <button onClick={closeAuthModal} className="absolute top-5 right-5 w-8 h-8 rounded-full bg-muted flex items-center justify-center hover:bg-muted/80 transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="flex border-b border-border">
          {(["login", "signup"] as const).map((tabOption) => (
            <button
              key={tabOption}
              onClick={() => switchTab(tabOption)}
              className={`flex-1 py-3 text-sm font-bold transition-colors ${tab === tabOption ? "text-primary border-b-2 border-primary" : "text-foreground/50 hover:text-foreground"}`}
            >
              {tabOption === "login" ? t("auth_signIn") : t("auth_signUp")}
            </button>
          ))}
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {!isSupabaseConfigured && (
            <div className="flex items-center gap-2 px-4 py-3 bg-yellow-500/10 border border-yellow-500/30 rounded-xl text-yellow-400 text-sm">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              {t("auth_dbNotConnected")}
            </div>
          )}

          {error && (
            <div className="flex items-center gap-2 px-4 py-3 bg-destructive/10 border border-destructive/30 rounded-xl text-destructive text-sm">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />{error}
            </div>
          )}

          {success && (
            <div className="flex items-center gap-2 px-4 py-3 bg-green-500/10 border border-green-500/30 rounded-xl text-green-400 text-sm">
              <CheckCircle className="w-4 h-4 flex-shrink-0" />{success}
            </div>
          )}

          {tab === "signup" && (
            <div>
              <label className="text-xs font-bold text-foreground/50 uppercase tracking-wider mb-1.5 block">{t("auth_username")}</label>
              <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="GamerTag123" className={inp} autoFocus />
            </div>
          )}

          <div>
            <label className="text-xs font-bold text-foreground/50 uppercase tracking-wider mb-1.5 block">{t("auth_email")}</label>
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" className={inp} autoFocus={tab === "login"} />
          </div>

          <div>
            <label className="text-xs font-bold text-foreground/50 uppercase tracking-wider mb-1.5 block">{t("auth_password")}</label>
            <div className="relative">
              <input
                type={showPw ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className={inp + " pr-11"}
                onKeyDown={(e) => e.key === "Enter" && handleSubmit(e as any)}
              />
              <button type="button" onClick={() => setShowPw(!showPw)} className="absolute right-3 top-1/2 -translate-y-1/2 text-foreground/40 hover:text-foreground/70">
                {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            {tab === "signup" && <p className="text-[11px] text-foreground/40 mt-1">{t("auth_minChars")}</p>}
          </div>

          <button
            type="submit"
            disabled={loading || !isSupabaseConfigured}
            className="w-full py-3 bg-primary hover:bg-primary/90 disabled:opacity-50 text-white font-bold rounded-xl transition-all flex items-center justify-center gap-2"
          >
            {loading ? (
              <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            ) : tab === "login" ? (
              <><LogIn className="w-4 h-4" />{t("auth_signIn")}</>
            ) : (
              <><UserPlus className="w-4 h-4" />{t("auth_createAccount")}</>
            )}
          </button>

          <p className="text-center text-xs text-foreground/40">
            {tab === "login" ? t("auth_noAccount") : t("auth_haveAccount")}
            <button type="button" onClick={() => switchTab(tab === "login" ? "signup" : "login")} className="text-primary hover:underline font-medium">
              {tab === "login" ? t("auth_signUpFree") : t("auth_signIn")}
            </button>
          </p>
        </form>
      </div>
    </div>
  );
}
