import { useState } from "react";
import { User, LogOut, LogIn, Heart, Lock, Eye, EyeOff, CheckCircle, AlertCircle, Loader2, Shield } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";
import { supabase, isSupabaseConfigured } from "@/lib/supabase";

function Avatar({ email, username }: { email: string; username?: string }) {
  const initials = username
    ? username.slice(0, 2).toUpperCase()
    : email.slice(0, 2).toUpperCase();
  return (
    <div className="w-20 h-20 rounded-2xl bg-primary/20 flex items-center justify-center text-primary text-2xl font-black select-none">
      {initials}
    </div>
  );
}

function ChangePasswordForm() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [showCurrent, setShowCurrent] = useState(false);
  const [showNext, setShowNext] = useState(false);
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSuccess("");
    setError("");

    if (next.length < 6) {
      setError("New password must be at least 6 characters.");
      return;
    }
    if (next !== confirm) {
      setError("Passwords do not match.");
      return;
    }
    if (!supabase) {
      setError("Supabase is not configured.");
      return;
    }

    setLoading(true);
    try {
      const { error: err } = await supabase.auth.updateUser({ password: next });
      if (err) throw err;
      setSuccess("Password updated successfully!");
      setCurrent("");
      setNext("");
      setConfirm("");
    } catch (e: any) {
      setError(e.message || "Failed to update password.");
    } finally {
      setLoading(false);
    }
  };

  const inp =
    "w-full pl-4 pr-10 py-2.5 bg-muted border border-border rounded-xl text-sm text-foreground placeholder:text-foreground/30 focus:outline-none focus:ring-2 focus:ring-primary/40 transition-all";

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {/* Current password (UI only — Supabase update doesn't require it, but good UX) */}
      <div className="space-y-1.5">
        <label className="text-xs font-semibold text-foreground/60 uppercase tracking-wider">
          Current Password
        </label>
        <div className="relative">
          <input
            type={showCurrent ? "text" : "password"}
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            placeholder="Enter current password"
            className={inp}
          />
          <button
            type="button"
            onClick={() => setShowCurrent(!showCurrent)}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-foreground/40 hover:text-foreground transition-colors"
          >
            {showCurrent ? <Eye className="w-4 h-4" /> : <EyeOff className="w-4 h-4" />}
          </button>
        </div>
      </div>

      <div className="space-y-1.5">
        <label className="text-xs font-semibold text-foreground/60 uppercase tracking-wider">
          New Password
        </label>
        <div className="relative">
          <input
            type={showNext ? "text" : "password"}
            value={next}
            onChange={(e) => setNext(e.target.value)}
            placeholder="At least 6 characters"
            className={inp}
          />
          <button
            type="button"
            onClick={() => setShowNext(!showNext)}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-foreground/40 hover:text-foreground transition-colors"
          >
            {showNext ? <Eye className="w-4 h-4" /> : <EyeOff className="w-4 h-4" />}
          </button>
        </div>
      </div>

      <div className="space-y-1.5">
        <label className="text-xs font-semibold text-foreground/60 uppercase tracking-wider">
          Confirm New Password
        </label>
        <input
          type="password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          placeholder="Repeat new password"
          className={inp}
        />
      </div>

      {error && (
        <div className="flex items-center gap-2 px-3 py-2.5 bg-destructive/10 border border-destructive/30 rounded-xl text-destructive text-xs">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          {error}
        </div>
      )}
      {success && (
        <div className="flex items-center gap-2 px-3 py-2.5 bg-green-500/10 border border-green-500/30 rounded-xl text-green-400 text-xs">
          <CheckCircle className="w-4 h-4 flex-shrink-0" />
          {success}
        </div>
      )}

      <button
        type="submit"
        disabled={loading || !current || !next || !confirm}
        className="flex items-center justify-center gap-2 w-full py-2.5 bg-primary hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed text-primary-foreground font-bold rounded-xl text-sm transition-all"
      >
        {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Lock className="w-4 h-4" />}
        {loading ? "Updating…" : "Update Password"}
      </button>
    </form>
  );
}

export default function Profile() {
  const { user, loading, openAuthModal, logout, favorites } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  if (!user) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background px-4">
        <div className="h-16" />
        <div className="text-center space-y-5 max-w-sm">
          <div className="w-20 h-20 rounded-2xl bg-primary/15 flex items-center justify-center mx-auto">
            <User className="w-10 h-10 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-black text-foreground mb-2">My Profile</h1>
            <p className="text-foreground/60 text-sm">
              Sign in to manage your account, view your favorites, and update your password.
            </p>
          </div>
          <button
            onClick={() => openAuthModal("login")}
            className="inline-flex items-center gap-2 px-6 py-3 bg-primary hover:bg-primary/90 text-white font-bold rounded-xl transition-all"
          >
            <LogIn className="w-4 h-4" />
            Sign In to Your Account
          </button>
          <button
            onClick={() => openAuthModal("signup")}
            className="inline-flex items-center gap-2 px-6 py-2.5 bg-muted border border-border hover:border-primary/40 text-foreground/70 hover:text-foreground font-semibold rounded-xl text-sm transition-all w-full justify-center"
          >
            Create an Account
          </button>
        </div>
      </div>
    );
  }

  const username = (user.user_metadata?.username as string) || "";
  const memberSince = new Date(user.created_at).toLocaleDateString("en-GB", {
    day: "numeric",
    month: "long",
    year: "numeric",
  });

  return (
    <div className="min-h-screen bg-background">
      <div className="h-16" />
      <div className="container mx-auto px-4 py-10 max-w-2xl space-y-6">

        {/* Profile card */}
        <div className="bg-card border border-border rounded-2xl p-6 flex items-center gap-5">
          <Avatar email={user.email ?? ""} username={username} />
          <div className="flex-1 min-w-0">
            <h1 className="text-xl font-black text-foreground truncate">
              {username || user.email?.split("@")[0]}
            </h1>
            <p className="text-sm text-foreground/50 truncate">{user.email}</p>
            <p className="text-xs text-foreground/40 mt-1">Member since {memberSince}</p>
          </div>
          <button
            onClick={logout}
            className="flex items-center gap-2 px-4 py-2 bg-muted border border-border hover:border-destructive/40 hover:text-destructive text-foreground/60 font-semibold rounded-xl text-sm transition-all flex-shrink-0"
          >
            <LogOut className="w-4 h-4" />
            Sign Out
          </button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 gap-4">
          <div className="bg-card border border-border rounded-2xl p-5 flex items-center gap-4">
            <div className="w-11 h-11 rounded-xl bg-primary/15 flex items-center justify-center flex-shrink-0">
              <Heart className="w-5 h-5 text-primary fill-primary" />
            </div>
            <div>
              <p className="text-2xl font-black text-foreground">{favorites.size}</p>
              <p className="text-xs text-foreground/50">Saved Games</p>
            </div>
          </div>
          <div className="bg-card border border-border rounded-2xl p-5 flex items-center gap-4">
            <div className="w-11 h-11 rounded-xl bg-secondary/15 flex items-center justify-center flex-shrink-0">
              <Shield className="w-5 h-5 text-secondary" />
            </div>
            <div>
              <p className="text-2xl font-black text-foreground">Active</p>
              <p className="text-xs text-foreground/50">Account Status</p>
            </div>
          </div>
        </div>

        {/* Change password */}
        {isSupabaseConfigured && (
          <div className="bg-card border border-border rounded-2xl p-6 space-y-5">
            <div className="flex items-center gap-2">
              <Lock className="w-5 h-5 text-foreground/50" />
              <h2 className="font-bold text-foreground">Change Password</h2>
            </div>
            <ChangePasswordForm />
          </div>
        )}

        {/* Account info */}
        <div className="bg-card border border-border rounded-2xl p-6 space-y-4">
          <h2 className="font-bold text-foreground flex items-center gap-2">
            <User className="w-5 h-5 text-foreground/50" />
            Account Details
          </h2>
          <div className="space-y-3">
            <div className="flex justify-between items-center py-2 border-b border-border/50">
              <span className="text-sm text-foreground/50">Email</span>
              <span className="text-sm font-medium text-foreground">{user.email}</span>
            </div>
            {username && (
              <div className="flex justify-between items-center py-2 border-b border-border/50">
                <span className="text-sm text-foreground/50">Username</span>
                <span className="text-sm font-medium text-foreground">{username}</span>
              </div>
            )}
            <div className="flex justify-between items-center py-2">
              <span className="text-sm text-foreground/50">Member Since</span>
              <span className="text-sm font-medium text-foreground">{memberSince}</span>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
