---
name: Supabase-to-Replit migration
description: Key decisions and quirks from migrating GAMEARLY from Supabase to Replit PostgreSQL + session auth.
---

# Supabase → Replit PostgreSQL + Session Auth Migration

## What was replaced
- Supabase Auth → express-session + bcryptjs (session stored server-side)
- Supabase DB (games, hard_drives, accessories, favorites, site_settings) → Replit PostgreSQL via `pg` Pool
- Supabase realtime subscriptions → polling / API calls in hooks

## Key files changed
- `artifacts/api-server/src/routes/data.ts` — new CRUD routes for auth, games, hard_drives, accessories, favorites
- `artifacts/api-server/src/app.ts` — added cookie-parser, express-session, `trust proxy 1`
- `artifacts/owlgaming/src/lib/supabase.ts` — rewrapped to call `/api/*` instead of Supabase SDK; `supabase` export is now null, `isSupabaseConfigured` is always true
- `artifacts/owlgaming/src/contexts/AuthContext.tsx` — uses GET /api/auth/me instead of Supabase session
- `artifacts/owlgaming/src/hooks/useBrand.ts` — uses GET/POST /api/site-settings
- `artifacts/owlgaming/src/hooks/useHomeContent.ts` — same
- `artifacts/owlgaming/src/hooks/usePricing.ts` — same
- `artifacts/owlgaming/src/hooks/useContactInfo.ts` — same

## Critical quirks

**`pg` must be externalised AND installed as a direct dep in api-server.**
- It must be in `external: [...]` in `artifacts/api-server/build.mjs` (esbuild won't bundle it)
- It must also be in `artifacts/api-server/package.json` (pnpm hoisting means it may not be found at runtime otherwise)

**`trust proxy 1` is required on the Express app.**
- Replit runs behind a proxy that sets X-Forwarded-For; without this express-rate-limit throws ERR_ERL_UNEXPECTED_X_FORWARDED_FOR

**Why:**
Both issues caused runtime crashes during the migration. The pg bundling error is silent at build time but crashes at start; the rate-limit error is a ValidationError that surfaces only when the first request arrives.
