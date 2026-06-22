# Workspace

## Overview

pnpm workspace monorepo using TypeScript. Each package manages its own dependencies.

## Application: Owlgaming (GAMEARLY)

A gaming storefront web app with dark purple/blue gaming aesthetic. Supports Arabic + English, game catalog browsing, hard drive ordering, accessories, cart, favorites, and an admin panel.

## Stack

- **Monorepo tool**: pnpm workspaces
- **Node.js version**: 24
- **Package manager**: pnpm
- **TypeScript version**: 5.9
- **Frontend**: React 18 + Vite + Tailwind CSS v4 (artifact: `artifacts/owlgaming`)
- **Backend**: Express 5 (artifact: `artifacts/api-server`)
- **Database**: PostgreSQL + Drizzle ORM (for future use; current data via Supabase)
- **Auth**: Supabase (optional — configured via `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY` env vars)
- **Validation**: Zod (`zod/v4`), `drizzle-zod`
- **API codegen**: Orval (from OpenAPI spec)
- **Build**: esbuild (CJS bundle)
- **Routing**: React Router DOM v6

## Key Artifacts

- `artifacts/owlgaming/` — Frontend web app (React + Vite, port assigned by workflow)
- `artifacts/api-server/` — Express API server (IGDB, RAWG, SteamGridDB proxies, admin auth, site settings)

## API Routes (in api-server)

- `GET /api/rawg/*` — RAWG game database proxy (requires `RAWG_API_KEY` secret)
- `GET /api/igdb/*` — IGDB game database proxy (requires `IGDB_CLIENT_ID` + `IGDB_CLIENT_SECRET` secrets)
- `GET /api/games/*` — SteamGridDB proxy
- `GET/POST /api/site-settings` — Persistent site settings (stored in `.data/site-settings.json`)
- `POST /api/admin/verify` — Admin auth (requires `ADMIN_PASSWORD` secret)

## Environment Variables / Secrets

- `VITE_SUPABASE_URL` — Supabase project URL (optional; app works without it)
- `VITE_SUPABASE_ANON_KEY` — Supabase anon key (optional)
- `RAWG_API_KEY` — RAWG game database API key (optional; needed for RAWG features)
- `IGDB_CLIENT_ID` — Twitch/IGDB client ID (optional)
- `IGDB_CLIENT_SECRET` — Twitch/IGDB client secret (optional)
- `ADMIN_PASSWORD` — Admin panel password (optional)

## Key Commands

- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)

See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details.
