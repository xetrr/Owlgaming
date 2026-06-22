# Deploying GAMEARLY (Owlgaming) on Vercel

This monorepo ships two artifacts:

- `artifacts/owlgaming` — the React + Vite storefront (the only thing visitors see).
- `artifacts/api-server` — the Express API used by the admin panel and a few server-only helpers.

In addition, the repo contains an `api/` folder at the **root** with Vercel serverless functions for the public RAWG / IGDB game-info proxies. These are what the storefront's game-info popup calls.

There are two ways to deploy:

1. **Single Vercel project (recommended for most users).** The storefront is served as a static site and the public RAWG / IGDB proxies in `api/` are deployed as serverless functions of that same project. The admin panel features that need the Express server (`/admin/verify`, persistent site settings) won't work unless you also deploy `artifacts/api-server` separately and point the storefront at it via `VITE_API_URL`.
2. **Two Vercel projects (storefront + api-server).** Use this if you want the full admin panel and persistent server-side site settings.

---

## 1. Prerequisites

- A Vercel account.
- The repository pushed to GitHub / GitLab / Bitbucket.
- `pnpm` selected as the install command in Vercel (Settings → General → Install Command: `pnpm install`).

## 2. Single-project deployment (storefront + serverless `api/`)

1. New Project → Import the repo.
2. **Root directory**: leave as `/` (the repo root). Vercel needs to see both `vercel.json` and the `api/` folder.
3. **Framework preset**: Other.
4. **Build command**: `pnpm run build` (already set in `vercel.json`).
5. **Output directory**: `artifacts/owlgaming/dist/public` (already set in `vercel.json`).
6. **Environment variables (Production *and* Preview)**:

   | Name | Required for | Notes |
   |------|--------------|-------|
   | `RAWG_API_KEY` | game-info popup | Server-only. Get one free at https://rawg.io/apidocs. |
   | `IGDB_CLIENT_ID` | game-info popup | Server-only. Twitch developer console. |
   | `IGDB_CLIENT_SECRET` | game-info popup | Server-only. Twitch developer console. |
   | `VITE_SUPABASE_URL` | optional auth/realtime | Public, fine to expose. |
   | `VITE_SUPABASE_ANON_KEY` | optional auth/realtime | Public, fine to expose. |

   > **Do NOT** add `VITE_ADMIN_PASSWORD` or `VITE_RAWG_API_KEY`. Anything starting with `VITE_` is bundled into the public JavaScript and visible to every visitor.
   >
   > Leave `VITE_API_URL` **unset** in this setup so the storefront calls the same-origin `/api/*` serverless functions.

7. Deploy. Open the site, click any game, and the popup should now show description, screenshots, etc.

### Verifying the popup works

Open the browser DevTools network tab while the popup loads. You should see:

- `/api/rawg/search?name=...` returning `{"data": { ... }}` with status 200.
- `/api/igdb/search?name=...` returning `{"data": { ... }}` with status 200.

If you see `{"data": null, "reason": "RAWG_API_KEY environment variable is not set on the server"}` (or the IGDB equivalent), the env vars haven't been set in the Vercel project. Set them in **Settings → Environment Variables** and redeploy.

The serverless functions also send an `X-API-Status` response header that explains exactly which key is missing.

## 3. Two-project deployment (adds full admin panel)

Follow step 2 above for the storefront, then add a second Vercel project for the Express API server.

### Project B — the API server

1. New Project → Import the same repo.
2. **Root directory**: `artifacts/api-server`.
3. **Framework preset**: Other.
4. **Build command**: `pnpm install --filter=@workspace/api-server... && pnpm --filter @workspace/api-server build`.
5. **Output directory**: leave default — the API runs on Vercel's Node runtime.
6. **Environment variables** (server-only, not visible to the browser):

   | Name | Value |
   |------|-------|
   | `ADMIN_PASSWORD` | your admin password |
   | `ADMIN_TOKEN_SECRET` | a long random string (32+ chars) |
   | `RAWG_API_KEY` | your RAWG key |
   | `IGDB_CLIENT_ID` / `IGDB_CLIENT_SECRET` | optional, only if you use IGDB |
   | `ALLOWED_ORIGINS` | the storefront URL, e.g. `https://owlgaming.vercel.app` |
   | `NODE_ENV` | `production` |

7. After it deploys, copy its public URL (e.g. `https://owlgaming-api.vercel.app`).
8. Go back to the **storefront** project → Settings → Environment Variables, and add:

   | Name | Value |
   |------|-------|
   | `VITE_API_URL` | the api project URL, e.g. `https://owlgaming-api.vercel.app` |

   Redeploy the storefront so the new env var is baked into the bundle.

## 4. After both projects are live

1. Visit the storefront. The game-info popup should populate with descriptions, screenshots and trailers.
2. Open `/admin`, log in with your `ADMIN_PASSWORD`. Change the brand name, hero copy, logo, accent colour — every change is broadcast to all open browsers in real time via Supabase.
3. Check the network tab on the storefront — confirm there are **no `VITE_ADMIN_PASSWORD`** strings in any of the `.js` files served (View Source → Ctrl+F).

## 5. Custom domain

1. In the storefront project → Settings → Domains → add your domain.
2. If you used the two-project setup, update `ALLOWED_ORIGINS` on the API project to the new domain.
3. Optional: also point the API project at `api.yourdomain.com` and update `VITE_API_URL` on the storefront accordingly.

## 6. Rolling back

Vercel keeps every deployment. From the storefront project's "Deployments" tab, click "…" on a previous build → "Promote to Production".

## 7. Health check

If you deployed the api-server, it exposes `GET /api/health` and `GET /health`. Add either one to Vercel's "Health Checks" if you want automatic redeploy-on-failure.

---

## Troubleshooting the game-info popup

If the popup opens but never shows description / screenshots / trailer:

1. Open DevTools → Network. Click a game.
2. Look at the responses for `/api/rawg/search` and `/api/igdb/search`.
3. If the JSON body contains `"reason": "RAWG_API_KEY environment variable is not set..."` or similar, add the matching env var to your Vercel project and redeploy.
4. Open DevTools → Console — the storefront also prints a `[rawg]` / `[igdb]` warning describing the failure reason.
5. If `/api/rawg/search` returns 404, the serverless functions weren't picked up by Vercel — confirm the project's **Root Directory** is `/` (the repo root), not `artifacts/owlgaming`.
