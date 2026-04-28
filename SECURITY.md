# Security Notes — Owlgaming / GAMEARLY

This document summarises the security posture of the project and the manual hardening steps that should be completed before the site is exposed to the public internet.

## 1. Findings from the internal review

| # | Severity | Area | Finding | Status |
|---|----------|------|---------|--------|
| 1 | **High** | Secrets | `VITE_ADMIN_PASSWORD` and `VITE_RAWG_API_KEY` were defined as Vite environment variables. Anything prefixed with `VITE_` is bundled into the client JavaScript and visible to every visitor. | Move to non-prefixed `ADMIN_PASSWORD` and `RAWG_API_KEY` (server-only). Delete the `VITE_` versions in your secret manager. |
| 2 | Medium | Headers | `Strict-Transport-Security` was missing. | Now sent automatically when `NODE_ENV=production` (`max-age=31536000; includeSubDomains; preload`). |
| 3 | Medium | Headers | `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy` were missing. | Added (`same-origin` / `same-site`). |
| 4 | Medium | CSP | `base-uri` and `object-src` were not pinned. | Added (`'none'` for both). |
| 5 | Low | Static title | `index.html` shipped with a fixed `<title>`, leaking the legacy brand name to scrapers. | Replaced; runtime brand title applied via the new `BrandHead` component. |

## 2. Already in place

- Admin login uses a **timing-safe** comparison (`crypto.timingSafeEqual`).
- Admin sessions are signed HMAC tokens (no plaintext credentials, 8-hour TTL).
- In-memory IP throttle on admin login (5 attempts / 15 minutes).
- Two `express-rate-limit` policies: 60 req/min on public API, 20 req/15 min on `/api/admin`.
- Strict CORS allow-list (`ALLOWED_ORIGINS` env var) plus same-host fallback.
- `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy` locked to no camera/mic/geolocation.
- `x-powered-by` removed.
- Body size limited to 256 KB (`express.json` and `express.urlencoded`).
- All write logs go through pino with redacted request URLs.

## 3. Required manual steps

1. **Set the admin password as a server secret** (not a `VITE_` variable):
   - Key: `ADMIN_PASSWORD`
   - Value: `Mm01068283805`
2. **Move RAWG to the server**:
   - Key: `RAWG_API_KEY`
3. **Delete the old client-exposed secrets** in your secret manager:
   - `VITE_ADMIN_PASSWORD`
   - `VITE_RAWG_API_KEY`
4. **Set `ALLOWED_ORIGINS`** in production to the exact hostname(s) you serve from (comma separated).
5. **Set `NODE_ENV=production`** in production so HSTS is sent.

## 4. Recommended follow-ups

- Rotate `ADMIN_PASSWORD` periodically.
- Consider moving the admin login behind a separate hostname or VPN allow-list.
- Enable Supabase Row-Level Security on the `site_settings`, `games`, `hard_drives`, and `accessories` tables (anon = read-only; writes via service role only on the server).
- Enable bot/abuse protection at the edge (Cloudflare / Vercel Firewall / WAF).

## 5. Penetration-test summary

- **Information disclosure** — none observed in API responses; CSP and Permissions-Policy reviewed.
- **Injection** — payloads stored via Supabase use parameterised queries; no raw SQL builds with user input.
- **Auth** — admin path resists timing attacks and brute force (rate-limited + IP throttle + signed token TTL).
- **Clickjacking** — blocked by `X-Frame-Options: DENY` and CSP `frame-src 'none'`.
- **TLS / HSTS** — relies on the host (Vercel/Replit) for TLS termination; HSTS now sent in production.
- **Open redirects** — none.
- **Mass assignment / IDOR** — admin-only writes; public reads are immutable.

After applying the manual steps above, the project meets the baseline for a public production launch.
