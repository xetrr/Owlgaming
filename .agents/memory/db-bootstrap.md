---
name: DB table bootstrap
description: The Drizzle schema in lib/db is an empty placeholder. All app tables must be created with raw SQL on each fresh database.
---

## Rule
`pnpm --filter @workspace/db run push` will report "no changes detected" because the Drizzle schema exports nothing. Tables must be bootstrapped with raw SQL directly against DATABASE_URL.

**Why:** The app predates any Drizzle schema definition; tables were originally in Supabase and migrated manually.

**How to apply:** On a fresh Replit PostgreSQL database, run this SQL (e.g. via node + pg Pool):

```sql
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS games (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  image_url TEXT NOT NULL,
  size TEXT NOT NULL,
  source TEXT DEFAULT '',
  genre TEXT DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS hard_drives (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  image_url TEXT NOT NULL,
  capacity TEXT NOT NULL,
  type TEXT NOT NULL,
  speed TEXT NOT NULL,
  price TEXT NOT NULL,
  description TEXT DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS accessories (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  image_url TEXT NOT NULL,
  category TEXT NOT NULL,
  price TEXT NOT NULL,
  description TEXT DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS favorites (
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  game_id TEXT REFERENCES games(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (user_id, game_id)
);
```

Also install `@types/pg` as a devDependency in `artifacts/api-server` — it is not included by default.
