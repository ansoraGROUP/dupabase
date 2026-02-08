# Migration from Supabase

This guide walks you through moving from managed Supabase to Dupabase on your own server.

## Cost Comparison

The whole reason Dupabase exists. Here's what Supabase actually costs vs self-hosting with Dupabase.

### Supabase Pricing (Pro plan)

- **Base**: $25/project/month
- **Compute**: Micro (1 GB) free, Small (2 GB) $15, Medium (4 GB) $60, Large (8 GB) $110, XL (16 GB) $210
- **$10 compute credit** included per project
- **DB storage**: 8 GB included, then $0.125/GB
- **Egress**: 250 GB included, then $0.09/GB (1 TB overage = $67.50)
- **File storage**: 100 GB included, then $0.021/GB

Typical Pro + Medium (4 GB) project: $25 + $60 - $10 = **$75/month per project**.

### Hetzner VPS Pricing

| Plan | vCPU | RAM | NVMe SSD | Traffic | Monthly |
|---|---|---|---|---|---|
| CPX22 | 2 | 4 GB | 80 GB | 20 TB | **$7.59** |
| CPX32 | 4 | 8 GB | 160 GB | 20 TB | **$12.59** |
| CPX42 | 8 | 16 GB | 320 GB | 20 TB | **$22.59** |
| CPX52 | 12 | 24 GB | 480 GB | 20 TB | **$32.09** |

All Hetzner plans include **20 TB of traffic** (vs Supabase's 250 GB).

### Side-by-Side Comparison

| Scenario | Supabase Pro + Medium | Dupabase + Hetzner CPX22 | Savings |
|---|---|---|---|
| 1 project | $75/mo | $7.59/mo | **$67/mo (90%)** |
| 3 environments (dev/stage/prod) | $225/mo | $7.59/mo | **$217/mo (97%)** |
| 5 projects | $375/mo | $7.59/mo | **$367/mo (98%)** |
| 10 projects | $750/mo | $12.59/mo (CPX32) | **$737/mo (98%)** |

Even with **Micro compute** (free on Pro, 1 GB RAM):

| Scenario | Supabase Pro + Micro | Dupabase + Hetzner CPX22 | Savings |
|---|---|---|---|
| 1 project | $25/mo | $7.59/mo | **$17/mo (70%)** |
| 3 environments | $75/mo | $7.59/mo | **$67/mo (90%)** |
| 10 projects | $250/mo | $7.59/mo | **$242/mo (97%)** |

### At Scale: Compute Price Comparison

Supabase charges per-project. Hetzner is a flat rate for the server — unlimited projects.

| RAM | Supabase/mo (per project) | Hetzner/mo (flat) | Multiplier |
|---|---|---|---|
| 4 GB | $75 | $7.59 (CPX22) | **~10x** |
| 8 GB | $135 | $12.59 (CPX32) | **~11x** |
| 16 GB | $235 | $22.59 (CPX42) | **~10x** |
| 32 GB | $435 | $43.59 (CPX62) | **~10x** |
| 64 GB | $985 | ~$39 (dedicated auction) | **~25x** |
| 128 GB | $1,895 | ~$70 (dedicated auction) | **~27x** |
| 256 GB | $3,755 | ~$95 (dedicated auction) | **~40x** |

> *Supabase price = Pro $25 + compute - $10 credit. Hetzner dedicated prices from server auction (real Xeon servers with ECC RAM).*

### The Hidden Cost: Traffic

Supabase includes 250 GB egress on Pro, then charges **$0.09/GB**. A busy API can easily exceed this.

Hetzner includes **20 TB** (20,000 GB) on every VPS plan. That's 80x more traffic at no extra cost. On Supabase, 20 TB of egress would cost **~$1,777/month** in overage fees.

### What You Give Up

To be fair, Supabase managed includes things you'd need to set up yourself:

| Feature | Supabase Managed | Dupabase + Hetzner |
|---|---|---|
| PostgreSQL | Managed | You install + maintain |
| Automatic backups | 7-14 days | You configure (S3 via Dupabase dashboard) |
| Auth (GoTrue) | Built-in | Built-in (Dupabase handles this) |
| REST API (PostgREST) | Built-in | Built-in (Dupabase handles this) |
| Dashboard | Built-in | Built-in (Dupabase handles this) |
| Connection pooling | Built-in (PgBouncer) | Built-in (Dupabase pool manager) |
| Realtime | Built-in | Not yet |
| Storage API | Built-in | Not yet |
| Edge Functions | Built-in | Not yet |
| SOC2 / HIPAA | Team+ plan ($599/mo) | Your responsibility |
| Vertical scaling | One-click | Server migration |

**Bottom line**: If you need auth + REST API + dashboard (which is most projects), Dupabase gives you that at a fraction of the cost. If you need Realtime, Storage, or Edge Functions, you'll need to wait or supplement.

## Why Migrate?

1. **Cost** — Supabase is ~10x more expensive at small scale, ~25-40x at large scale
2. **Code stays the same** — `@supabase/supabase-js` works unchanged. Just change the URL.
3. **Dev/stage/prod** — One Dupabase instance handles all environments. No more paying per-project.
4. **Traffic** — 20 TB included on Hetzner vs 250 GB on Supabase
5. **No vendor lock-in** — Your data is on your server. MIT licensed. Fork it if you want.
6. **Full PostgreSQL** — Install any extension (pgvector, PostGIS, pg_cron, etc.).
7. **No pausing** — Supabase Free pauses after 1 week inactivity. Your VPS doesn't.

## Migration Steps

### Step 1: Set Up Your Server

See the [Deployment Guide](deployment.md) for detailed instructions. Quick version:

```bash
# On your Hetzner VPS (or any server)
apt install postgresql-16
sudo -u postgres psql -c "CREATE USER dupabase WITH PASSWORD 'securepass' CREATEROLE CREATEDB;"

git clone https://github.com/ansoraGROUP/dupabase.git
cd dupabase && cp .env.example .env
# Edit .env with your DATABASE_URL
make build && make up
```

### Step 2: Export Your Supabase Database

#### Option A: Supabase Dashboard
1. Go to your Supabase project → Settings → Database
2. Under "Database Backups", download the latest backup

#### Option B: pg_dump (recommended)
```bash
# Get your Supabase connection string from Settings → Database → Connection string
pg_dump "postgresql://postgres:[password]@db.[ref].supabase.co:5432/postgres" \
  --format=custom \
  --no-owner \
  --no-privileges \
  -f my_database.dump
```

For plain SQL format:
```bash
pg_dump "postgresql://postgres:[password]@db.[ref].supabase.co:5432/postgres" \
  --format=plain \
  --no-owner \
  --no-privileges \
  -f my_database.sql
```

### Step 3: Create a Project in Dupabase

1. Open your Dupabase dashboard
2. Create a new project (e.g., "my-app-prod")
3. Note the project's anon key and service role key

### Step 4: Import the Database

#### Option A: Dashboard (drag-and-drop)
1. Go to the project detail page
2. Click the "Import" tab
3. Drag and drop your `.dump` or `.sql` file
4. Dupabase automatically filters Supabase auth schema objects to avoid conflicts
5. Watch the progress in the import history

#### Option B: Direct pg_restore
```bash
# Get the project's database credentials from the Credentials page
pg_restore \
  --host=localhost --port=5432 \
  --username=proj_abc123 \
  --dbname=proj_abc123 \
  --clean --if-exists \
  --no-owner --no-privileges \
  my_database.dump
```

### Step 5: Update Your Client Code

This is the easy part — change one line:

```typescript
// Before (Supabase)
const supabase = createClient(
  'https://abc123.supabase.co',
  'eyJhbGciOiJIUzI1NiIs...'  // your Supabase anon key
)

// After (Dupabase) — just change the URL and key
const supabase = createClient(
  'https://your-domain.com',   // your Dupabase URL
  'eyJhbGciOiJIUzI1NiIs...'   // your Dupabase anon key (from dashboard)
)
```

Everything else stays the same: `.from()`, `.select()`, `.auth.signUp()`, `.rpc()` — all of it.

### Step 6: Test

Run your application against Dupabase and verify:

- [ ] User signup and login work
- [ ] Token refresh works
- [ ] CRUD operations return expected data
- [ ] RLS policies are enforced correctly
- [ ] RPC functions execute correctly
- [ ] `.single()`, `.eq()`, `.order()`, `.limit()`, `.range()` all work

> **Tip**: Run Dupabase in parallel with Supabase during testing. Point your dev environment at Dupabase while production still uses Supabase. Switch over once you're confident.

### Step 7: Go Live

1. Update your production environment variables to point at Dupabase
2. Update DNS if needed
3. Set up S3 backups (see [Backup & Import](backup-and-import.md))
4. Shut down your Supabase project

## What Migrates

| Feature | Status |
|---------|--------|
| Auth users + sessions | Imported via pg_dump |
| Public schema tables | Imported via pg_dump |
| RLS policies | Imported via pg_dump |
| PostgreSQL functions | Imported via pg_dump |
| Triggers | Imported via pg_dump |
| Storage buckets / files | **Not supported** (Dupabase doesn't have a Storage API yet) |
| Realtime subscriptions | **Not supported** (no WebSocket API yet) |
| Edge Functions | **Not supported** |

## What About Auth Users?

Dupabase imports the `auth` schema from your pg_dump. Existing user passwords **will work** because Dupabase uses the same bcrypt password hashing that Supabase/GoTrue uses. Users can log in with their existing credentials — no password resets needed.

## Multi-Environment Setup

One of the biggest Dupabase advantages. Instead of 3 Supabase projects ($75-225/month):

```
Dupabase Instance (1 Hetzner CPX22 — $7.59/month)
├── my-app-dev      (development)
├── my-app-staging  (staging)
└── my-app-prod     (production)
```

Each project is completely isolated (separate databases, separate auth, separate API keys) but runs on the same server. On Supabase Pro + Medium, this would cost **$225/month**.

```typescript
// dev
const supabaseDev = createClient(DUPABASE_URL, DEV_ANON_KEY)

// staging
const supabaseStaging = createClient(DUPABASE_URL, STAGING_ANON_KEY)

// production
const supabaseProd = createClient(DUPABASE_URL, PROD_ANON_KEY)
```

Same URL, different API keys. Each key routes to its own isolated database.
