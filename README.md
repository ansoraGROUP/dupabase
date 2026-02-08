# Dupabase

### Stop paying $100+/month to Supabase.

![Go 1.25](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Tests: 318 passing](https://img.shields.io/badge/tests-318%20passing-brightgreen)
![Docker](https://img.shields.io/badge/Docker-ready-blue?logo=docker&logoColor=white)

Dupabase is a **Supabase-compatible API middleware** for your own PostgreSQL. It doesn't include a database — you bring your own. Works with the official `@supabase/supabase-js` client with zero code changes.

---

## The Problem

- **Supabase costs add up fast.** Pro plan is $25/project/month base. Add Medium compute (4 GB) and it's $75/project/month. Three environments = $225/month before usage charges.
- **Self-hosting Supabase is painful.** 15+ Docker containers (Kong, GoTrue, PostgREST, Realtime, Storage, pg_meta, Studio...) per environment.
- **Your code is locked in.** Everything uses `@supabase/supabase-js` — rewriting to use raw PostgreSQL is months of work.

## The Solution

- **Single Go binary.** Replaces all 15+ Supabase containers with one lightweight process.
- **BYO PostgreSQL.** Dupabase is just the API layer — connect it to your PostgreSQL on any VPS.
- **Zero code changes.** `@supabase/supabase-js` works unchanged. Literally just change the URL.

## Cost Comparison

Supabase Pro ($25/mo) + Medium compute (4 GB RAM) = **$75/project/month** after $10 compute credit.

A Hetzner CPX22 (2 vCPU, 4 GB RAM, 80 GB NVMe, 20 TB traffic) costs **$7.59/month** — and runs unlimited Dupabase projects.

| Scenario | Supabase Pro + Medium | Dupabase + Hetzner CPX22 |
|---|---|---|
| **1 project** | $75/mo | **$7.59/mo** |
| **3 environments** (dev/stage/prod) | $225/mo | **$7.59/mo** (1 server, multi-tenant) |
| **10 projects** | $750/mo | **$7.59/mo** (still 1 server) |
| **Egress** | 250 GB, then $0.09/GB | **20 TB included** |
| **DB storage** | 8 GB, then $0.125/GB | **80 GB NVMe included** |

> **Even at Micro compute** (1 GB, free on Pro): 3 Supabase projects = $75/month. Same Hetzner VPS = $7.59/month — **10x cheaper** with 80x more traffic included.

Need more power? Hetzner CPX32 (4 vCPU, 8 GB, 160 GB) is **$12.59/mo** — equivalent to Supabase's Large compute tier at **$135/mo** ($25 plan + $110 compute).

<details>
<summary><b>Full compute price comparison (Supabase vs Hetzner)</b></summary>

| RAM | Supabase (plan + compute) | Hetzner Cloud | Multiplier |
|---|---|---|---|
| 4 GB | $75/mo | $7.59/mo (CPX22) | **~10x** |
| 8 GB | $135/mo | $12.59/mo (CPX32) | **~11x** |
| 16 GB | $235/mo | $22.59/mo (CPX42) | **~10x** |
| 32 GB | $435/mo | $43.59/mo (CPX62) | **~10x** |
| 64 GB | $985/mo | ~$39/mo (dedicated auction) | **~25x** |
| 128 GB | $1,895/mo | ~$70/mo (dedicated auction) | **~27x** |

*Supabase = Pro $25 + compute - $10 credit. Per project. Hetzner = flat rate, unlimited projects.*

</details>

## How It Works

```
Your App (@supabase/supabase-js)
         │
         ▼
┌─────────────────────────┐
│   Dupabase (Go binary)  │  ← Auth + REST API + Dashboard
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│   YOUR PostgreSQL        │  ← Hetzner VPS, AWS, local, anywhere
└─────────────────────────┘
```

Dupabase provides:
- **GoTrue-compatible auth** — signup, login, JWT sessions, token refresh
- **PostgREST-compatible REST API** — CRUD, filtering, ordering, pagination, RPC
- **Dashboard** — project management, API keys, backups, settings, admin panel
- **Multi-tenant** — unlimited isolated projects on one server

Dupabase does **not** provide:
- PostgreSQL (you bring this)
- S3 storage (you bring this for backups)
- Realtime subscriptions (not yet)
- File storage API (not yet)
- Edge Functions (not yet)

## Quick Start

```bash
git clone https://github.com/ansoraGROUP/dupabase.git
cd dupabase
cp .deploy/local/.env.example .deploy/local/.env
# Edit .deploy/local/.env — set DATABASE_URL and PLATFORM_JWT_SECRET
make build && make up
# Dashboard at http://localhost:16733
```

That's it. Create a project, grab the API key, and use it with `@supabase/supabase-js`:

```typescript
import { createClient } from '@supabase/supabase-js'

const supabase = createClient(
  'http://localhost:16733',  // your Dupabase
  'your-anon-key'            // from dashboard
)

// Everything works the same
await supabase.auth.signUp({ email: 'user@example.com', password: 'password' })
const { data } = await supabase.from('todos').select('*')
```

## Features

- [x] **Auth** — GoTrue-compatible signup, login, JWT, refresh tokens, RLS
- [x] **REST API** — PostgREST-compatible CRUD, filtering (eq/neq/gt/lt/like/in/is), ordering, pagination, upsert, RPC
- [x] **Dashboard** — Next.js 16 + shadcn/ui, dark mode, project management, API keys, settings
- [x] **Multi-tenant** — isolated databases per project, separate auth, separate API keys
- [x] **Admin panel** — user management, invite system, registration control (open/invite/disabled)
- [x] **Database import** — pg_dump upload (custom + SQL format), drag-and-drop, auth schema filtering
- [x] **S3 backups** — scheduled (hourly/daily/weekly), per-project selection, AES-256-GCM encrypted credentials
- [x] **Security** — rate limiting, CORS, security headers, parameterized queries, encrypted credentials

See [full documentation](docs/) for details.

## API Compatibility

Works with `@supabase/supabase-js` out of the box:

| Method | Status |
|--------|--------|
| `supabase.auth.signUp()` / `signInWithPassword()` / `signOut()` | Working |
| `supabase.auth.getUser()` / `updateUser()` / `refreshSession()` | Working |
| `supabase.from().select()` / `insert()` / `update()` / `delete()` / `upsert()` | Working |
| `supabase.rpc()` | Working |
| `.eq()` `.neq()` `.gt()` `.lt()` `.like()` `.ilike()` `.in()` `.is()` | Working |
| `.order()` `.limit()` `.range()` `.single()` | Working |
| `Prefer: count=exact` | Working |
| Schema selection (`Accept-Profile` / `Content-Profile`) | Working |
| `supabase.auth.signInWithOAuth()` | Not yet |
| `supabase.storage.*` | Not yet |
| `supabase.channel()` / Realtime | Not yet |
| `supabase.functions.invoke()` | Not yet |

## Documentation

| Guide | Description |
|-------|-------------|
| [Getting Started](docs/getting-started.md) | First project setup with BYO PostgreSQL |
| [Configuration](docs/configuration.md) | All environment variables |
| [Deployment](docs/deployment.md) | Hetzner VPS, Docker, bare metal, SSL |
| [Architecture](docs/architecture.md) | How the middleware works |
| [Migration from Supabase](docs/migration-from-supabase.md) | Step-by-step with cost breakdown |
| [Backup & Import](docs/backup-and-import.md) | S3 backups and database import |
| [Troubleshooting](docs/troubleshooting.md) | Common issues and fixes |

## Testing

318 integration tests across 4 suites:

```bash
node tests/test_full_compatibility.mjs    # 120 tests — API compatibility
node tests/test_supabase_dropin.mjs       # 77 tests — drop-in replacement
node tests/test_import.mjs                # 44 tests — database import
node tests/test_admin.mjs                 # 77 tests — admin panel & invites
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). PRs welcome.

## License

MIT — see [LICENSE](LICENSE).
