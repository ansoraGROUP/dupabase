# Getting Started

Dupabase is a Supabase-compatible API middleware. It does **not** include PostgreSQL — you bring your own database, and Dupabase provides the GoTrue auth + PostgREST-compatible REST API on top of it.

## Prerequisites

| Requirement | Version | Notes |
|------------|---------|-------|
| **PostgreSQL** | 15+ | **You provide this** — local Docker, Hetzner VPS, managed (Neon, Railway, etc.) |
| Go | 1.25+ | Only if building from source |
| Node.js | 20+ | Only for the dashboard |
| Docker | Latest | Recommended deployment method |

> **Key concept**: Dupabase connects to YOUR PostgreSQL. It doesn't ship a database. This is what makes it so cheap to run — a Hetzner CPX22 VPS ($7.59/month, 4 GB RAM, 80 GB NVMe, 20 TB traffic) with PostgreSQL installed is all you need.

## Option A: Docker (Recommended)

### 1. Set up PostgreSQL

If you don't have PostgreSQL yet, start one with Docker:

```bash
docker run -d --name dupabase-pg \
  -e POSTGRES_USER=myuser \
  -e POSTGRES_PASSWORD=mypassword \
  -p 5432:5432 \
  postgres:16
```

Or install PostgreSQL directly on your server (see [Deployment Guide](deployment.md#hetzner-vps) for Hetzner setup).

The database user needs `CREATEROLE` and `CREATEDB` privileges:

```sql
ALTER USER myuser CREATEROLE CREATEDB;
```

### 2. Clone and configure

```bash
git clone https://github.com/ansoraGROUP/dupabase.git
cd dupabase
cp .deploy/local/.env.example .deploy/local/.env
```

Edit `.deploy/local/.env` — the only required values:

```bash
# Point to YOUR PostgreSQL
DATABASE_URL=postgresql://myuser:mypassword@localhost:5432/postgres

# Any random string, min 32 characters
PLATFORM_JWT_SECRET=your-secret-key-at-least-32-characters-long

# Optional: auto-create an admin user
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=your-admin-password
```

> **Gotcha**: If your password contains `@`, URL-encode it as `%40`. Example: `S0cr@t123` becomes `S0cr%40t123`.

### 3. Build and run

```bash
make build && make up
```

Dupabase is now running at `http://localhost:16733`.

### 4. Open the dashboard

Navigate to `http://localhost:16733`. If you set `ADMIN_EMAIL`/`ADMIN_PASSWORD`, log in with those credentials. Otherwise, register a new account.

## Option B: Manual (No Docker)

```bash
git clone https://github.com/ansoraGROUP/dupabase.git
cd dupabase
cp .env.example .env
# Edit .env with your DATABASE_URL and PLATFORM_JWT_SECRET

# Build and run
go build -o dupabase ./cmd/server
./dupabase
```

The server runs on port 3000 by default (configurable via `PORT` env var).

For the dashboard (separate terminal):

```bash
cd dashboard
npm install
npm run dev
```

## Create Your First Project

1. Log into the dashboard
2. Click **"New Project"** — give it a name
3. Dupabase creates an isolated PostgreSQL database for the project
4. Copy the **anon key** and **service role key** from the project detail page

## Connect with @supabase/supabase-js

```bash
npm install @supabase/supabase-js
```

```typescript
import { createClient } from '@supabase/supabase-js'

// Point to YOUR Dupabase server — everything else is the same
const supabase = createClient(
  'http://localhost:16733',  // your Dupabase URL
  'your-anon-key'            // from the dashboard
)

// Auth works the same
const { data } = await supabase.auth.signUp({
  email: 'user@example.com',
  password: 'password123',
})

// REST API works the same
const { data: rows } = await supabase
  .from('todos')
  .select('*')
  .eq('user_id', data.user.id)
```

**That's it.** Your existing Supabase code works unchanged — you just change the URL.

## Next Steps

- [Configuration Reference](configuration.md) — all environment variables
- [Deployment Guide](deployment.md) — production setup on Hetzner
- [Migration from Supabase](migration-from-supabase.md) — move your existing project
- [Architecture](architecture.md) — understand how Dupabase works
