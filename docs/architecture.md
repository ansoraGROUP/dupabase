# Architecture

## Dupabase Is Middleware

Dupabase is **not a database**. It's an API compatibility layer that sits between your application and your PostgreSQL server.

```
Your App (@supabase/supabase-js)
         │
         ▼
┌─────────────────────────┐
│   Dupabase (Go binary)  │  ← Middleware: auth, REST API, project routing
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│   YOUR PostgreSQL        │  ← You provide this (Hetzner, AWS, local, etc.)
└─────────────────────────┘
```

This is what makes Dupabase so cheap to run. Supabase self-hosted requires 15+ containers (Kong, GoTrue, PostgREST, Realtime, Storage, pg_meta, Studio, etc.). Dupabase replaces all of them with a single binary.

## Request Flow

1. Client sends a request with an API key (JWT)
2. Dupabase extracts the `project_id` from the JWT
3. The request is routed to the correct project's database
4. Auth requests go through the GoTrue-compatible handler
5. REST requests go through the PostgREST-compatible handler
6. Response is returned to the client

## API Routes

### Supabase-Compatible (per-project, authenticated via API key)

| Method | Route | Description |
|--------|-------|-------------|
| `POST` | `/auth/v1/signup` | Sign up a new user |
| `POST` | `/auth/v1/token?grant_type=password` | Sign in |
| `GET` | `/auth/v1/user` | Get current user |
| `PUT` | `/auth/v1/user` | Update user |
| `POST` | `/auth/v1/logout` | Sign out |
| `POST` | `/auth/v1/token?grant_type=refresh_token` | Refresh session |
| `GET/POST/PATCH/DELETE` | `/rest/v1/:table` | CRUD operations |
| `POST` | `/rest/v1/rpc/:function` | Call RPC function |

### Platform (dashboard backend, authenticated via platform JWT)

| Method | Route | Description |
|--------|-------|-------------|
| `POST` | `/platform/auth/register` | Register platform user |
| `POST` | `/platform/auth/login` | Login |
| `GET` | `/platform/auth/me` | Current user info |
| `PUT` | `/platform/auth/password` | Change password |
| `GET/POST/DELETE` | `/platform/projects[/:id]` | CRUD projects |
| `PATCH` | `/platform/projects/:id/settings` | Update project auth settings |
| `POST` | `/platform/projects/:id/import` | Upload database import |
| `GET` | `/platform/projects/:id/import/history` | Import history |
| `POST` | `/platform/credentials/reveal` | Reveal PG password |
| `GET/POST` | `/platform/backups/settings` | Backup S3 config |
| `GET` | `/platform/backups/history` | Backup history |
| `POST` | `/platform/backups/run` | Trigger manual backup |

### Admin (admin only)

| Method | Route | Description |
|--------|-------|-------------|
| `GET` | `/platform/admin/users` | List all users (paginated) |
| `DELETE` | `/platform/admin/users/:id` | Delete user |
| `GET/PUT` | `/platform/admin/settings` | Registration mode |
| `GET/POST/DELETE` | `/platform/admin/invites[/:id]` | Invite system |

## Connection Pool Manager

Dupabase maintains a pool of database connections using LRU (Least Recently Used) eviction:

- Each project gets its own connection pool (default: 5 connections)
- When the global limit is reached (default: 100), the least recently used pool is evicted
- Idle connections are closed after the timeout (default: 300 seconds)
- This allows hundreds of projects on a single Dupabase instance without exhausting PostgreSQL connections

## Two-Layer Authentication

### Layer 1: Platform Auth

Used by the dashboard. Platform users register/login to manage projects. JWTs are signed with `PLATFORM_JWT_SECRET`.

### Layer 2: Per-Project Supabase Auth

Each project has its own `auth` schema with users, sessions, and refresh tokens. API keys (anon_key, service_role_key) are JWTs that encode the `project_id`. This is fully compatible with `@supabase/supabase-js`.

## Database Structure

Dupabase uses a single PostgreSQL instance with multiple databases:

```
PostgreSQL Instance (YOUR server)
│
├── dupabase (platform database)
│   └── platform schema
│       ├── users          (platform accounts)
│       ├── projects       (project registry)
│       ├── pg_users       (encrypted PG credentials)
│       ├── audit_log      (activity log)
│       ├── backup_settings (S3 config)
│       ├── backup_history (backup records)
│       ├── import_tasks   (import history)
│       ├── platform_settings (registration mode)
│       └── invite_codes   (invite system)
│
├── proj_abc123 (project A)
│   ├── auth schema (users, sessions, refresh_tokens)
│   └── public schema (your application tables)
│
├── proj_def456 (project B)
│   ├── auth schema
│   └── public schema
│
└── ...
```

Each project database is completely isolated. Users, tables, and RLS policies in one project cannot access another.

## Security Model

- **AES-256-GCM encryption** — PostgreSQL credentials and S3 backup credentials are encrypted at rest using a key derived from the platform password (PBKDF2)
- **Row Level Security** — Dupabase sets `request.jwt.claims` on each connection, enabling standard PostgreSQL RLS policies
- **Rate limiting** — Auth and API endpoints are rate-limited per IP
- **Tenant isolation** — Each project runs in its own PostgreSQL database with its own role
- **Security headers** — X-Frame-Options, CSP, HSTS, X-Content-Type-Options
- **CORS whitelist** — Configurable allowed origins
- **Parameterized queries** — All SQL uses parameterized queries (no string interpolation)
- **Request body limits** — Configurable max body size
- **Non-root container** — Docker image runs as UID 1000
