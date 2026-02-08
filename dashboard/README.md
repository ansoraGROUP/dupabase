# Dupabase Dashboard

The management dashboard for Dupabase, built with Next.js 16, React 19, shadcn/ui, and Tailwind CSS v4.

## Features

- **Projects** — Create, delete, and manage PostgreSQL databases
- **API Keys** — View and copy anon key, service role key, JWT secret
- **Quick Start** — Per-project code examples for `@supabase/supabase-js`
- **Database Import** — Drag-and-drop pg_dump upload with progress tracking
- **Backups** — Configure S3-compatible backups with per-project selection, schedule, and history
- **Credentials** — Reveal encrypted PostgreSQL password with platform password verification
- **Settings** — Account profile, password change, project auth configuration
- **Admin Panel** — User management, registration control (open/invite/disabled), invite code system (admin only)
- **Dark Mode** — Supabase-inspired green accent color system

## Tech Stack

- **Next.js 16** (App Router, Turbopack)
- **React 19**
- **shadcn/ui** (new-york style)
- **Tailwind CSS v4** (OKLCh color space)
- **Lucide Icons**
- **Sonner** (toast notifications)

## Getting Started

```bash
npm install
npm run dev
```

The dashboard connects to the Dupabase API server. Set the API URL via environment variable:

```bash
# .env.local
NEXT_PUBLIC_API_URL=http://localhost:3333
```

## Build

```bash
npm run build
npm start
```

## Pages

| Route | Description |
|-------|-------------|
| `/login` | Platform login |
| `/register` | Platform registration |
| `/dashboard` | Projects list |
| `/dashboard/projects/[id]` | Project detail (API keys, connection, quick start, import) |
| `/dashboard/projects/[id]/settings` | Project auth settings |
| `/dashboard/credentials` | PostgreSQL credentials |
| `/dashboard/backups` | S3 backup configuration and history |
| `/dashboard/settings` | Account settings |
| `/dashboard/admin` | Admin panel — users, invites, registration mode (admin only) |
