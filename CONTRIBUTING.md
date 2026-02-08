# Contributing to Dupabase

Thanks for your interest in contributing! This guide will help you get started.

## Prerequisites

- **Go 1.25+**
- **PostgreSQL 15+** (running locally or via Docker)
- **Node.js 20+** (for dashboard and tests)
- **Docker** (optional, for containerized development)

## Development Setup

### 1. Clone the repository

```bash
git clone https://github.com/ansoraGROUP/dupabase.git
cd dupabase
```

### 2. Set up PostgreSQL

You need a PostgreSQL instance with a superuser that has `CREATEROLE` and `CREATEDB` privileges.

```bash
# Example: using Docker
docker run -d --name dupabase-pg \
  -e POSTGRES_USER=stech \
  -e POSTGRES_PASSWORD=yourpassword \
  -p 15432:5432 \
  postgres:16
```

### 3. Configure environment

```bash
# For Docker development:
cp .deploy/local/.env.example .deploy/local/.env
# Edit .deploy/local/.env with your PostgreSQL connection string

# For local (no Docker) development:
cp .env.example .env
# Edit .env with your PostgreSQL connection string
```

### 4. Run the server

```bash
go run ./cmd/server
```

### 5. Run the dashboard

```bash
cd dashboard
npm install
npm run dev
```

The dashboard will be available at `http://localhost:3000` (or next available port).

## Running Tests

```bash
# Install test dependencies
npm install

# Run all test suites (318 tests total)
node tests/test_full_compatibility.mjs    # 120 tests - full API compatibility
node tests/test_supabase_dropin.mjs       # 77 tests - drop-in replacement
node tests/test_import.mjs                # 44 tests - database import
node tests/test_admin.mjs                 # 77 tests - admin panel & invites

# Run Go tests
go test ./...
```

Make sure the server is running before executing the test suites.

## Code Style

### Go
- Format with `gofmt`
- Follow standard Go conventions
- No unused imports or variables

### TypeScript (Dashboard)
- ESLint configuration is provided
- Run `npm run lint` in the `dashboard/` directory

## Submitting Changes

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run the test suites to ensure nothing is broken
5. Commit with a descriptive message
6. Push and open a pull request

### Commit Messages

- Use imperative mood: "Add feature" not "Added feature"
- Keep the first line under 72 characters
- Reference issues when applicable: "Fix #123: resolve auth token expiry"

### What Makes a Good PR

- Focused on a single change
- Includes tests for new functionality
- Doesn't break existing tests
- Has a clear description of what and why

## Reporting Issues

- Use the GitHub issue templates
- Include steps to reproduce for bugs
- Include your environment (OS, Go version, PostgreSQL version)

## Project Structure

```
dupabase/
├── cmd/server/          # Server entry point (embedded migrations)
├── internal/
│   ├── api/auth/        # GoTrue-compatible auth handlers
│   ├── api/rest/        # PostgREST-compatible REST handlers
│   ├── config/          # Configuration
│   ├── database/        # Connection pool manager + migrations runner
│   ├── middleware/       # Auth, routing, rate limiting, CORS
│   ├── platform/        # Platform features (auth, projects, credentials, backup, import, admin)
│   └── server/          # HTTP server and routing
├── dashboard/           # Next.js 16 dashboard (shadcn/ui, dark mode)
│   └── src/app/dashboard/
│       ├── page.tsx             # Projects list
│       ├── admin/page.tsx       # Admin panel (users, invites, registration)
│       ├── backups/page.tsx     # S3 backup settings + history
│       ├── credentials/page.tsx # PG credentials
│       ├── settings/page.tsx    # Account settings
│       └── projects/[id]/       # Project detail + settings
├── tests/               # Integration test suites (318 tests)
├── .deploy/             # Docker deployment configs
└── ../landing/          # Landing page (Next.js 16 + shadcn/ui + Shiki)
```

## API Routes

### Platform Routes (dashboard backend)

| Method | Route | Description |
|--------|-------|-------------|
| `POST` | `/platform/auth/register` | Register (respects registration mode) |
| `POST` | `/platform/auth/login` | Login |
| `GET` | `/platform/auth/me` | Get current user |
| `PUT` | `/platform/auth/password` | Change password |
| `GET` | `/platform/auth/registration-mode` | Public: get registration mode |
| `GET/POST/DELETE` | `/platform/projects[/:id]` | CRUD projects |
| `PATCH` | `/platform/projects/:id/settings` | Update project auth settings |
| `POST` | `/platform/projects/:id/import` | Upload database import |
| `GET` | `/platform/projects/:id/import/history` | Import history |
| `POST` | `/platform/credentials/reveal` | Reveal PG password |
| `GET/POST` | `/platform/backups/settings` | Backup S3 config |
| `GET` | `/platform/backups/history` | Backup history |
| `POST` | `/platform/backups/run` | Trigger manual backup |

### Admin Routes (admin only)

| Method | Route | Description |
|--------|-------|-------------|
| `GET` | `/platform/admin/users` | List all platform users |
| `DELETE` | `/platform/admin/users/:id` | Delete a user |
| `GET` | `/platform/admin/settings` | Get platform settings |
| `PUT` | `/platform/admin/settings` | Update registration mode |
| `GET` | `/platform/admin/invites` | List invite codes |
| `POST` | `/platform/admin/invites` | Create invite code |
| `DELETE` | `/platform/admin/invites/:id` | Revoke invite |

### Supabase-Compatible Routes

| Method | Route | Description |
|--------|-------|-------------|
| `POST` | `/auth/v1/signup` | GoTrue signup |
| `POST` | `/auth/v1/token?grant_type=password` | GoTrue login |
| `GET` | `/auth/v1/user` | Get authenticated user |
| `POST` | `/auth/v1/logout` | Sign out |
| `POST` | `/auth/v1/token?grant_type=refresh_token` | Refresh session |
| `GET/POST/PATCH/DELETE` | `/rest/v1/:table` | PostgREST CRUD |
| `POST` | `/rest/v1/rpc/:function` | Call RPC function |

## Documentation

Full project documentation is in the [`docs/`](docs/) directory:

- [Getting Started](docs/getting-started.md)
- [Configuration](docs/configuration.md)
- [Deployment](docs/deployment.md)
- [Architecture](docs/architecture.md)
- [Migration from Supabase](docs/migration-from-supabase.md)
- [Backup & Import](docs/backup-and-import.md)
- [Troubleshooting](docs/troubleshooting.md)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
