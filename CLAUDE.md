# Dupabase

Go-based Supabase-compatible API middleware. It is not a database -- it connects to YOUR PostgreSQL and provides Supabase-compatible auth, REST, and platform management APIs on top of it.

GitHub: `ansoragroup/dupabase` (moved from BLINK-UZ)

## Project Structure

```
cmd/server/main.go              -- Entry point, migrations, service init, graceful shutdown
internal/
  config/config.go              -- Env var loading (godotenv), Config struct
  server/router.go              -- HTTP router, CORS, security headers, all route handlers
  api/
    auth/handlers.go            -- GoTrue-compatible auth (signup, token, user, logout, admin delete)
    rest/handlers.go            -- PostgREST-compatible REST (CRUD, RPC, embedding, upsert, filters)
  middleware/
    project_router.go           -- Extracts project from apikey JWT, injects project+pool into context
    platform_auth.go            -- Validates platform JWT for dashboard endpoints
    ratelimit.go                -- Per-IP token bucket rate limiter
    request_id.go               -- X-Request-ID middleware (generates/propagates request IDs)
    helpers.go                  -- Context helpers
  httputil/
    response.go                 -- Shared WriteJSON helper for consistent JSON responses
  database/
    platform.go                 -- Platform DB pool, migration runner
    pool_manager.go             -- Per-project connection pool manager with LRU eviction
    rls.go                      -- ExecuteWithRLS: SET LOCAL ROLE + jwt claims in transaction
  platform/
    auth.go                     -- Platform user auth (register, login, JWT)
    projects.go                 -- Project CRUD, DB provisioning, JWT key generation
    credentials.go              -- Credential reveal with password verification
    backup.go                   -- S3 backup (pg_dump, encrypt, upload)
    backup_scheduler.go         -- Cron-like backup scheduler
    import.go                   -- Database import (.sql, .dump, .tar)
    admin.go                    -- Admin user management, settings, invites
    audit.go                    -- Audit logging
    crypto.go                   -- AES encryption for secrets at rest
dashboard/                      -- Next.js 15 dashboard (standalone build, proxied by Go server)
.deploy/
  _shared/Dockerfile            -- Multi-stage: Go build -> Next.js build -> alpine prod image
  _shared/entrypoint.sh         -- Starts Next.js on :3000, then Go server on :3333
  prod/docker-compose.yaml      -- Production compose (GHCR image, Watchtower labels)
  local/docker-compose.yaml     -- Local dev compose
.github/workflows/deploy.yaml  -- CI/CD: build -> push GHCR -> trigger Watchtower
migrations/                     -- SQL migration files (also embedded in main.go)
tests/                          -- Supabase JS client tests
```

## Build & Run

### Local development (no Docker)
```bash
cp .env.example .env            # Edit with your PostgreSQL URL
go run ./cmd/server             # or: make dev
```

### Docker (local)
```bash
make build                      # docker compose -f .deploy/local/docker-compose.yaml build
make up                         # start containers
make logs                       # tail logs
make down                       # stop
```

### Docker (production)
```bash
make prod-build
make prod-up
make prod-logs
```

### Tests
```bash
make test                       # runs: node tests/test_supabase_client.mjs
go test ./...                   # Go unit tests
```

## Required Environment Variables

- `DATABASE_URL` -- PostgreSQL superuser connection (needs CREATEROLE + CREATEDB)
- `PLATFORM_JWT_SECRET` -- min 32 chars, for dashboard auth

## Optional Environment Variables

- `PORT` (default 3000), `HOST` (default 0.0.0.0), `SITE_URL`
- `ADMIN_EMAIL` + `ADMIN_PASSWORD` -- auto-created admin on startup
- `ALLOWED_ORIGINS` -- comma-separated CORS origins
- `MAX_CONNECTIONS_PER_DB` (default 5), `GLOBAL_MAX_CONNECTIONS` (default 100)
- `POOL_IDLE_TIMEOUT_SECONDS` (default 300)
- `BACKUP_ENCRYPTION_KEY` -- falls back to PLATFORM_JWT_SECRET
- `IMPORT_MAX_SIZE_MB` (default 500), `IMPORT_TEMP_DIR` (default /tmp/imports)
- `PLATFORM_JWT_EXPIRY` (default 86400) -- platform dashboard JWT lifetime in seconds
- `PLATFORM_MAX_CONNECTIONS` (default 10) -- platform DB pool max connections
- `PLATFORM_MIN_CONNECTIONS` (default 2) -- platform DB pool min connections
- `API_KEY_EXPIRY_DAYS` (default 365) -- project API key expiry in days
- `LOG_FORMAT` (default text) -- set to "json" for structured JSON logging
- `BACKUP_SCHEDULER_STARTUP_DELAY` (default 30s) -- delay before first backup check
- `ALLOWED_SCHEMAS` (default "public") -- comma-separated schemas for REST API access
- `DASHBOARD_URL` -- set automatically in entrypoint.sh to http://localhost:3000
- `TRUST_PROXY` -- set to "true" to trust X-Forwarded-For headers for rate limiting

## Deployment (CI/CD)

1. Push to `main` branch
2. GitHub Actions builds multi-stage Docker image (Go + Next.js)
3. Pushes to `ghcr.io/ansoragroup/dupabase:prod-latest`
4. Triggers Watchtower via webhook, which pulls the new image and restarts the container

Production server: `65.108.104.85`
- Compose: `/var/www/dupabase/dupabase/.deploy/prod/`
- Env: `/var/www/dupabase/dupabase/.deploy/prod/.env`
- Container: `dupabase` on port 3333, networks: `ansora_network` + `theo_network`
- Proxied via Nginx Proxy Manager: `api.dupabase.dev` and `dash.dupabase.dev`

## Architecture

### Request Flow
1. Request hits Go server on :3333
2. `securityHeaders` middleware adds X-Content-Type-Options, CSP, HSTS, etc.
3. `cors` middleware handles CORS (reflects requested headers, whitelists origins for credentials)
4. Route matching:
   - `/platform/*` -- Platform API (dashboard auth via `PlatformAuth` middleware)
   - `/auth/v1/*` -- GoTrue-compatible auth (project routing via `ProjectRouter` middleware)
   - `/rest/v1/*` -- PostgREST-compatible REST (project routing via `ProjectRouter` middleware)
   - `/health` -- health check with DB ping
   - `/*` -- reverse proxy to Next.js dashboard (if DASHBOARD_URL is set)
5. Rate limiting: auth endpoints 5 req/s burst 10, API endpoints 30 req/s burst 60

### Multi-Tenant Project Routing
- Client sends `apikey` header containing a JWT with `project_id` claim
- `ProjectRouter` middleware decodes JWT, looks up project in platform DB (60s cache)
- Verifies JWT signature against the project's `jwt_secret`
- Gets or creates a database connection pool for the project's dedicated database
- Injects project record + pool into request context
- The `role` claim in the JWT determines RLS role (anon, authenticated, service_role)

### RLS (Row Level Security)
- `ExecuteWithRLS` wraps queries in a transaction with `SET LOCAL ROLE` and `set_config('request.jwt.claims', ...)`
- `service_role` bypasses RLS entirely (no role switching)
- Role names validated via regex to prevent SQL injection
- Individual claims (sub, role, email) set as `request.jwt.claim.*` GUC variables

### Connection Pooling
- `PoolManager` maintains per-project `pgxpool.Pool` instances
- LRU eviction when hitting `GLOBAL_MAX_CONNECTIONS` limit
- Idle pools evicted after `POOL_IDLE_TIMEOUT_SECONDS`
- Project records cached for 60 seconds

### CORS
- Whitelisted origins (from `ALLOWED_ORIGINS`) get `Access-Control-Allow-Credentials: true`
- Unknown origins are allowed but without credentials
- `Access-Control-Allow-Headers` reflects whatever the client requests (no hardcoded list)
- Preflight cached for 24 hours

### Platform Database Schema
All platform tables in `platform` schema:
- `platform.users` -- dashboard users
- `platform.pg_users` -- per-user PostgreSQL credentials (encrypted)
- `platform.projects` -- multi-tenant projects with JWT keys
- `platform.audit_log` -- action audit trail
- `platform.backup_settings` -- S3 backup config (encrypted credentials)
- `platform.backup_history` -- backup run history
- `platform.import_tasks` -- database import jobs
- `platform.settings` -- global settings (registration_mode)
- `platform.invites` -- invite codes for closed registration

### Per-Project Auth Schema
Each project database gets a standard Supabase `auth` schema:
- `auth.users` -- end users (email, password, metadata, is_anonymous)
- `auth.sessions` -- active sessions (user_agent, IP, AAL)
- `auth.refresh_tokens` -- refresh token rotation with revocation
- `auth.identities` -- identity providers (email for now)

## Key Dependencies

- `github.com/jackc/pgx/v5` -- PostgreSQL driver and connection pooling
- `github.com/golang-jwt/jwt/v5` -- JWT signing and verification (HMAC only)
- `github.com/joho/godotenv` -- .env file loading
- `golang.org/x/crypto` -- bcrypt password hashing
- `github.com/aws/aws-sdk-go-v2` -- S3 for backups

## Important Patterns

- All error responses from REST API use PostgREST error format: `{code, message, details, hint}`
- Auth error responses use GoTrue format: `{error, error_description}`
- DB errors are sanitized before returning to clients (never expose raw PG errors)
- Password hashing uses bcrypt with cost 12
- Timing-safe login: dummy bcrypt compare on user-not-found to prevent enumeration
- JWT tokens expire in 1 hour, refresh tokens are rotated with revocation detection
- Body size limits: 1MB for most endpoints, configurable for imports
- Dashboard is reverse-proxied through the Go server (same-origin, no CORS needed)

## Sprint 1: Phase 1+2 Tracker (Stop the Bleeding + Trust but Verify)

### Security (Team 1)
- [x] S1: Fix 6 silent error discards in auth handlers
- [x] S2: Wrap UpdateUser in DB transaction
- [x] S3: Require current_password for password change
- [x] S4: Add max password length 72 (bcrypt limit)
- [x] S5: Wrap AdminDeleteUser in DB transaction
- [x] S6: Remove JWT secret from ListProjects response
- [x] S7: Token invalidation on password change
- [x] S8: CORS: stop reflecting unknown origins
- [x] S9: HSTS: gate behind TRUST_PROXY

### Reliability (Team 2)
- [x] R1: Remove hardcoded --role=stech (CRITICAL)
- [x] R2: Add go test to CI/CD (CRITICAL)
- [x] R3: Wrap migrations in transactions (CRITICAL)
- [x] R4: Fix goroutine leak in RateLimiter
- [x] R5: Fix modulo bias in GenerateRandomPassword
- [x] R6: Replace fmt.Printf with slog in backup
- [x] R7: Unify IP extraction with TRUST_PROXY in audit
- [x] R8: Delete dead code readOutput
- [x] R9: Replace duplicate migration 002
- [x] R10: Fix isDue to accept context
- [x] R11: Fix audit logging to log own errors
- [x] R12: Log warning on backup key fallback
- [x] R13: Path traversal protection on import upload
- [x] R14: Add request ID middleware

### Testing (Team 3)
- [x] T1: CORS middleware tests
- [x] T2: Security headers tests
- [x] T3: RateLimiter concurrent/race tests
- [x] T4: Shared WriteJSON helper (httputil package)
- [x] T5: Run gofmt on entire codebase

### Knowledge Base (Team 4)
- [x] K1: .claude/settings.json
- [x] K2: .claude/commands/test.md
- [x] K3: .claude/commands/audit.md
- [x] K4: Sprint tracker in CLAUDE.md
- [x] K5: Update /teo/CLAUDE.md
- [x] K6: Update memory/MEMORY.md
- [x] K7: Update memory/architecture.md
- [x] K8-K12: Continuous doc updates

## Sprint 2: Hardening + Cleanup (2026-03-02)

### Security Hardening (Team 1)
- [x] AUTH-05: Enforce min password length in UpdateUser
- [x] AUTH-07: Per-email brute-force protection on GoTrue token endpoint
- [x] AUTH-01/04: Email format validation on signup and update
- [x] REST-03/04: Block bulk delete/update without filter
- [x] REST-01: Return error for unsupported logical operators
- [x] ROUTER-08: Admin delete endpoint uses stricter rate limiter
- [x] ROUTER-07: Audit logging for project settings update
- [x] AUTH-02: Compute ExpiresIn dynamically

### Reliability & Resource Cleanup (Team 2)
- [x] ADMIN-01: Clean up PG role on user delete
- [x] ADMIN-02: Clean up project databases on user delete
- [x] PROJ-01: Project creation cleanup on failure
- [x] PROJ-03: Log errors in DeleteProject
- [x] ROUTER-04: Stop rate limiters on graceful shutdown
- [x] IMPORT-04: Clean temp file on import failure
- [x] BACK-05/IMPORT-06: Hide DB credentials from process args (PGPASSWORD)
- [x] BACK-02: S3 retention enforcement
- [x] SCHED-01/02: Scheduler cancellable context + WaitGroup
- [x] BACK-04: isDue per-project not per-user
- [x] POOL-01: evictIdle cleans projectCache
- [x] ROUTER-02: Health endpoint error sanitization

### Testing & Code Quality (Team 3)
- [x] TEST-04: SQL filter state machine tests (filterSQLFile, filterTOC, isOnlyWarnings)
- [x] LOG-01: Migrate all writeJSON to httputil.WriteJSON (5 duplicates eliminated)
- [x] AUTH-08: Strip port from IP in session storage
- [x] AUTH-06: Intent comment on Logout body decode
- [x] REST-06: Remove ToLower in isAllowedSchema
- [x] REST-07: Sanitize DB error messages
- [x] ROUTER-05: Sanitize internal errors in platform handlers
- [x] RLS-02: Log set_config errors

### DevOps & Infrastructure (Team 4)
- [x] CI-01: Combine build/push into single CI job
- [x] CI-02: Post-deploy health check
- [x] DOCKER-02: PG client version configurable via build arg
- [x] DOCKER-03: HEALTHCHECK instruction in Dockerfile
- [x] DOCKER-01: /tmp/imports writable by node user
- [x] ENTRY-01: Replace sleep with poll loop in entrypoint
- [x] DB-02: Move _migrations to platform schema
- [x] MAIN-01: Migration timeout (30s)

### Deferred to Sprint 3
- ~~PLAUTH-05: Token versioning for JWT invalidation~~ → Done in Sprint 4
- ~~PLAUTH-01/02: Persistent login attempt tracking~~ → In-memory with cleanup goroutine (Sprint 3)
- ~~BACK-01: S3 streaming with Content-Length~~ → Deferred (low priority)
- ~~BACK-03: pg_dump cancellation handling~~ → Deferred (low priority)
- ~~PROJ-02: Redesign pool manager for creation flow~~ → evictLRULocked fixed (Sprint 3)
- ~~PROJ-05: Document anon grant implications~~ → Done in Sprint 4
- ~~IMPORT-02/03: SQL filter edge cases~~ → TOC patterns narrowed (Sprint 4)
- ~~PR-01: Distributed cache invalidation~~ → Deferred (requires Redis, multi-replica scope)

## Sprint 3: CRITICAL + HIGH Remaining Fixes (2026-03-02)

### Auth & Security (Team 1)
- [x] CRIT-02: Atomic token refresh (revoke + insert in single transaction)
- [x] CRIT-05: dummyProjectHash init() with panic on failure
- [x] HIGH-01: json.Unmarshal error logging in HandleSignUp/HandleToken
- [x] HIGH-02: Per-email brute-force cleanup goroutine (unbounded map fix)
- [x] HIGH-03: TOCTOU fix with SELECT FOR UPDATE on password change
- [x] HIGH-04: Email validation in platform Register + registerInternal
- [x] HIGH-05: HandleRPC body decode error handling
- [x] HIGH-07: count Scan error logging in REST handlers
- [x] HIGH-08: REVOKE CONNECT error handling in DeleteProject

### Reliability & Error Handling (Team 2)
- [x] CRIT-01: evictLRULocked cleans projectCache (pool_manager.go)
- [x] MED-02: rls.go claimsJSON marshal error properly returned
- [x] MED-03: database/platform.go CREATE SCHEMA error handling
- [x] MED-04: backup.go mark-completed error logging
- [x] MED-05: import.go isOnlyWarnings lowercase fix
- [x] MED-06: import.go postImport error logging
- [x] MED-07: admin.go audit logging for DB drops
- [x] MED-08: httpServer.Shutdown error logging in main.go
- [x] MED-09: router.go rand.Read error check
- [x] MED-10: router.go health endpoint Content-Type header
- [x] LOW-01: Dead code cleanup across codebase

### REST/Router/Import (Team 3)
- [x] REST-08: allowedSchemas configurable via ALLOWED_SCHEMAS env var
- [x] REST-09: HandleRPC schema validation
- [x] ROUTER-09: Consistent error format across all handlers
- [x] IMPORT-05: filterTOC pattern narrowing (auth → auth\.)
- [x] IMPORT-07: Import progress tracking improvements
- [x] PROJ-04: Project listing pagination support
- [x] BACK-06: S3 retention pagination (IsTruncated + ContinuationToken)
- [x] BACK-07: projectID[:8] safe slice for short IDs

### DevOps & Config Validation (Team 4)
- [x] CRIT-03: entrypoint.sh curl→wget fix (alpine compatibility)
- [x] CRIT-04: CI health check exits 1 on failure (was non-fatal)
- [x] CONFIG-01: PORT validation in config.go
- [x] CONFIG-02: Connection config validation (min/max connections)
- [x] CONFIG-03: BACKUP_ENCRYPTION_KEY length validation
- [x] CONFIG-04: New env vars: PLATFORM_MAX_CONNECTIONS, PLATFORM_MIN_CONNECTIONS, API_KEY_EXPIRY_DAYS
- [x] DOCKER-04: Docker base image pinning comment
- [x] LOG-02: LOG_FORMAT env var for structured JSON logging
- [x] SCHED-03: Configurable BACKUP_SCHEDULER_STARTUP_DELAY
- [x] CI-03: Go test step timeout in CI
- [x] MAIN-02: Graceful shutdown logs errors from httpServer.Shutdown
- [x] DB-03: Migration 006_token_version.sql for token versioning column

## Sprint 4: Comprehensive Tests + Deferred Items (2026-03-02)

### Missing Tests (Team 5)
- [x] TEST-05: backup.go tests (isDue, retention, markBackupFailed)
- [x] TEST-06: backup_scheduler.go tests (Start/Stop, isDue integration)
- [x] TEST-07: admin.go tests (DeleteUser validation, role cleanup)
- [x] TEST-08: auth/handlers_test.go (email validation, password limits, lockout)
- [x] TEST-09: rest/handlers_test.go (hasFilterParams, bulk op guards, schema validation)
- [x] TEST-10: platform/auth_test.go (email validation, token version)
- [x] TEST-11: server/integration_test.go (httptest health endpoint)

### Deferred Items (Team 6)
- [x] PLAUTH-05: Token versioning (token_version column + migration + JWT claim + validation)
- [x] IMPORT-02: TOC filter patterns narrowed (auth\. instead of auth)
- [x] PROJ-05: Anon grant documentation comment in projects.go
- [x] PLAUTH-02: In-memory login attempt tracking with cleanup goroutine

### Still Deferred (Future Sprints)
- ~~BACK-01: S3 streaming upload~~ → Already streaming, confirmed in Sprint 7
- ~~BACK-03: pg_dump cancellation handling~~ → Done in Sprint 7
- PR-01: Distributed cache invalidation (requires Redis, multi-replica deployment scope)

## Sprint 5: Final Audit Fixes (2026-03-02)

### CRITICAL Fixes (Team 1)
- [x] C-1: Platform DB pool now uses PLATFORM_MAX_CONNECTIONS/PLATFORM_MIN_CONNECTIONS env vars
- [x] C-2: GoTrue cleanup goroutine has shutdown mechanism (StopGoTrueCleanup)
- [x] C-3: Platform auth loginAttempts cleanup goroutine (StartCleanup/StopCleanup)

### HIGH Fixes (Team 1)
- [x] H-1: TOCTOU fix in platform ChangePassword (SELECT FOR UPDATE in transaction)
- [x] H-2: Checked Exec return values in import.go (cancel + completion status updates)
- [x] H-3: ValidateToken accepts context.Context parameter (no more context.Background)
- [x] H-5: extractRPCName rejects paths with slashes
- [x] H-6: ListProjects uses '' AS jwt_secret (secret never fetched from DB)

### MEDIUM Fixes (Team 2)
- [x] M-1: json.Marshal errors checked and logged in auth handlers (4 locations)
- [x] M-2: UUID validation on project ID path params (4 handlers)
- [x] M-3: Content-Range header fix for empty results (*/count instead of 0--1/count)
- [x] M-4: Deduplicated S3 client creation in backup.go (uploadToS3 uses getS3Client)
- [x] M-5: ParseMultipartForm memory limit reduced to 32MB
- [x] M-7: Invite email validation in admin.go
- [x] M-8: Race condition fix in CancelImport (copy process pointer under lock)
- [x] M-9: Admin delete user notifies pool manager (ClosePool for each project)

### LOW Fixes (Team 3)
- [x] L-1: WriteJSON encoder error checked and logged
- [x] L-4: extractIP uses net.SplitHostPort for proper IPv6 handling
- [x] L-5: Consolidated extractClientIP into httputil.ExtractClientIP (shared by ratelimit + audit)
- [x] L-6: API key expiry uses config APIKeyExpiryDays (no longer hardcoded 365)
- [x] L-10: isOnlyWarnings uses specific pg_restore/pg_dump error patterns
- [x] L-11: RequestID middleware validates incoming X-Request-ID (max 128 chars, alphanumeric)

## Sprint 6: Final Polish (2026-03-02)

### HIGH Fixes
- [x] H-1: UUID validation added to handleImportStatus, handleImportHistory, handleCancelImport, handleAdminDeleteUser
- [x] H-2: BackupScheduler.Stop() uses sync.Once to prevent double-close panic

### MEDIUM Fixes
- [x] M-1: TRUST_PROXY loaded once at startup into Config, passed to Server/RateLimiter/AuditService
- [x] M-3: credentials.go URL parse errors checked and logged
- [x] M-4: godotenv.Load() error checked (warns on parse/permission errors, silent on file-not-found)

### LOW Fixes
- [x] L-3: Dashboard next.config.ts poweredByHeader: false (removes X-Powered-By: Next.js)

### Skipped (acceptable tradeoffs)
- M-5: localStorage token storage — standard SPA pattern
- L-1/L-2: Test file hardcoded tokens and error discards — test-only code

## Sprint 7: Deferred Items Resolved (2026-03-02)

- [x] CORS: Removed hardcoded localhost origins — empty map by default, fully controlled by ALLOWED_ORIGINS env var
- [x] pg_dump cancellation: Context-aware cancellation with proper status tracking (cancelled vs failed) + S3 partial upload cleanup via deleteS3Object
- [x] S3 streaming: Already streaming (pg_dump stdout → PutObject), no Content-Length needed — AWS SDK handles chunked transfer
