# Troubleshooting

## Connection Issues

### "connection refused" to PostgreSQL

**Cause**: PostgreSQL isn't running, wrong host/port, or firewall blocking.

**Fix**:
```bash
# Check if PostgreSQL is running
systemctl status postgresql

# Check it's listening
ss -tlnp | grep 5432

# Test connection
psql "postgresql://user:password@localhost:5432/dbname"
```

If using Docker, make sure Dupabase can reach PostgreSQL:
- Same Docker network: use the container name as host
- Host machine: use `host.docker.internal` (or `172.17.0.1` on Linux)

### Password URL encoding

**Symptom**: "authentication failed" even though the password is correct.

**Cause**: Special characters in `DATABASE_URL` password must be URL-encoded.

| Character | Encoded |
|-----------|---------|
| `@` | `%40` |
| `#` | `%23` |
| `?` | `%3F` |
| `:` | `%3A` |
| `/` | `%2F` |

**Example**: Password `S0cr@t123` → `DATABASE_URL=postgresql://user:S0cr%40t123@localhost:5432/db`

### "PLATFORM_JWT_SECRET must be at least 32 characters"

**Fix**: Generate a longer secret:
```bash
openssl rand -base64 48
```

### Port already in use

**Symptom**: "listen tcp :3000: bind: address already in use"

**Fix**: Change the `PORT` in `.env`:
```bash
PORT=3333
```

Or find and stop whatever's using the port:
```bash
lsof -ti:3000 | xargs kill
```

---

## Auth Issues

### RLS policies not working

**Symptom**: Queries return empty results or permission errors even when authenticated.

**Cause**: The `authenticated` role needs access to the `auth` schema to call `auth.uid()`:

```sql
GRANT USAGE ON SCHEMA auth TO authenticated;
```

Dupabase sets this up automatically for new projects, but imported databases might be missing it.

### "JWT expired" errors

**Cause**: The access token has expired and needs refresh.

**Fix**: Use `supabase.auth.refreshSession()` or configure shorter `PLATFORM_JWT_EXPIRY` in `.env`.

### Signup returns 400

**Possible causes**:
- Signups disabled for the project (check project settings in dashboard)
- Password too short (check `DEFAULT_PASSWORD_MIN_LENGTH`)
- Email already registered

---

## Import Issues

### Import fails with dollar-quoted functions

**Symptom**: Plain SQL imports fail on functions with `$$` in their bodies.

**Cause**: Complex multi-line PL/pgSQL functions in plain SQL format can trip up the parser.

**Fix**: Use custom format (`.dump`) instead of plain SQL. Export with:
```bash
pg_dump --format=custom -f backup.dump your_database
```

### pg_restore "relation already exists"

**Fix**: Always use `--clean --if-exists` together:
```bash
pg_restore --clean --if-exists --no-owner --no-privileges -d dbname backup.dump
```

> `--if-exists` requires `--clean`. Using `--if-exists` alone will error.

### PostgreSQL 18 psql meta-commands

**Symptom**: Import fails with "unrecognized command `\restrict`"

**Cause**: pg_dump from PostgreSQL 18 adds `\restrict` and `\unrestrict` psql meta-commands.

**Fix**: Dupabase's dashboard import filters these automatically. If importing manually, strip them:
```bash
grep -v '^\\\(un\)\?restrict' dump.sql > clean_dump.sql
```

### File too large

**Fix**: Increase the limit in `.env`:
```bash
IMPORT_MAX_SIZE_MB=1000
```

---

## Docker Issues

### Go version mismatch in Dockerfile

**Symptom**: Build fails with Go version errors.

**Fix**: The project uses Go 1.25. The Dockerfile must use `golang:1.25-alpine`, not older versions.

### Docker Desktop not running (macOS)

**Symptom**: "Cannot connect to the Docker daemon"

**Fix**:
```bash
open -a Docker
# Wait 10-20 seconds for it to start
docker ps  # verify it's running
```

### Container can't reach host PostgreSQL

**Fix for Docker Compose**: Add to your service:
```yaml
extra_hosts:
  - "host.docker.internal:host-gateway"
```

Then use `host.docker.internal` in your `DATABASE_URL`.

---

## Dashboard Issues

### Project settings return null

**Symptom**: Settings page shows errors or blank values.

**Cause**: New projects may have `null` settings until explicitly configured.

**Fix**: This is handled in the dashboard with optional chaining. If you're using the API directly, check for null values.

### Credential API returns 400

**Symptom**: "password is required" when revealing credentials.

**Fix**: The credential reveal endpoint expects `platform_password` (not `password`):
```json
{
  "platform_password": "your-platform-login-password"
}
```

---

## Performance

### Connection pool exhaustion

**Symptom**: "too many clients" errors from PostgreSQL.

**Fix**: Adjust pool settings in `.env`:
```bash
MAX_CONNECTIONS_PER_DB=10    # connections per project (default: 5)
GLOBAL_MAX_CONNECTIONS=200   # total across all projects (default: 100)
```

Also check PostgreSQL's `max_connections` setting:
```sql
SHOW max_connections;
-- Default is usually 100. Increase if needed:
ALTER SYSTEM SET max_connections = 300;
-- Requires PostgreSQL restart
```

### Idle connections piling up

**Fix**: Reduce idle timeout:
```bash
POOL_IDLE_TIMEOUT_SECONDS=120  # default: 300
```

---

## Getting Help

- **GitHub Issues**: [github.com/ansoraGROUP/dupabase/issues](https://github.com/ansoraGROUP/dupabase/issues)
- **Contributing**: See [CONTRIBUTING.md](../CONTRIBUTING.md)
