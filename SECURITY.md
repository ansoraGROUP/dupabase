# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Dupabase, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please send an email with details to the project maintainers or use GitHub's private vulnerability reporting feature.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Fix release**: Depends on severity, typically within 2 weeks for critical issues

## Scope

The following are in scope:

- Authentication bypass or privilege escalation
- Admin middleware bypass or unauthorized admin access
- SQL injection or data leakage between tenants
- Credential exposure (API keys, JWT secrets, PG passwords, S3 backup credentials)
- Invite code abuse (replay, brute-force, or bypass)
- Remote code execution
- Cross-site scripting (XSS) in the dashboard
- Backup data exposure or unauthorized S3 access

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |

## Security Features

Dupabase includes several security measures:

- AES-256-GCM encrypted PostgreSQL credentials (PBKDF2 key derivation from platform password)
- AES-256-GCM encrypted S3 backup credentials (server-level encryption key)
- Per-tenant database isolation (separate PostgreSQL databases per project)
- Rate limiting on auth (5 req/s) and API (30 req/s) endpoints
- SQL injection prevention via parameterized queries throughout
- CORS whitelist with configurable allowed origins
- Request body size limits (1 MB for API, configurable for imports)
- Security headers (X-Frame-Options, X-Content-Type-Options, CSP, HSTS, Referrer-Policy, Permissions-Policy)
- Platform password verification required for sensitive operations (credential reveal, backup config)
- Admin-only API routes protected by middleware (`is_admin` check on every request)
- Registration control — admin can disable registration entirely or restrict to invite-only
- Invite codes with 72-hour expiry, single-use, optional email targeting
- Admin cannot delete themselves or other admins via the API
- Admin user auto-created from environment variables on startup (no default credentials shipped)
