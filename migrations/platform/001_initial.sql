-- Platform schema for SaaS management
CREATE SCHEMA IF NOT EXISTS platform;

-- Platform users (SaaS users who manage databases)
CREATE TABLE IF NOT EXISTS platform.users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  display_name TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_platform_users_email ON platform.users(email);

-- PostgreSQL roles mapped to platform users
-- One PG user per platform user, shared across all their databases
CREATE TABLE IF NOT EXISTS platform.pg_users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL UNIQUE REFERENCES platform.users(id) ON DELETE CASCADE,
  pg_username TEXT NOT NULL UNIQUE,
  pg_password_hash TEXT NOT NULL,
  pg_password_encrypted TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Projects (each project = one database)
CREATE TABLE IF NOT EXISTS platform.projects (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES platform.users(id) ON DELETE CASCADE,
  pg_user_id UUID NOT NULL REFERENCES platform.pg_users(id),
  name TEXT NOT NULL,
  db_name TEXT NOT NULL UNIQUE,
  region TEXT NOT NULL DEFAULT 'local',

  -- Per-project Supabase settings
  jwt_secret TEXT NOT NULL,
  anon_key TEXT NOT NULL,
  service_role_key TEXT NOT NULL,

  -- Per-project auth settings
  enable_signup BOOLEAN NOT NULL DEFAULT TRUE,
  autoconfirm BOOLEAN NOT NULL DEFAULT TRUE,
  password_min_length INTEGER NOT NULL DEFAULT 6,
  site_url TEXT NOT NULL DEFAULT 'http://localhost:3000',

  status TEXT NOT NULL DEFAULT 'creating'
    CHECK (status IN ('creating', 'active', 'paused', 'deleting', 'deleted')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  UNIQUE(user_id, name)
);

CREATE INDEX IF NOT EXISTS idx_platform_projects_user ON platform.projects(user_id);
CREATE INDEX IF NOT EXISTS idx_platform_projects_db ON platform.projects(db_name);
CREATE INDEX IF NOT EXISTS idx_platform_projects_status ON platform.projects(status);

-- Audit log for security-relevant platform events
CREATE TABLE IF NOT EXISTS platform.audit_log (
  id BIGSERIAL PRIMARY KEY,
  user_id UUID REFERENCES platform.users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  resource_type TEXT,
  resource_id TEXT,
  ip_address TEXT,
  user_agent TEXT,
  metadata JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_platform_audit_log_user ON platform.audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_platform_audit_log_action ON platform.audit_log(action);
CREATE INDEX IF NOT EXISTS idx_platform_audit_log_created ON platform.audit_log(created_at);

-- S3 backup settings (one per user)
CREATE TABLE IF NOT EXISTS platform.backup_settings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL UNIQUE REFERENCES platform.users(id) ON DELETE CASCADE,
  s3_endpoint TEXT NOT NULL,
  s3_region TEXT NOT NULL DEFAULT 'us-east-1',
  s3_bucket TEXT NOT NULL,
  s3_access_key_encrypted TEXT NOT NULL,
  s3_secret_key_encrypted TEXT NOT NULL,
  s3_path_prefix TEXT NOT NULL DEFAULT '',
  schedule TEXT NOT NULL DEFAULT 'daily',
  retention_days INTEGER NOT NULL DEFAULT 30,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Backup history log
CREATE TABLE IF NOT EXISTS platform.backup_history (
  id BIGSERIAL PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES platform.users(id) ON DELETE CASCADE,
  project_id UUID NOT NULL REFERENCES platform.projects(id) ON DELETE CASCADE,
  db_name TEXT NOT NULL,
  s3_key TEXT NOT NULL,
  size_bytes BIGINT,
  status TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'completed', 'failed')),
  error_message TEXT,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_backup_history_user ON platform.backup_history(user_id);
CREATE INDEX IF NOT EXISTS idx_backup_history_status ON platform.backup_history(status);
