-- Supabase-compatible auth schema for each project database
CREATE SCHEMA IF NOT EXISTS auth;

-- auth.users (GoTrue compatible)
CREATE TABLE IF NOT EXISTS auth.users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  instance_id UUID,
  aud VARCHAR(255) DEFAULT 'authenticated',
  role VARCHAR(255) DEFAULT 'authenticated',
  email VARCHAR(255) UNIQUE,
  encrypted_password VARCHAR(255),
  email_confirmed_at TIMESTAMPTZ,
  invited_at TIMESTAMPTZ,
  confirmation_token VARCHAR(255) DEFAULT '',
  confirmation_sent_at TIMESTAMPTZ,
  recovery_token VARCHAR(255) DEFAULT '',
  recovery_sent_at TIMESTAMPTZ,
  email_change_token_new VARCHAR(255) DEFAULT '',
  email_change VARCHAR(255) DEFAULT '',
  email_change_sent_at TIMESTAMPTZ,
  last_sign_in_at TIMESTAMPTZ,
  raw_app_meta_data JSONB DEFAULT '{"provider":"email","providers":["email"]}'::jsonb,
  raw_user_meta_data JSONB DEFAULT '{}'::jsonb,
  is_super_admin BOOLEAN,
  phone TEXT UNIQUE DEFAULT NULL,
  phone_confirmed_at TIMESTAMPTZ,
  phone_change TEXT DEFAULT '',
  phone_change_token VARCHAR(255) DEFAULT '',
  phone_change_sent_at TIMESTAMPTZ,
  confirmed_at TIMESTAMPTZ GENERATED ALWAYS AS (
    LEAST(email_confirmed_at, phone_confirmed_at)
  ) STORED,
  email_change_token_current VARCHAR(255) DEFAULT '',
  email_change_confirm_status SMALLINT DEFAULT 0,
  banned_until TIMESTAMPTZ,
  reauthentication_token VARCHAR(255) DEFAULT '',
  reauthentication_sent_at TIMESTAMPTZ,
  is_sso_user BOOLEAN NOT NULL DEFAULT FALSE,
  deleted_at TIMESTAMPTZ,
  is_anonymous BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_users_email ON auth.users(email);
CREATE INDEX IF NOT EXISTS idx_auth_users_instance_id ON auth.users(instance_id);

-- auth.sessions
CREATE TABLE IF NOT EXISTS auth.sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  factor_id UUID,
  aal VARCHAR(255) DEFAULT 'aal1',
  not_after TIMESTAMPTZ,
  refreshed_at TIMESTAMPTZ,
  user_agent TEXT,
  ip TEXT,
  tag TEXT
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth.sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_not_after ON auth.sessions(not_after);

-- auth.refresh_tokens
CREATE TABLE IF NOT EXISTS auth.refresh_tokens (
  id BIGSERIAL PRIMARY KEY,
  token VARCHAR(255) UNIQUE NOT NULL,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  parent VARCHAR(255),
  session_id UUID REFERENCES auth.sessions(id) ON DELETE CASCADE,
  revoked BOOLEAN DEFAULT FALSE,
  expires_at TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '7 days'),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_refresh_tokens_token ON auth.refresh_tokens(token);
CREATE INDEX IF NOT EXISTS idx_auth_refresh_tokens_session ON auth.refresh_tokens(session_id);
CREATE INDEX IF NOT EXISTS idx_auth_refresh_tokens_parent ON auth.refresh_tokens(parent);

-- auth.identities
CREATE TABLE IF NOT EXISTS auth.identities (
  provider_id TEXT NOT NULL,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  identity_data JSONB NOT NULL DEFAULT '{}'::jsonb,
  provider TEXT NOT NULL,
  last_sign_in_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  id UUID PRIMARY KEY DEFAULT gen_random_uuid()
);

CREATE INDEX IF NOT EXISTS idx_auth_identities_user ON auth.identities(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_identities_provider
  ON auth.identities(provider_id, provider);

-- auth.flow_state (PKCE flow)
CREATE TABLE IF NOT EXISTS auth.flow_state (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  auth_code VARCHAR(255) NOT NULL,
  code_challenge VARCHAR(255) NOT NULL,
  code_challenge_method VARCHAR(255) NOT NULL DEFAULT 's256',
  provider_type VARCHAR(255) NOT NULL DEFAULT 'email',
  provider_access_token TEXT,
  provider_refresh_token TEXT,
  authentication_method VARCHAR(255) NOT NULL DEFAULT 'email/password',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create RLS roles (idempotent)
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'anon') THEN
    CREATE ROLE anon NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'authenticated') THEN
    CREATE ROLE authenticated NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'service_role') THEN
    CREATE ROLE service_role NOLOGIN BYPASSRLS;
  END IF;
END $$;

-- Grant access on public schema to all roles
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;
GRANT ALL ON ALL TABLES IN SCHEMA public TO anon, authenticated, service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated, service_role;
GRANT ALL ON ALL ROUTINES IN SCHEMA public TO anon, authenticated, service_role;

ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON ROUTINES TO anon, authenticated, service_role;

-- Grant auth schema access to service_role only
GRANT USAGE ON SCHEMA auth TO service_role;
GRANT ALL ON ALL TABLES IN SCHEMA auth TO service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA auth TO service_role;

-- Create the auth.uid() function used in RLS policies
CREATE OR REPLACE FUNCTION auth.uid() RETURNS UUID AS $$
  SELECT NULLIF(current_setting('request.jwt.claim.sub', true), '')::UUID;
$$ LANGUAGE sql STABLE;

-- Create the auth.role() function used in RLS policies
CREATE OR REPLACE FUNCTION auth.role() RETURNS TEXT AS $$
  SELECT NULLIF(current_setting('request.jwt.claim.role', true), '');
$$ LANGUAGE sql STABLE;

-- Create auth.jwt() function to get full JWT claims
CREATE OR REPLACE FUNCTION auth.jwt() RETURNS JSONB AS $$
  SELECT NULLIF(current_setting('request.jwt.claims', true), '')::JSONB;
$$ LANGUAGE sql STABLE;

-- Enable RLS on auth tables to prevent cross-user data access
ALTER TABLE auth.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth.sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth.refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth.identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth.flow_state ENABLE ROW LEVEL SECURITY;

-- auth.users: authenticated users can only read their own row
CREATE POLICY users_self_read ON auth.users FOR SELECT
  TO authenticated USING (id = auth.uid());
CREATE POLICY users_self_update ON auth.users FOR UPDATE
  TO authenticated USING (id = auth.uid());

-- auth.sessions: users can only see their own sessions
CREATE POLICY sessions_self_read ON auth.sessions FOR SELECT
  TO authenticated USING (user_id = auth.uid());
CREATE POLICY sessions_self_delete ON auth.sessions FOR DELETE
  TO authenticated USING (user_id = auth.uid());

-- auth.refresh_tokens: users can only see their own tokens
CREATE POLICY refresh_tokens_self_read ON auth.refresh_tokens FOR SELECT
  TO authenticated USING (user_id = auth.uid());

-- auth.identities: users can only see their own identities
CREATE POLICY identities_self_read ON auth.identities FOR SELECT
  TO authenticated USING (user_id = auth.uid());

-- auth.flow_state: users can only see their own flow states
CREATE POLICY flow_state_self_read ON auth.flow_state FOR SELECT
  TO authenticated USING (user_id = auth.uid());

-- service_role bypasses RLS (BYPASSRLS is set on the role)
-- anon has no access to auth tables (no GRANT, no policies)
