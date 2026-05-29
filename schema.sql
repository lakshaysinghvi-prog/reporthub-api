-- ============================================================
-- ReportHub Database Schema
-- Paste this ENTIRE file into Supabase SQL Editor and click Run
-- ============================================================

-- Users table
CREATE TABLE IF NOT EXISTS rh_users (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username    TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role        TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin','user')),
  created_at  TIMESTAMPTZ DEFAULT now()
);

-- Reports metadata
CREATE TABLE IF NOT EXISTS rh_reports (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name         TEXT NOT NULL,
  config       JSONB NOT NULL,
  card_fields  JSONB DEFAULT '[]',
  num_fields   JSONB DEFAULT '[]',
  is_published BOOLEAN DEFAULT false,
  row_count    INT DEFAULT 0,
  field_count  INT DEFAULT 0,
  created_by   UUID REFERENCES rh_users(id),
  created_at   TIMESTAMPTZ DEFAULT now()
);

-- Field list per report
CREATE TABLE IF NOT EXISTS rh_datasets (
  id        BIGSERIAL PRIMARY KEY,
  report_id UUID REFERENCES rh_reports(id) ON DELETE CASCADE,
  fields    JSONB NOT NULL
);

-- Data rows (each row stored as JSON)
CREATE TABLE IF NOT EXISTS rh_rows (
  id        BIGSERIAL PRIMARY KEY,
  report_id UUID REFERENCES rh_reports(id) ON DELETE CASCADE,
  row_data  JSONB NOT NULL
);

-- Index for fast row retrieval by report
CREATE INDEX IF NOT EXISTS idx_rh_rows_report ON rh_rows(report_id);

-- ── Create default admin user (password: admin123) ────────────────────────────
-- bcrypt hash of "admin123" with cost factor 10
INSERT INTO rh_users (username, password_hash, role)
VALUES ('admin', '$2b$10$rOzMhBuVeHNqcWFMfR7VIeB5.5nFzQ1UJL0G1dKVPuF7oFRWt9zJ6', 'admin')
ON CONFLICT (username) DO NOTHING;

-- Create a default viewer user (password: view123)
INSERT INTO rh_users (username, password_hash, role)
VALUES ('viewer', '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p33zBOgEeyULTsGFBNwOlS', 'user')
ON CONFLICT (username) DO NOTHING;

-- ── Verify setup ─────────────────────────────────────────────────────────────
SELECT 'Tables created successfully' as status;
SELECT username, role, created_at FROM rh_users;

-- ── OAuth tokens (for Microsoft Graph + Google Drive API access) ─────────────
CREATE TABLE IF NOT EXISTS rh_oauth_tokens (
  id           BIGSERIAL PRIMARY KEY,
  user_id      UUID REFERENCES rh_users(id) ON DELETE CASCADE,
  provider     TEXT NOT NULL CHECK (provider IN ('microsoft','google')),
  access_token TEXT NOT NULL,
  refresh_token TEXT,
  expires_at   TIMESTAMPTZ,
  token_data   JSONB DEFAULT '{}',
  created_at   TIMESTAMPTZ DEFAULT now(),
  updated_at   TIMESTAMPTZ DEFAULT now(),
  UNIQUE (user_id, provider)
);
CREATE INDEX IF NOT EXISTS idx_rh_oauth_user ON rh_oauth_tokens(user_id);

-- ── Permission system additions ────────────────────────────────────────────────

-- Add subadmin role if not present (alter the check constraint)
DO $$ BEGIN
  ALTER TABLE rh_users DROP CONSTRAINT IF EXISTS rh_users_role_check;
  ALTER TABLE rh_users ADD CONSTRAINT rh_users_role_check
    CHECK (role IN ('admin','subadmin','user'));
EXCEPTION WHEN others THEN NULL; END $$;

-- created_by on reports
ALTER TABLE rh_reports ADD COLUMN IF NOT EXISTS created_by UUID REFERENCES rh_users(id) ON DELETE SET NULL;

-- Report access control table
CREATE TABLE IF NOT EXISTS rh_report_access (
  report_id UUID NOT NULL REFERENCES rh_reports(id) ON DELETE CASCADE,
  user_id   UUID NOT NULL REFERENCES rh_users(id)   ON DELETE CASCADE,
  granted_at TIMESTAMPTZ DEFAULT now(),
  PRIMARY KEY (report_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_rra_user ON rh_report_access(user_id);
CREATE INDEX IF NOT EXISTS idx_rra_report ON rh_report_access(report_id);

-- ── Phase 2: User approval status ────────────────────────────────────────────
DO $$ BEGIN
  ALTER TABLE rh_users ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active';
  -- Add constraint only if it doesn't exist
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'rh_users_status_check'
  ) THEN
    ALTER TABLE rh_users ADD CONSTRAINT rh_users_status_check
      CHECK (status IN ('active', 'pending'));
  END IF;
EXCEPTION WHEN others THEN NULL; END $$;

-- ── Phase 2: subadmin_user role ────────────────────────────────────────────────
DO $$ BEGIN
  ALTER TABLE rh_users DROP CONSTRAINT IF EXISTS rh_users_role_check;
  ALTER TABLE rh_users ADD CONSTRAINT rh_users_role_check
    CHECK (role IN ('admin','subadmin','user','subadmin_user'));
EXCEPTION WHEN others THEN NULL; END $$;

-- ── Phase 2: Auto-refresh schedule ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rh_refresh_schedules (
  report_id        UUID PRIMARY KEY REFERENCES rh_reports(id) ON DELETE CASCADE,
  interval_minutes INT NOT NULL DEFAULT 0,
  enabled          BOOLEAN DEFAULT false,
  last_run         TIMESTAMPTZ,
  next_run         TIMESTAMPTZ,
  updated_at       TIMESTAMPTZ DEFAULT now()
);

-- ── Custom OAuth app credentials (per-instance, replaces env vars) ─────────────
CREATE TABLE IF NOT EXISTS rh_custom_credentials (
  id           SERIAL PRIMARY KEY,
  provider     TEXT NOT NULL CHECK (provider IN ('microsoft','google')),
  client_id    TEXT NOT NULL,
  client_secret TEXT NOT NULL,
  tenant_id    TEXT,          -- Microsoft only: tenant ID or 'common'
  extra        JSONB DEFAULT '{}',
  updated_at   TIMESTAMPTZ DEFAULT now(),
  updated_by   UUID REFERENCES rh_users(id),
  UNIQUE (provider)
);
