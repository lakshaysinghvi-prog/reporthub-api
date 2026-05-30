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

-- ── Phase 3: Collaborative Workflow ──────────────────────────────────────────────

-- Enable collab mode per report
ALTER TABLE rh_reports ADD COLUMN IF NOT EXISTS collab_enabled BOOLEAN DEFAULT false;

-- Collab column definitions (builder defines extra columns for collaboration)
CREATE TABLE IF NOT EXISTS rh_collab_columns (
  id            BIGSERIAL PRIMARY KEY,
  report_id     UUID NOT NULL REFERENCES rh_reports(id) ON DELETE CASCADE,
  label         TEXT NOT NULL,
  col_type      TEXT NOT NULL DEFAULT 'input' CHECK (col_type IN ('input','workflow')),
  inputter_ids  JSONB DEFAULT '[]',   -- user UUIDs who can input
  reviewer_ids  JSONB DEFAULT '[]',   -- user UUIDs who can approve/reject/hold (workflow type only)
  ref_column    TEXT,                  -- optional: name of a data column for reference display
  col_order     INT DEFAULT 0,
  created_at    TIMESTAMPTZ DEFAULT now(),
  updated_at    TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_rcc_report ON rh_collab_columns(report_id);

-- Collab cycles (monthly periods — only one open at a time per report)
CREATE TABLE IF NOT EXISTS rh_collab_cycles (
  id                  BIGSERIAL PRIMARY KEY,
  report_id           UUID NOT NULL REFERENCES rh_reports(id) ON DELETE CASCADE,
  period_label        TEXT NOT NULL,    -- e.g. "May 2026"
  status              TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed')),
  history_viewer_ids  JSONB DEFAULT '[]',  -- users who can see this cycle in History
  opened_by           UUID REFERENCES rh_users(id),
  closed_by           UUID REFERENCES rh_users(id),
  closed_at           TIMESTAMPTZ,
  created_at          TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_rcyc_report ON rh_collab_cycles(report_id);

-- Collab cell values (one row per data-row × collab-column × cycle)
CREATE TABLE IF NOT EXISTS rh_collab_values (
  id               BIGSERIAL PRIMARY KEY,
  cycle_id         BIGINT NOT NULL REFERENCES rh_collab_cycles(id) ON DELETE CASCADE,
  report_id        UUID NOT NULL REFERENCES rh_reports(id) ON DELETE CASCADE,
  row_key          TEXT NOT NULL,      -- value of the builder-designated key column
  col_id           BIGINT NOT NULL REFERENCES rh_collab_columns(id) ON DELETE CASCADE,
  value            NUMERIC,            -- the input value (default 0 = not stored)
  remarks          TEXT,               -- inputter remarks
  status           TEXT NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending','submitted','approved','rejected','hold')),
  inputter_id      UUID REFERENCES rh_users(id),
  reviewer_id      UUID REFERENCES rh_users(id),
  reviewer_remarks TEXT,
  reviewed_at      TIMESTAMPTZ,
  updated_at       TIMESTAMPTZ DEFAULT now(),
  UNIQUE (cycle_id, row_key, col_id)
);
CREATE INDEX IF NOT EXISTS idx_rcv_cycle ON rh_collab_values(cycle_id);
CREATE INDEX IF NOT EXISTS idx_rcv_rowkey ON rh_collab_values(cycle_id, row_key);

-- Immutable audit log (every save/submit/approve/reject/hold action)
CREATE TABLE IF NOT EXISTS rh_collab_audit (
  id         BIGSERIAL PRIMARY KEY,
  cycle_id   BIGINT NOT NULL REFERENCES rh_collab_cycles(id) ON DELETE CASCADE,
  report_id  UUID NOT NULL REFERENCES rh_reports(id) ON DELETE CASCADE,
  row_key    TEXT NOT NULL,
  col_id     BIGINT REFERENCES rh_collab_columns(id) ON DELETE SET NULL,
  actor_id   UUID REFERENCES rh_users(id),
  action     TEXT NOT NULL,   -- 'save'|'submit'|'approved'|'rejected'|'hold'
  value      NUMERIC,
  remarks    TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_rca_cycle ON rh_collab_audit(cycle_id);
CREATE INDEX IF NOT EXISTS idx_rca_rowkey ON rh_collab_audit(cycle_id, row_key);
