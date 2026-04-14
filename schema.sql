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
