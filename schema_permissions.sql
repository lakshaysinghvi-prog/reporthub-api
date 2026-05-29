-- ── Permission system migration ───────────────────────────────────────────────
-- Run this in Supabase SQL Editor

-- 1. Add subadmin role to rh_users (if not already)
DO $$
BEGIN
  ALTER TABLE rh_users DROP CONSTRAINT IF EXISTS rh_users_role_check;
  ALTER TABLE rh_users ADD CONSTRAINT rh_users_role_check
    CHECK (role IN ('admin','subadmin','user'));
END$$;

-- 2. Report access table: controls which users see which report
-- Empty = all users can see it (legacy reports stay visible)
CREATE TABLE IF NOT EXISTS rh_report_access (
  report_id UUID NOT NULL REFERENCES rh_reports(id) ON DELETE CASCADE,
  user_id   UUID NOT NULL REFERENCES rh_users(id)   ON DELETE CASCADE,
  PRIMARY KEY (report_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_rh_ra_report ON rh_report_access(report_id);
CREATE INDEX IF NOT EXISTS idx_rh_ra_user   ON rh_report_access(user_id);

-- 3. Ensure rh_reports has created_by column
ALTER TABLE rh_reports ADD COLUMN IF NOT EXISTS created_by UUID REFERENCES rh_users(id);

-- Done ─────────────────────────────────────────────────────────────────────────
