-- Tally ERP — migration 011: hardening (Phase 10)
-- roles.mfa_required: role-level MFA policy flag. admin + auditor are
-- seeded as MFA-required roles (H-T2/H-T7). Enforcement is per-user
-- (users.mfa_required + totp_secret, Phase 0 columns): a role-required
-- user with no enrolled secret is NOT locked out — login reports
-- mfa_enrollment_required until enrollment completes, after which a
-- code is mandatory. Locking out the seeded admin (who has no secret
-- anywhere) would brick a fresh install with no recovery path.
-- sessions.break_glass: 1 for emergency break-glass sessions (1h
-- absolute lifetime, admin-only), so the session record itself flags
-- the emergency access.
-- break_glass_events: one row per break-glass login, with justification,
-- token-hash prefix (never the raw token), and review state. Events
-- are append-only in practice: review moves only the review columns
-- (trigger below), and nothing deletes them.

ALTER TABLE roles ADD COLUMN mfa_required INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN break_glass INTEGER NOT NULL DEFAULT 0;

CREATE TABLE break_glass_events (
  id                INTEGER PRIMARY KEY,
  user_id           INTEGER NOT NULL REFERENCES users(id),
  justification     TEXT NOT NULL CHECK (length(justification) >= 20),
  token_hash_prefix TEXT NOT NULL,
  session_id        INTEGER NULL REFERENCES sessions(id),
  created_at        TEXT NOT NULL,
  reviewed_at       TEXT NULL,
  reviewed_by       INTEGER NULL REFERENCES users(id),
  status            TEXT NOT NULL DEFAULT 'unreviewed'
                    CHECK (status IN ('unreviewed', 'reviewed'))
);

-- Review moves only review columns; justification / identity / timestamp
-- of the event itself are immutable. No DELETE trigger needed beyond the
-- audit-log pattern: break-glass events are evidence, never removed.
CREATE TRIGGER break_glass_events_review_only
BEFORE UPDATE ON break_glass_events
WHEN OLD.user_id IS NOT NEW.user_id
  OR OLD.justification IS NOT NEW.justification
  OR OLD.token_hash_prefix IS NOT NEW.token_hash_prefix
  OR OLD.session_id IS NOT NEW.session_id
  OR OLD.created_at IS NOT NEW.created_at
BEGIN
  SELECT RAISE(ABORT, 'break-glass events are immutable except for review');
END;

CREATE TRIGGER break_glass_events_no_delete
BEFORE DELETE ON break_glass_events
BEGIN
  SELECT RAISE(ABORT, 'break-glass events are never deleted');
END;

CREATE INDEX idx_break_glass_status ON break_glass_events(status);
CREATE INDEX idx_break_glass_user ON break_glass_events(user_id);
