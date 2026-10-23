-- Tally ERP — migration 001: compliance spine (Phase 0)
-- users / roles / sessions / hash-chained audit_log / retention policies

CREATE TABLE roles (
  id   INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);

CREATE TABLE role_permissions (
  role_id  INTEGER NOT NULL REFERENCES roles(id),
  resource TEXT    NOT NULL,
  action   TEXT    NOT NULL,
  PRIMARY KEY (role_id, resource, action)
);

CREATE TABLE users (
  id             INTEGER PRIMARY KEY,
  email          TEXT NOT NULL UNIQUE,
  pw_hash        TEXT NOT NULL,
  role_id        INTEGER NOT NULL REFERENCES roles(id),
  totp_secret    TEXT NULL,
  mfa_required   INTEGER NOT NULL DEFAULT 0,
  must_change_pw INTEGER NOT NULL DEFAULT 0,
  disabled_at    TEXT NULL,
  failed_logins  INTEGER NOT NULL DEFAULT 0,
  locked_until   TEXT NULL,
  created_at     TEXT NOT NULL,
  updated_at     TEXT NOT NULL,
  created_by     INTEGER NULL REFERENCES users(id)
);

CREATE TABLE sessions (
  id          INTEGER PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id),
  token_hash  TEXT NOT NULL UNIQUE,
  created_at  TEXT NOT NULL,
  expires_at  TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  ip          TEXT NULL,
  user_agent  TEXT NULL
);

CREATE TABLE audit_log (
  id          INTEGER PRIMARY KEY,
  seq         INTEGER NOT NULL UNIQUE,
  ts          TEXT NOT NULL,
  actor_id    INTEGER NULL,
  action      TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id   TEXT NULL,
  before_json TEXT NULL,
  after_json  TEXT NULL,
  prev_hash   TEXT NOT NULL,
  hash        TEXT NOT NULL
);

-- Append-only enforcement: no UPDATE, no DELETE on audit_log, ever.
CREATE TRIGGER audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE rejected');
END;

CREATE TRIGGER audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only: DELETE rejected');
END;

CREATE TABLE retention_policies (
  entity_type TEXT PRIMARY KEY,
  years       INTEGER NOT NULL
);

CREATE INDEX idx_users_email    ON users(email);
CREATE INDEX idx_sessions_token ON sessions(token_hash);
CREATE INDEX idx_sessions_user  ON sessions(user_id);
CREATE INDEX idx_audit_ts      ON audit_log(ts);
CREATE INDEX idx_audit_action  ON audit_log(action);
CREATE INDEX idx_audit_entity  ON audit_log(entity_type, entity_id);
