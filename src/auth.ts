// Tally ERP — auth.ts
// argon2id passwords (Bun.password), failed-login lockout with backoff,
// bearer sessions with 15-min idle timeout (sliding last_seen_at) + 12-h
// absolute max. Tokens are stored as sha256 hashes — the raw token is shown
// exactly once, at login.

import type { Database } from "bun:sqlite";
import { randomBytes } from "node:crypto";
import { appendAudit } from "./audit";
import { sha256HexSync } from "./crypto";
import { nowIso } from "./db";

export interface SessionConfig {
  idleTimeoutMs: number; // H-T3 automatic logoff (addressable — implemented)
  absoluteMaxMs: number;
  maxFailedLogins: number;
  lockoutBaseMinutes: number;
  lockoutMaxMinutes: number;
}

export function sessionConfigFromEnv(): SessionConfig {
  return {
    idleTimeoutMs: parseInt(process.env.TALLY_IDLE_TIMEOUT_MS ?? String(15 * 60 * 1000), 10),
    absoluteMaxMs: parseInt(process.env.TALLY_ABSOLUTE_MAX_MS ?? String(12 * 60 * 60 * 1000), 10),
    maxFailedLogins: 5,
    lockoutBaseMinutes: 5,
    lockoutMaxMinutes: 60,
  };
}

export interface UserRow {
  id: number;
  email: string;
  pw_hash: string;
  role_id: number;
  role_name: string;
  totp_secret: string | null;
  mfa_required: number;
  must_change_pw: number;
  disabled_at: string | null;
  failed_logins: number;
  locked_until: string | null;
}

export interface SessionRow {
  id: number;
  user_id: number;
  token_hash: string;
  created_at: string;
  expires_at: string;
  last_seen_at: string;
}

// --- password policy (H-A3) -------------------------------------------------

const COMMON_PASSWORDS = new Set(
  [
    "password", "password1", "password123", "password1234", "changeme", "changeme123",
    "letmein", "letmein123", "welcome", "welcome1", "welcome123", "qwerty", "qwerty123",
    "admin", "admin123", "administrator", "123456", "12345678", "123456789",
    "1234567890", "abc123", "111111", "iloveyou", "monkey", "dragon", "master",
    "sunshine", "princess", "football", "company", "company123", "tally", "tally123",
    "passw0rd", "p@ssw0rd", "p@ssword", "trustno1",
  ].map((s) => s.toLowerCase()),
);

export function validatePassword(pw: string): { ok: true } | { ok: false; reason: string } {
  if (typeof pw !== "string" || pw.length < 12) {
    return { ok: false, reason: "password must be at least 12 characters" };
  }
  if (COMMON_PASSWORDS.has(pw.toLowerCase())) {
    return { ok: false, reason: "password is too common" };
  }
  if (!/[a-zA-Z]/.test(pw) || !/[0-9]/.test(pw)) {
    return { ok: false, reason: "password must contain a letter and a digit" };
  }
  return { ok: true };
}

export async function hashPassword(pw: string): Promise<string> {
  const v = validatePassword(pw);
  if (!v.ok) throw new Error(`weak password: ${v.reason}`);
  return Bun.password.hash(pw); // argon2id
}

// --- user lookups -----------------------------------------------------------

export function getUserByEmail(db: Database, email: string): UserRow | null {
  return db
    .query(
      `SELECT u.*, r.name AS role_name FROM users u
       JOIN roles r ON r.id = u.role_id WHERE u.email = ?`,
    )
    .get(email.toLowerCase().trim()) as UserRow | null;
}

export function getUserById(db: Database, id: number): UserRow | null {
  return db
    .query(
      `SELECT u.*, r.name AS role_name FROM users u
       JOIN roles r ON r.id = u.role_id WHERE u.id = ?`,
    )
    .get(id) as UserRow | null;
}

function lockoutMinutes(failedLogins: number, cfg: SessionConfig): number {
  // exponential backoff from the threshold, capped
  const steps = Math.max(0, failedLogins - cfg.maxFailedLogins);
  return Math.min(cfg.lockoutBaseMinutes * 2 ** steps, cfg.lockoutMaxMinutes);
}

// --- login / logout ---------------------------------------------------------

export type LoginResult =
  | { ok: true; token: string; expires_at: string; must_change_password: boolean; user: UserRow }
  | { ok: false; code: "invalid_credentials" | "account_locked" | "validation"; message: string };

export async function login(
  db: Database,
  email: string,
  password: string,
  opts: { ip?: string | null; userAgent?: string | null },
  cfg: SessionConfig,
): Promise<LoginResult> {
  if (!email || !password) {
    return { ok: false, code: "validation", message: "email and password are required" };
  }
  const user = getUserByEmail(db, email);
  const now = Date.now();

  const recordFailure = (u: UserRow | null, reason: string, code: "invalid_credentials" | "account_locked") =>
    db.transaction(() => {
      if (u) {
        const failed = u.failed_logins + 1;
        let locked_until: string | null = u.locked_until;
        if (failed >= cfg.maxFailedLogins) {
          locked_until = new Date(now + lockoutMinutes(failed, cfg) * 60 * 1000).toISOString();
        }
        db.query("UPDATE users SET failed_logins = ?, locked_until = ?, updated_at = ? WHERE id = ?").run(
          failed,
          locked_until,
          nowIso(),
          u.id,
        );
      }
      appendAudit(db, {
        actor_id: u?.id ?? null,
        action: code === "account_locked" ? "auth.locked" : "auth.login_failed",
        entity_type: "user",
        entity_id: u?.id ?? email.toLowerCase().trim(),
        after: { reason }, // never the password
      });
    })();

  if (!user) {
    recordFailure(null, "unknown_email", "invalid_credentials");
    return { ok: false, code: "invalid_credentials", message: "invalid email or password" };
  }
  if (user.disabled_at) {
    recordFailure(user, "disabled", "invalid_credentials");
    return { ok: false, code: "invalid_credentials", message: "invalid email or password" };
  }
  if (user.locked_until && Date.parse(user.locked_until) > now) {
    recordFailure(user, "locked", "account_locked");
    return { ok: false, code: "account_locked", message: "account temporarily locked after too many failed logins" };
  }

  const pwOk = await Bun.password.verify(password, user.pw_hash);
  if (!pwOk) {
    recordFailure(user, "bad_password", "invalid_credentials");
    return { ok: false, code: "invalid_credentials", message: "invalid email or password" };
  }

  const token = randomBytes(32).toString("hex");
  const tokenHash = sha256HexSync(token);
  // timestamp at issuance, not at request start: password verification
  // (argon2) takes ~150ms, and the idle clock must start when the session
  // is actually created (H-T3).
  const issuedAt = Date.now();
  const createdAt = new Date(issuedAt).toISOString();
  const expiresAt = new Date(issuedAt + cfg.absoluteMaxMs).toISOString();

  db.transaction(() => {
    db.query("UPDATE users SET failed_logins = 0, locked_until = NULL, updated_at = ? WHERE id = ?").run(
      nowIso(),
      user.id,
    );
    db.query(
      `INSERT INTO sessions (user_id, token_hash, created_at, expires_at, last_seen_at, ip, user_agent)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).run(user.id, tokenHash, createdAt, expiresAt, createdAt, opts.ip ?? null, opts.userAgent ?? null);
    appendAudit(db, {
      actor_id: user.id,
      action: "auth.login",
      entity_type: "session",
      entity_id: tokenHash.slice(0, 16), // token hash prefix only — never the raw token
      after: { ip: opts.ip ?? null },
    });
  })();

  return {
    ok: true,
    token,
    expires_at: expiresAt,
    must_change_password: user.must_change_pw === 1,
    user,
  };
}

export function logout(db: Database, token: string): boolean {
  const tokenHash = sha256HexSync(token);
  const session = db.query("SELECT id, user_id FROM sessions WHERE token_hash = ?").get(tokenHash) as {
    id: number;
    user_id: number;
  } | null;
  if (!session) return false;
  db.transaction(() => {
    db.query("DELETE FROM sessions WHERE id = ?").run(session.id);
    appendAudit(db, {
      actor_id: session.user_id,
      action: "auth.logout",
      entity_type: "session",
      entity_id: tokenHash.slice(0, 16),
    });
  })();
  return true;
}

// --- request authentication -------------------------------------------------

export type AuthResult =
  | { ok: true; user: UserRow; session: SessionRow }
  | { ok: false; code: "unauthorized" | "session_expired"; message: string };

export function authenticate(db: Database, token: string | null, cfg: SessionConfig): AuthResult {
  if (!token) return { ok: false, code: "unauthorized", message: "missing bearer token" };
  const tokenHash = sha256HexSync(token);
  const session = db.query("SELECT * FROM sessions WHERE token_hash = ?").get(tokenHash) as SessionRow | null;
  if (!session) return { ok: false, code: "unauthorized", message: "invalid or revoked session" };

  const now = Date.now();
  const expire = (code: "session_expired", message: string) => {
    db.transaction(() => {
      db.query("DELETE FROM sessions WHERE id = ?").run(session.id);
      appendAudit(db, {
        actor_id: session.user_id,
        action: "auth.session_expired",
        entity_type: "session",
        entity_id: tokenHash.slice(0, 16),
        after: { reason: message },
      });
    })();
    return { ok: false as const, code, message };
  };

  if (now > Date.parse(session.expires_at)) {
    return expire("session_expired", "absolute session lifetime exceeded");
  }
  if (now - Date.parse(session.last_seen_at) > cfg.idleTimeoutMs) {
    return expire("session_expired", "session expired due to inactivity");
  }

  const user = getUserById(db, session.user_id);
  if (!user || user.disabled_at) {
    db.query("DELETE FROM sessions WHERE id = ?").run(session.id);
    return { ok: false, code: "unauthorized", message: "account disabled" };
  }

  // sliding window: successful request refreshes last_seen_at (H-T3)
  db.query("UPDATE sessions SET last_seen_at = ? WHERE id = ?").run(new Date(now).toISOString(), session.id);

  return { ok: true, user, session };
}
