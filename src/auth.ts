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
import { verifyTotp } from "./totp";

export interface SessionConfig {
  idleTimeoutMs: number; // H-T3 automatic logoff (addressable — implemented)
  absoluteMaxMs: number;
  maxFailedLogins: number;
  lockoutBaseMinutes: number;
  lockoutMaxMinutes: number;
  /** Auth-attempt rate limit (login + break-glass), per IP per minute. */
  authRateLimitPerMinute: number;
}

export function sessionConfigFromEnv(): SessionConfig {
  return {
    idleTimeoutMs: parseInt(process.env.TALLY_IDLE_TIMEOUT_MS ?? String(15 * 60 * 1000), 10),
    absoluteMaxMs: parseInt(process.env.TALLY_ABSOLUTE_MAX_MS ?? String(12 * 60 * 60 * 1000), 10),
    maxFailedLogins: 5,
    lockoutBaseMinutes: 5,
    lockoutMaxMinutes: 60,
    authRateLimitPerMinute: parseInt(process.env.TALLY_AUTH_RATE_LIMIT ?? "20", 10) || 20,
  };
}

export interface UserRow {
  id: number;
  email: string;
  pw_hash: string;
  role_id: number;
  role_name: string;
  /** Phase 10: role-level MFA policy flag (roles.mfa_required, 011). */
  role_mfa_required?: number;
  /** Phase 7: supervisory-principal flag (users.is_principal, 008). */
  is_principal?: number;
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
  /** Phase 10: 1 for break-glass sessions. */
  break_glass?: number;
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
      `SELECT u.*, r.name AS role_name, r.mfa_required AS role_mfa_required FROM users u
       JOIN roles r ON r.id = u.role_id WHERE u.email = ?`,
    )
    .get(email.toLowerCase().trim()) as UserRow | null;
}

export function getUserById(db: Database, id: number): UserRow | null {
  return db
    .query(
      `SELECT u.*, r.name AS role_name, r.mfa_required AS role_mfa_required FROM users u
       JOIN roles r ON r.id = u.role_id WHERE u.id = ?`,
    )
    .get(id) as UserRow | null;
}

/**
 * Phase 10 MFA policy (H-T2/H-T7). Effective MFA for a user:
 *   user.mfa_required = 1 (set on TOTP confirm) OR their role is
 *   MFA-required (roles.mfa_required, seeded for admin + auditor).
 * Enforcement bites only once a secret exists: a role-required user
 * with no secret is in the enrollment window — login succeeds and
 * reports mfa_enrollment_required (see login()), because locking out
 * a user who has no secret anywhere would brick the account. Once a
 * secret exists, a valid code is mandatory and no session is issued
 * without one.
 */
export function mfaPolicyRequired(user: UserRow): boolean {
  return user.mfa_required === 1 || user.role_mfa_required === 1;
}

export function mfaEnforced(user: UserRow): boolean {
  return mfaPolicyRequired(user) && user.totp_secret !== null && user.totp_secret !== "";
}

function lockoutMinutes(failedLogins: number, cfg: SessionConfig): number {
  // exponential backoff from the threshold, capped
  const steps = Math.max(0, failedLogins - cfg.maxFailedLogins);
  return Math.min(cfg.lockoutBaseMinutes * 2 ** steps, cfg.lockoutMaxMinutes);
}

// --- login / logout ---------------------------------------------------------

export type LoginResult =
  | {
      ok: true;
      token: string;
      expires_at: string;
      must_change_password: boolean;
      mfa_enrollment_required: boolean;
      user: UserRow;
    }
  | {
      ok: false;
      code:
        | "invalid_credentials"
        | "account_locked"
        | "validation"
        | "totp_required"
        | "totp_invalid";
      message: string;
    };

/** Shared failed-login recording (lockout backoff + audit, never the password). */
function recordLoginFailure(
  db: Database,
  email: string,
  user: UserRow | null,
  reason: string,
  code: "invalid_credentials" | "account_locked",
  cfg: SessionConfig,
  now: number,
): void {
  db.transaction(() => {
    if (user) {
      const failed = user.failed_logins + 1;
      let locked_until: string | null = user.locked_until;
      if (failed >= cfg.maxFailedLogins) {
        locked_until = new Date(now + lockoutMinutes(failed, cfg) * 60 * 1000).toISOString();
      }
      db.query("UPDATE users SET failed_logins = ?, locked_until = ?, updated_at = ? WHERE id = ?").run(
        failed,
        locked_until,
        nowIso(),
        user.id,
      );
    }
    appendAudit(db, {
      actor_id: user?.id ?? null,
      action: code === "account_locked" ? "auth.locked" : "auth.login_failed",
      entity_type: "user",
      entity_id: user?.id ?? email.toLowerCase().trim(),
      after: { reason }, // never the password
    });
  })();
}

export async function login(
  db: Database,
  email: string,
  password: string,
  opts: { ip?: string | null; userAgent?: string | null; totpCode?: string | null },
  cfg: SessionConfig,
): Promise<LoginResult> {
  if (!email || !password) {
    return { ok: false, code: "validation", message: "email and password are required" };
  }
  const user = getUserByEmail(db, email);
  const now = Date.now();

  const recordFailure = (u: UserRow | null, reason: string, code: "invalid_credentials" | "account_locked") =>
    recordLoginFailure(db, email, u, reason, code, cfg, now);

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

  // Phase 10 MFA gate: enforced users need a valid code, and a
  // password-only login issues NO session (H-T7).
  if (mfaEnforced(user)) {
    if (!opts.totpCode) {
      db.transaction(() => {
        appendAudit(db, {
          actor_id: user.id,
          action: "auth.totp_required",
          entity_type: "user",
          entity_id: user.id,
          after: { reason: "totp_code_missing" }, // never the code
        });
      })();
      return { ok: false, code: "totp_required", message: "a TOTP code is required for this account" };
    }
    if (!verifyTotp(user.totp_secret!, opts.totpCode)) {
      recordFailure(user, "bad_totp", "invalid_credentials");
      return { ok: false, code: "totp_invalid", message: "invalid TOTP code" };
    }
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
    // Role-required but not yet enrolled: prompt enrollment, do not block.
    mfa_enrollment_required: mfaPolicyRequired(user) && !mfaEnforced(user),
    user,
  };
}

// --- break-glass ------------------------------------------------------------
// Phase 10 emergency access (H-A4, F-R5): admin-role users ONLY, with a
// written justification (>= 20 chars). Issues a 1-hour absolute session
// flagged break_glass, inserts a break_glass_events row, and audits
// auth.break_glass — all in one transaction. The event surfaces in the
// compliance dashboard until a principal/admin reviews it. Break-glass
// does NOT bypass password, lockout, or disabled checks, and does NOT
// bypass MFA for an enrolled user: an enrolled admin must still supply
// a valid TOTP code (emergency access is supervised, not a backdoor).

export const BREAK_GLASS_SESSION_MS = 60 * 60 * 1000;
export const BREAK_GLASS_MIN_JUSTIFICATION = 20;

export interface BreakGlassEventRow {
  id: number;
  user_id: number;
  justification: string;
  token_hash_prefix: string;
  session_id: number | null;
  created_at: string;
  reviewed_at: string | null;
  reviewed_by: number | null;
  status: string;
}

export type BreakGlassResult =
  | { ok: true; token: string; expires_at: string; event_id: number; user: UserRow }
  | {
      ok: false;
      code:
        | "invalid_credentials"
        | "account_locked"
        | "validation"
        | "forbidden"
        | "totp_required"
        | "totp_invalid";
      message: string;
    };

export async function breakGlassLogin(
  db: Database,
  email: string,
  password: string,
  justification: string,
  opts: { ip?: string | null; userAgent?: string | null; totpCode?: string | null },
  cfg: SessionConfig,
): Promise<BreakGlassResult> {
  if (!email || !password) {
    return { ok: false, code: "validation", message: "email and password are required" };
  }
  if (typeof justification !== "string" || justification.trim().length < BREAK_GLASS_MIN_JUSTIFICATION) {
    return {
      ok: false,
      code: "validation",
      message: `justification must be at least ${BREAK_GLASS_MIN_JUSTIFICATION} characters`,
    };
  }
  const user = getUserByEmail(db, email);
  const now = Date.now();
  const recordFailure = (u: UserRow | null, reason: string, code: "invalid_credentials" | "account_locked") =>
    recordLoginFailure(db, email, u, reason, code, cfg, now);

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
  // Admin-role only — checked AFTER password verification so the
  // endpoint does not enumerate which emails are admins.
  if (user.role_name !== "admin") {
    db.transaction(() => {
      appendAudit(db, {
        actor_id: user.id,
        action: "auth.break_glass_denied",
        entity_type: "user",
        entity_id: user.id,
        after: { reason: "not_admin" },
      });
    })();
    return { ok: false, code: "forbidden", message: "break-glass access is restricted to administrators" };
  }
  if (mfaEnforced(user)) {
    if (!opts.totpCode) {
      return { ok: false, code: "totp_required", message: "a TOTP code is required for this account" };
    }
    if (!verifyTotp(user.totp_secret!, opts.totpCode)) {
      recordFailure(user, "bad_totp", "invalid_credentials");
      return { ok: false, code: "totp_invalid", message: "invalid TOTP code" };
    }
  }

  const token = randomBytes(32).toString("hex");
  const tokenHash = sha256HexSync(token);
  const issuedAt = Date.now();
  const createdAt = new Date(issuedAt).toISOString();
  const expiresAt = new Date(issuedAt + BREAK_GLASS_SESSION_MS).toISOString();
  const justificationTrimmed = justification.trim();

  const eventId = db.transaction(() => {
    db.query("UPDATE users SET failed_logins = 0, locked_until = NULL, updated_at = ? WHERE id = ?").run(
      nowIso(),
      user.id,
    );
    const session = db
      .query(
        `INSERT INTO sessions (user_id, token_hash, created_at, expires_at, last_seen_at, ip, user_agent, break_glass)
         VALUES (?, ?, ?, ?, ?, ?, ?, 1)`,
      )
      .run(user.id, tokenHash, createdAt, expiresAt, createdAt, opts.ip ?? null, opts.userAgent ?? null);
    const sessionId = Number(session.lastInsertRowid);
    const event = db
      .query(
        `INSERT INTO break_glass_events
           (user_id, justification, token_hash_prefix, session_id, created_at, status)
         VALUES (?, ?, ?, ?, ?, 'unreviewed')`,
      )
      .run(user.id, justificationTrimmed, tokenHash.slice(0, 16), sessionId, createdAt);
    const eventRowId = Number(event.lastInsertRowid);
    appendAudit(db, {
      actor_id: user.id,
      action: "auth.break_glass",
      entity_type: "break_glass_event",
      entity_id: eventRowId,
      // Flagged in the audit record itself; justification lives on the
      // event row, the raw token never appears anywhere.
      after: { break_glass: true, token_hash_prefix: tokenHash.slice(0, 16) },
    });
    return eventRowId;
  })();

  return { ok: true, token, expires_at: expiresAt, event_id: eventId, user };
}

/** Unreviewed break-glass events, newest first (dashboard alert source). */
export function listBreakGlassEvents(
  db: Database,
  opts: { status?: "unreviewed" | "reviewed" | "all" } = {},
): (BreakGlassEventRow & { email: string })[] {
  const status = opts.status ?? "unreviewed";
  const clause = status === "all" ? "" : "WHERE e.status = ?";
  const params = status === "all" ? [] : [status];
  return db
    .query(
      `SELECT e.*, u.email FROM break_glass_events e
       JOIN users u ON u.id = e.user_id ${clause} ORDER BY e.created_at DESC, e.id DESC`,
    )
    .all(...params) as (BreakGlassEventRow & { email: string })[];
}

/** Mark a break-glass event reviewed. Reviewer must be admin or principal (checked by caller). */
export function reviewBreakGlassEvent(
  db: Database,
  eventId: number,
  reviewerId: number,
): BreakGlassEventRow | null {
  const event = db
    .query("SELECT * FROM break_glass_events WHERE id = ?")
    .get(eventId) as BreakGlassEventRow | undefined;
  if (!event) return null;
  if (event.status === "reviewed") return event;
  const reviewedAt = nowIso();
  db.transaction(() => {
    db.query(
      "UPDATE break_glass_events SET reviewed_at = ?, reviewed_by = ?, status = 'reviewed' WHERE id = ?",
    ).run(reviewedAt, reviewerId, eventId);
    appendAudit(db, {
      actor_id: reviewerId,
      action: "auth.break_glass_reviewed",
      entity_type: "break_glass_event",
      entity_id: eventId,
      after: { break_glass: true, reviewed_by: reviewerId },
    });
  })();
  return db.query("SELECT * FROM break_glass_events WHERE id = ?").get(eventId) as BreakGlassEventRow;
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
