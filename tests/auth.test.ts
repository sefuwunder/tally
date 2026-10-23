// Phase 0 acceptance: login/logout/session-expiry, lockout, password policy.

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { makeTestEnv, loginAs, authHeaders, createTestUser, ADMIN_EMAIL, ADMIN_PASSWORD, type TestEnv } from "./helpers";
import { validatePassword, getUserByEmail } from "../src/auth";

let env: TestEnv;
beforeAll(async () => {
  env = await makeTestEnv();
});
afterAll(() => env.cleanup());

describe("login", () => {
  test("valid credentials return a token and expiry", async () => {
    const r = await loginAs(env.base, ADMIN_EMAIL, ADMIN_PASSWORD);
    expect(r.status).toBe(200);
    expect(typeof r.token).toBe("string");
    expect(r.token.length).toBeGreaterThanOrEqual(64);
    expect(typeof r.expires_at).toBe("string");
    expect(r.body.must_change_password).toBe(true); // seeded admin must change pw
  });

  test("wrong password -> 401 invalid_credentials, failed_logins increments", async () => {
    const before = getUserByEmail(env.db, ADMIN_EMAIL)!.failed_logins;
    const res = await fetch(`${env.base}/api/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: ADMIN_EMAIL, password: "Wrong-Password-999" }),
    });
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error.code).toBe("invalid_credentials");
    expect(getUserByEmail(env.db, ADMIN_EMAIL)!.failed_logins).toBe(before + 1);
  });

  test("unknown email -> 401 invalid_credentials (no enumeration)", async () => {
    const res = await fetch(`${env.base}/api/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "nobody@example.local", password: "Whatever-123456" }),
    });
    expect(res.status).toBe(401);
    expect((await res.json()).error.code).toBe("invalid_credentials");
  });

  test("missing fields -> 400 validation", async () => {
    const res = await fetch(`${env.base}/api/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: ADMIN_EMAIL }),
    });
    expect(res.status).toBe(400);
    expect((await res.json()).error.code).toBe("validation");
  });

  test("malformed JSON -> 400 validation", async () => {
    const res = await fetch(`${env.base}/api/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{not json",
    });
    expect(res.status).toBe(400);
    expect((await res.json()).error.code).toBe("validation");
  });

  test("raw token is stored only as a hash, never plaintext", async () => {
    const r = await loginAs(env.base, ADMIN_EMAIL, ADMIN_PASSWORD);
    const row = env.db
      .query("SELECT token_hash FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = ?)")
      .get(ADMIN_EMAIL) as { token_hash: string };
    expect(row.token_hash).not.toContain(r.token.slice(0, 16));
    expect(row.token_hash).toHaveLength(64); // sha256 hex
  });

  test("two logins for the same email create distinct sessions (H-T1)", async () => {
    const a = await loginAs(env.base, ADMIN_EMAIL, ADMIN_PASSWORD);
    const b = await loginAs(env.base, ADMIN_EMAIL, ADMIN_PASSWORD);
    expect(a.token).not.toBe(b.token);
  });
});

describe("lockout with backoff", () => {
  test("5 failed logins lock the account; correct password then gets account_locked", async () => {
    const email = "lockout@example.local";
    await createTestUser(env.db, email, "Lockout-Test-123", "viewer");
    for (let i = 0; i < 5; i++) {
      const res = await fetch(`${env.base}/api/v1/auth/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, password: "Wrong-Password-999" }),
      });
      expect(res.status).toBe(401);
      expect((await res.json()).error.code).toBe("invalid_credentials");
    }
    const locked = getUserByEmail(env.db, email)!;
    expect(locked.locked_until).not.toBeNull();

    const res = await fetch(`${env.base}/api/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password: "Lockout-Test-123" }),
    });
    expect(res.status).toBe(401);
    expect((await res.json()).error.code).toBe("account_locked");
  });

  test("successful login resets the failed-login counter", async () => {
    const email = "reset-counter@example.local";
    await createTestUser(env.db, email, "Reset-Counter-123", "viewer");
    await fetch(`${env.base}/api/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password: "Wrong-Password-999" }),
    });
    expect(getUserByEmail(env.db, email)!.failed_logins).toBe(1);
    const r = await loginAs(env.base, email, "Reset-Counter-123");
    expect(r.status).toBe(200);
    expect(getUserByEmail(env.db, email)!.failed_logins).toBe(0);
  });
});

describe("logout and me", () => {
  test("logout revokes the session; me -> 401 afterwards", async () => {
    const r = await loginAs(env.base, ADMIN_EMAIL, ADMIN_PASSWORD);
    const me = await fetch(`${env.base}/api/v1/auth/me`, { headers: authHeaders(r.token) });
    expect(me.status).toBe(200);
    expect((await me.json()).data.email).toBe(ADMIN_EMAIL);

    const out = await fetch(`${env.base}/api/v1/auth/logout`, {
      method: "POST",
      headers: authHeaders(r.token),
    });
    expect(out.status).toBe(200);

    const me2 = await fetch(`${env.base}/api/v1/auth/me`, { headers: authHeaders(r.token) });
    expect(me2.status).toBe(401);
    expect((await me2.json()).error.code).toBe("unauthorized");
  });

  test("me without token -> 401 unauthorized", async () => {
    const res = await fetch(`${env.base}/api/v1/auth/me`);
    expect(res.status).toBe(401);
    expect((await res.json()).error.code).toBe("unauthorized");
  });

  test("me never leaks the password hash", async () => {
    const r = await loginAs(env.base, ADMIN_EMAIL, ADMIN_PASSWORD);
    const body = await (await fetch(`${env.base}/api/v1/auth/me`, { headers: authHeaders(r.token) })).json();
    expect(JSON.stringify(body)).not.toContain("argon2");
    expect(body.data.pw_hash).toBeUndefined();
  });

  test("disabled user mid-session -> next request 401", async () => {
    const email = "disableme@example.local";
    await createTestUser(env.db, email, "Disable-Me-12345", "viewer");
    const r = await loginAs(env.base, email, "Disable-Me-12345");
    expect(r.status).toBe(200);
    env.db.query("UPDATE users SET disabled_at = ? WHERE email = ?").run(new Date().toISOString(), email);
    const me = await fetch(`${env.base}/api/v1/auth/me`, { headers: authHeaders(r.token) });
    expect(me.status).toBe(401);
  });
});

describe("password policy (H-A3)", () => {
  test("rejects short passwords", () => {
    expect(validatePassword("Short-1").ok).toBe(false);
  });
  test("rejects common passwords even at length", () => {
    expect(validatePassword("password1234").ok).toBe(false);
  });
  test("rejects letters-only and digits-only", () => {
    expect(validatePassword("abcdefghijklmn").ok).toBe(false);
    expect(validatePassword("123456789012").ok).toBe(false);
  });
  test("accepts the seeded admin password shape", () => {
    expect(validatePassword("Changeme-123456").ok).toBe(true);
  });
});
