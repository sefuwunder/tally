// Phase 10 acceptance: RFC 6238 TOTP, enrollment + enforcement, disable.

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import {
  makeTestEnv, loginAs, authHeaders, createTestUser, ADMIN_EMAIL, ADMIN_PASSWORD, type TestEnv,
} from "./helpers";
import {
  base32Encode, base32Decode, generateTotpSecret, totpCode, verifyTotp,
} from "../src/totp";
import { getUserByEmail } from "../src/auth";

let env: TestEnv;
beforeAll(async () => {
  env = await makeTestEnv();
});
afterAll(() => env.cleanup());

describe("totp primitives (RFC 6238 test vectors, 6-digit truncation)", () => {
  // RFC 6238 secret "12345678901234567890" (ASCII) as base32.
  const SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  test("base32 roundtrip + 160-bit generated secrets", () => {
    expect(base32Decode(SECRET)).toEqual(new TextEncoder().encode("12345678901234567890"));
    expect(base32Encode(new TextEncoder().encode("12345678901234567890"))).toBe(SECRET);
    const s = generateTotpSecret();
    expect(s).toHaveLength(32);
    expect(base32Decode(s)).toHaveLength(20);
    expect(() => base32Decode("NOT!BASE32")).toThrow();
  });
  test("RFC 6238 vectors truncated to 6 digits", () => {
    // 8-digit vectors: 94287082, 07081804, 89005924, 69279037, 65353130.
    expect(totpCode(SECRET, 59 * 1000)).toBe("287082");
    expect(totpCode(SECRET, 1111111109 * 1000)).toBe("081804");
    expect(totpCode(SECRET, 1234567890 * 1000)).toBe("005924");
    expect(totpCode(SECRET, 2000000000 * 1000)).toBe("279037");
    expect(totpCode(SECRET, 20000000000 * 1000)).toBe("353130");
  });
  test("±1 step accepted, ±2 rejected; malformed codes rejected", () => {
    const now = Date.now();
    const code = totpCode(SECRET, now);
    expect(verifyTotp(SECRET, code, { atMs: now })).toBe(true);
    expect(verifyTotp(SECRET, totpCode(SECRET, now - 30_000), { atMs: now })).toBe(true);
    expect(verifyTotp(SECRET, totpCode(SECRET, now + 30_000), { atMs: now })).toBe(true);
    expect(verifyTotp(SECRET, totpCode(SECRET, now - 60_000), { atMs: now })).toBe(false);
    expect(verifyTotp(SECRET, totpCode(SECRET, now + 60_000), { atMs: now })).toBe(false);
    expect(verifyTotp(SECRET, "12345", { atMs: now })).toBe(false);
    expect(verifyTotp(SECRET, "abcdef", { atMs: now })).toBe(false);
    expect(verifyTotp(SECRET, "000000", { atMs: now })).toBe(false);
  });
});

describe("seeded MFA policy flags (roles.mfa_required)", () => {
  test("admin + auditor roles are MFA-required; seeded admin login flags enrollment, not a block", async () => {
    const adminFlag = env.db.query("SELECT mfa_required FROM roles WHERE name = 'admin'").get() as { mfa_required: number };
    const auditorFlag = env.db.query("SELECT mfa_required FROM roles WHERE name = 'auditor'").get() as { mfa_required: number };
    const viewerFlag = env.db.query("SELECT mfa_required FROM roles WHERE name = 'viewer'").get() as { mfa_required: number };
    expect(adminFlag.mfa_required).toBe(1);
    expect(auditorFlag.mfa_required).toBe(1);
    expect(viewerFlag.mfa_required).toBe(0);
    // No secret enrolled yet: login succeeds but reports enrollment required.
    const r = await loginAs(env.base, ADMIN_EMAIL, ADMIN_PASSWORD);
    expect(r.status).toBe(200);
    expect(r.body.mfa_enrollment_required).toBe(true);
  });
});

describe("TOTP enrollment + enforcement flow", () => {
  const email = "mfa-user@example.local";
  const password = "Mfa-User-12345";
  let secret = "";

  test("enroll returns secret + otpauth URI and stores NOTHING until confirm", async () => {
    await createTestUser(env.db, email, password, "sales");
    const login = await loginAs(env.base, email, password);
    expect(login.status).toBe(200);
    const res = await fetch(`${env.base}/api/v1/auth/totp/enroll`, {
      method: "POST",
      headers: authHeaders(login.token),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    secret = body.data.secret;
    expect(secret).toHaveLength(32);
    expect(body.data.otpauth_uri).toContain("otpauth://totp/");
    expect(body.data.otpauth_uri).toContain(secret);
    // Still unenrolled in the DB.
    const user = getUserByEmail(env.db, email)!;
    expect(user.totp_secret).toBeNull();
    expect(user.mfa_required).toBe(0);
  });

  test("confirm with wrong code rejected; confirm with correct code enables MFA", async () => {
    const login = await loginAs(env.base, email, password);
    const wrong = await fetch(`${env.base}/api/v1/auth/totp/confirm`, {
      method: "POST",
      headers: { ...authHeaders(login.token), "content-type": "application/json" },
      body: JSON.stringify({ code: "000000" }),
    });
    expect(wrong.status).toBe(401);
    expect((await wrong.json()).error.code).toBe("totp_invalid");

    const ok = await fetch(`${env.base}/api/v1/auth/totp/confirm`, {
      method: "POST",
      headers: { ...authHeaders(login.token), "content-type": "application/json" },
      body: JSON.stringify({ code: totpCode(secret) }),
    });
    expect(ok.status).toBe(200);
    expect((await ok.json()).data.mfa_enabled).toBe(true);
    const user = getUserByEmail(env.db, email)!;
    expect(user.mfa_required).toBe(1);
    expect(user.totp_secret).toBe(secret);
  });

  test("password-only login blocked with totp_required and NO session row", async () => {
    const before = (env.db.query("SELECT COUNT(*) AS n FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = ?)").get(email) as { n: number }).n;
    const res = await fetch(`${env.base}/api/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    expect(res.status).toBe(401);
    expect((await res.json()).error.code).toBe("totp_required");
    const after = (env.db.query("SELECT COUNT(*) AS n FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = ?)").get(email) as { n: number }).n;
    expect(after).toBe(before);
  });

  test("login with valid code succeeds; wrong code rejected; ±1 window accepted, ±2 rejected", async () => {
    const good = await fetch(`${env.base}/api/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password, totp_code: totpCode(secret) }),
    });
    expect(good.status).toBe(200);
    expect((await good.json()).token).toBeTruthy();

    const bad = await fetch(`${env.base}/api/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password, totp_code: "000000" }),
    });
    expect(bad.status).toBe(401);
    expect((await bad.json()).error.code).toBe("totp_invalid");

    for (const offsetMs of [-30_000, 30_000]) {
      const r = await fetch(`${env.base}/api/v1/auth/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, password, totp_code: totpCode(secret, Date.now() + offsetMs) }),
      });
      expect(r.status).toBe(200);
    }
    for (const offsetMs of [-60_000, 60_000]) {
      const r = await fetch(`${env.base}/api/v1/auth/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, password, totp_code: totpCode(secret, Date.now() + offsetMs) }),
      });
      expect(r.status).toBe(401);
      expect((await r.json()).error.code).toBe("totp_invalid");
    }
  });

  test("secrets and codes never appear in audit rows", async () => {
    const rows = env.db
      .query("SELECT after_json FROM audit_log WHERE action LIKE 'auth.totp%'")
      .all() as { after_json: string | null }[];
    expect(rows.length).toBeGreaterThan(0);
    for (const r of rows) {
      expect(r.after_json ?? "").not.toContain(secret);
      expect(r.after_json ?? "").not.toContain(totpCode(secret));
    }
  });

  test("disable requires password re-check, then password-only login works again", async () => {
    const login = await fetch(`${env.base}/api/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password, totp_code: totpCode(secret) }),
    });
    const token = (await login.json()).token;
    const wrongPw = await fetch(`${env.base}/api/v1/auth/totp/disable`, {
      method: "POST",
      headers: { ...authHeaders(token), "content-type": "application/json" },
      body: JSON.stringify({ password: "Wrong-Password-999" }),
    });
    expect(wrongPw.status).toBe(401);
    const ok = await fetch(`${env.base}/api/v1/auth/totp/disable`, {
      method: "POST",
      headers: { ...authHeaders(token), "content-type": "application/json" },
      body: JSON.stringify({ password }),
    });
    expect(ok.status).toBe(200);
    const user = getUserByEmail(env.db, email)!;
    expect(user.totp_secret).toBeNull();
    expect(user.mfa_required).toBe(0);
    const plain = await loginAs(env.base, email, password);
    expect(plain.status).toBe(200);
  });

  test("enroll/confirm/disable require authentication", async () => {
    for (const path of ["totp/enroll", "totp/confirm", "totp/disable"]) {
      const res = await fetch(`${env.base}/api/v1/auth/${path}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({}),
      });
      expect(res.status).toBe(401);
    }
  });
});
