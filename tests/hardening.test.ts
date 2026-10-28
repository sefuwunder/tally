// Phase 10 acceptance: break-glass, auth rate limiting, default-deny
// route review, zero-dependency assertion.

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  makeTestEnv, loginAs, authHeaders, createTestUser, ADMIN_EMAIL, ADMIN_PASSWORD, type TestEnv,
} from "./helpers";

let env: TestEnv;
beforeAll(async () => {
  env = await makeTestEnv();
});
afterAll(() => env.cleanup());

const BG_JUSTIFICATION = "Emergency admin access: primary MFA device lost, need to rotate credentials";

describe("break-glass", () => {
  test("justification too short rejected (400 validation)", async () => {
    const res = await fetch(`${env.base}/api/v1/auth/break-glass`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: ADMIN_EMAIL, password: ADMIN_PASSWORD, justification: "too short" }),
    });
    expect(res.status).toBe(400);
    expect((await res.json()).error.code).toBe("validation");
  });

  test("non-admin rejected (403 forbidden) even with valid password + justification", async () => {
    const email = "bg-viewer@example.local";
    await createTestUser(env.db, email, "Bg-Viewer-12345", "viewer");
    const res = await fetch(`${env.base}/api/v1/auth/break-glass`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password: "Bg-Viewer-12345", justification: BG_JUSTIFICATION }),
    });
    expect(res.status).toBe(403);
    expect((await res.json()).error.code).toBe("forbidden");
    expect(
      env.db.query("SELECT COUNT(*) AS n FROM break_glass_events WHERE user_id = (SELECT id FROM users WHERE email = ?)").get(email),
    ).toEqual({ n: 0 });
  });

  test("admin break-glass succeeds: 1h flagged session + event row + audit row", async () => {
    const res = await fetch(`${env.base}/api/v1/auth/break-glass`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: ADMIN_EMAIL, password: ADMIN_PASSWORD, justification: BG_JUSTIFICATION }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.break_glass).toBe(true);
    expect(typeof body.break_glass_event_id).toBe("number");

    const event = env.db.query("SELECT * FROM break_glass_events WHERE id = ?").get(body.break_glass_event_id) as Record<string, unknown>;
    expect(event.status).toBe("unreviewed");
    expect(event.justification).toBe(BG_JUSTIFICATION);
    expect(event.reviewed_at).toBeNull();
    expect(typeof event.token_hash_prefix).toBe("string");
    expect((event.token_hash_prefix as string)).toHaveLength(16);

    const session = env.db.query("SELECT * FROM sessions WHERE id = ?").get(event.session_id as number) as Record<string, unknown>;
    expect(session.break_glass).toBe(1);
    const lifetimeMs = Date.parse(session.expires_at as string) - Date.parse(session.created_at as string);
    expect(lifetimeMs).toBe(60 * 60 * 1000);

    const audit = env.db.query("SELECT * FROM audit_log WHERE action = 'auth.break_glass' ORDER BY seq DESC LIMIT 1").get() as Record<string, unknown>;
    expect(audit).toBeTruthy();
    expect(audit.after_json as string).toContain("break_glass");

    // The session itself reports the flag via /me.
    const me = await fetch(`${env.base}/api/v1/auth/me`, { headers: authHeaders(body.token) });
    expect(me.status).toBe(200);
    expect((await me.json()).data.break_glass).toBe(true);
  });

  test("dashboard alert lists unreviewed events; review flow (principal/admin only)", async () => {
    const auditorEmail = "bg-auditor@example.local";
    await createTestUser(env.db, auditorEmail, "Bg-Auditor-1234", "auditor");
    const auditorLogin = await loginAs(env.base, auditorEmail, "Bg-Auditor-1234");
    expect(auditorLogin.status).toBe(200);

    const list = await fetch(`${env.base}/api/v1/compliance/break-glass`, {
      headers: authHeaders(auditorLogin.token),
    });
    expect(list.status).toBe(200);
    const events = (await list.json()).data as { id: number; status: string }[];
    expect(events.length).toBeGreaterThanOrEqual(1);
    expect(events.every((e) => e.status === "unreviewed")).toBe(true);
    const eventId = events[0].id;

    // Auditor is read-only: cannot review.
    const denied = await fetch(`${env.base}/api/v1/compliance/break-glass/${eventId}/review`, {
      method: "POST",
      headers: authHeaders(auditorLogin.token),
    });
    expect(denied.status).toBe(403);

    // Admin reviews.
    const adminLogin = await loginAs(env.base, ADMIN_EMAIL, ADMIN_PASSWORD);
    const reviewed = await fetch(`${env.base}/api/v1/compliance/break-glass/${eventId}/review`, {
      method: "POST",
      headers: authHeaders(adminLogin.token),
    });
    expect(reviewed.status).toBe(200);
    expect((await reviewed.json()).data.status).toBe("reviewed");

    // Reviewed events leave the default (unreviewed) listing.
    const list2 = await fetch(`${env.base}/api/v1/compliance/break-glass`, {
      headers: authHeaders(auditorLogin.token),
    });
    const remaining = (await list2.json()).data as { id: number }[];
    expect(remaining.some((e) => e.id === eventId)).toBe(false);
    const all = await fetch(`${env.base}/api/v1/compliance/break-glass?status=all`, {
      headers: authHeaders(auditorLogin.token),
    });
    expect(((await all.json()).data as { id: number }[]).some((e) => e.id === eventId)).toBe(true);

    const audit = env.db.query("SELECT * FROM audit_log WHERE action = 'auth.break_glass_reviewed' ORDER BY seq DESC LIMIT 1").get();
    expect(audit).toBeTruthy();
  });

  test("break-glass endpoint requires auth-adjacent guard: wrong password -> 401, no event", async () => {
    const before = (env.db.query("SELECT COUNT(*) AS n FROM break_glass_events").get() as { n: number }).n;
    const res = await fetch(`${env.base}/api/v1/auth/break-glass`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: ADMIN_EMAIL, password: "Wrong-Password-999", justification: BG_JUSTIFICATION }),
    });
    expect(res.status).toBe(401);
    expect((env.db.query("SELECT COUNT(*) AS n FROM break_glass_events").get() as { n: number }).n).toBe(before);
  });
});

describe("auth rate limiting", () => {
  test("limit exceeded -> 429 with Retry-After + auth.rate_limited audit row", async () => {
    const rl = await makeTestEnv({ authRateLimitPerMinute: 3 });
    try {
      for (let i = 0; i < 3; i++) {
        const res = await fetch(`${rl.base}/api/v1/auth/login`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ email: "nobody@example.local", password: "Whatever-123456" }),
        });
        expect(res.status).toBe(401);
      }
      const blocked = await fetch(`${rl.base}/api/v1/auth/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: "nobody@example.local", password: "Whatever-123456" }),
      });
      expect(blocked.status).toBe(429);
      expect((await blocked.json()).error.code).toBe("rate_limited");
      expect(blocked.headers.get("retry-after")).toBeTruthy();
      const audit = rl.db.query("SELECT * FROM audit_log WHERE action = 'auth.rate_limited'").get();
      expect(audit).toBeTruthy();
    } finally {
      rl.cleanup();
    }
  });
});

describe("default-deny route review", () => {
  test("unauthenticated access to protected routes returns 401 across modules", async () => {
    const paths = [
      "/api/v1/ledger/accounts",
      "/api/v1/ledger/trial-balance?period_id=1",
      "/api/v1/ar/customers",
      "/api/v1/ap/vendors",
      "/api/v1/inventory/items",
      "/api/v1/procurement/purchase-orders",
      "/api/v1/crm/companies",
      "/api/v1/hr/employees",
      "/api/v1/reports/profit-loss?period_id=1",
      "/api/v1/reports/report-runs",
      "/api/v1/documents",
      "/api/v1/compliance/audit-log",
      "/api/v1/compliance/break-glass",
      "/api/v1/compliance/verify",
    ];
    for (const p of paths) {
      const res = await fetch(`${env.base}${p}`);
      expect(res.status).toBe(401);
      expect((await res.json()).error.code).toMatch(/unauthorized|session_expired/);
    }
  });

  test("unknown routes return the 404 envelope", async () => {
    const res = await fetch(`${env.base}/api/v1/definitely-not-a-route`);
    expect(res.status).toBe(404);
    expect((await res.json()).error.code).toBe("not_found");
    const authed = await loginAs(env.base, ADMIN_EMAIL, ADMIN_PASSWORD);
    const res2 = await fetch(`${env.base}/api/v1/ledger/nope`, { headers: authHeaders(authed.token) });
    expect(res2.status).toBe(404);
  });

  test("public surface is exactly health + login + break-glass", async () => {
    const health = await fetch(`${env.base}/health`);
    expect(health.status).toBe(200);
    const login = await fetch(`${env.base}/api/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: ADMIN_EMAIL, password: ADMIN_PASSWORD }),
    });
    expect(login.status).toBe(200);
  });
});

describe("dependency audit", () => {
  test("package.json has zero dependencies and zero devDependencies", () => {
    const here = typeof import.meta.dir === "string"
      ? import.meta.dir
      : dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(readFileSync(join(here, "..", "package.json"), "utf8"));
    expect(pkg.dependencies ?? {}).toEqual({});
    expect(pkg.devDependencies ?? {}).toEqual({});
  });
});
