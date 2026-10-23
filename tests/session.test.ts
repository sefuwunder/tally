// Session expiry: idle timeout (H-T3) and absolute max, enforced server-side.

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { makeTestEnv, loginAs, authHeaders, type TestEnv } from "./helpers";
import { ADMIN_EMAIL, ADMIN_PASSWORD } from "../src/seed";

describe("idle timeout (H-T3)", () => {
  let env: TestEnv;
  beforeAll(async () => {
    env = await makeTestEnv({ idleTimeoutMs: 120 }); // 120ms for the test
  });
  afterAll(() => env.cleanup());

  test("request after idle window -> 401 session_expired", async () => {
    const r = await loginAs(env.base, ADMIN_EMAIL, ADMIN_PASSWORD);
    expect(r.status).toBe(200);
    await Bun.sleep(200);
    const me = await fetch(`${env.base}/api/v1/auth/me`, { headers: authHeaders(r.token) });
    expect(me.status).toBe(401);
    expect((await me.json()).error.code).toBe("session_expired");
  });

  test("expired session row is deleted on use", async () => {
    const r = await loginAs(env.base, ADMIN_EMAIL, ADMIN_PASSWORD);
    await Bun.sleep(200);
    await fetch(`${env.base}/api/v1/auth/me`, { headers: authHeaders(r.token) });
    const n = (env.db.query("SELECT COUNT(*) AS n FROM sessions").get() as { n: number }).n;
    expect(n).toBe(0);
  });

  test("activity inside the window keeps the session alive (sliding)", async () => {
    const r = await loginAs(env.base, ADMIN_EMAIL, ADMIN_PASSWORD);
    for (let i = 0; i < 4; i++) {
      await Bun.sleep(60);
      const me = await fetch(`${env.base}/api/v1/auth/me`, { headers: authHeaders(r.token) });
      expect(me.status).toBe(200);
    }
  });
});

describe("absolute session max", () => {
  let env: TestEnv;
  beforeAll(async () => {
    env = await makeTestEnv({ absoluteMaxMs: 150 });
  });
  afterAll(() => env.cleanup());

  test("request after absolute max -> 401 session_expired even with activity", async () => {
    const r = await loginAs(env.base, ADMIN_EMAIL, ADMIN_PASSWORD);
    await Bun.sleep(220);
    const me = await fetch(`${env.base}/api/v1/auth/me`, { headers: authHeaders(r.token) });
    expect(me.status).toBe(401);
    expect((await me.json()).error.code).toBe("session_expired");
  });
});
