// Audit log: hash chain verify after 100 mixed writes, tamper detection,
// trigger enforcement, and the ?verify=1 endpoint.

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { copyFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { mkdtempSync } from "node:fs";
import { Database } from "bun:sqlite";
import { makeTestEnv, loginAs, authHeaders, checkpoint, type TestEnv } from "./helpers";
import { appendAudit, verifyChain, canonicalJson } from "../src/audit";
import { ADMIN_EMAIL, ADMIN_PASSWORD } from "../src/seed";

let env: TestEnv;
beforeAll(async () => {
  env = await makeTestEnv();
});
afterAll(() => env.cleanup());

describe("hash chain", () => {
  test("verify passes after 100 mixed writes", () => {
    const tx = env.db.transaction(() => {
      for (let i = 0; i < 100; i++) {
        appendAudit(env.db, {
          actor_id: i % 3 === 0 ? null : 1,
          action: ["user.create", "journal.post", "auth.login", "invoice.void"][i % 4],
          entity_type: ["user", "journal", "session", "invoice"][i % 4],
          entity_id: i,
          before: i % 2 === 0 ? { balance: i * 100 } : undefined,
          after: { balance: i * 100 + 50, note: `row-${i}` },
        });
      }
    });
    tx();
    const v = verifyChain(env.db);
    expect(v.ok).toBe(true);
    expect(v.count).toBeGreaterThanOrEqual(100);
    expect(v.break_at_seq).toBeNull();
  });

  test("chain links: every row's prev_hash equals the previous row's hash", () => {
    const rows = env.db
      .query("SELECT seq, prev_hash, hash FROM audit_log ORDER BY seq ASC LIMIT 20")
      .all() as { seq: number; prev_hash: string; hash: string }[];
    expect(rows.length).toBeGreaterThan(0);
    expect(rows[0].prev_hash).toBe("GENESIS");
    for (let i = 1; i < rows.length; i++) {
      expect(rows[i].prev_hash).toBe(rows[i - 1].hash);
    }
  });

  test("canonicalJson is key-order stable", () => {
    expect(canonicalJson({ b: 1, a: { d: 4, c: 3 } })).toBe(canonicalJson({ a: { c: 3, d: 4 }, b: 1 }));
  });

  test("audit rows always carry an action, entity type, and timestamp", () => {
    const rows = env.db
      .query("SELECT action, entity_type, ts FROM audit_log ORDER BY seq DESC LIMIT 5")
      .all() as { action: string; entity_type: string; ts: string }[];
    for (const r of rows) {
      expect(r.action.length).toBeGreaterThan(0);
      expect(r.entity_type.length).toBeGreaterThan(0);
      expect(Number.isNaN(Date.parse(r.ts))).toBe(false);
    }
  });

  test("login/logout write audit rows with actor bound (no raw secrets)", () => {
    const before = (env.db.query("SELECT COUNT(*) AS n FROM audit_log").get() as { n: number }).n;
    return loginAs(env.base, ADMIN_EMAIL, ADMIN_PASSWORD).then(async (r) => {
      await fetch(`${env.base}/api/v1/auth/logout`, { method: "POST", headers: authHeaders(r.token) });
      const rows = env.db
        .query("SELECT action, actor_id, after_json FROM audit_log ORDER BY seq DESC LIMIT 3")
        .all() as { action: string; actor_id: number | null; after_json: string | null }[];
      const actions = rows.map((x) => x.action);
      expect(actions).toContain("auth.login");
      expect(actions).toContain("auth.logout");
      for (const row of rows) {
        const blob = `${row.after_json ?? ""}`;
        expect(blob).not.toContain(ADMIN_PASSWORD);
        expect(blob).not.toContain(r.token);
      }
      const after = (env.db.query("SELECT COUNT(*) AS n FROM audit_log").get() as { n: number }).n;
      expect(after).toBeGreaterThan(before);
    });
  });
});

describe("tamper detection", () => {
  test("tampering one row in a scratch copy breaks verify at that seq", () => {
    checkpoint(env.db);
    const dir = mkdtempSync(join(tmpdir(), "tally-tamper-"));
    const scratch = join(dir, "scratch.db");
    copyFileSync(env.dbPath, scratch);
    const sdb = new Database(scratch);
    try {
      const target = sdb.query("SELECT seq FROM audit_log ORDER BY seq ASC LIMIT 1 OFFSET 10").get() as {
        seq: number;
      };
      // attacker disables the trigger, then edits history
      sdb.exec("DROP TRIGGER audit_log_no_update;");
      sdb.query("UPDATE audit_log SET after_json = ? WHERE seq = ?").run('{"tampered":true}', target.seq);
      const v = verifyChain(sdb);
      expect(v.ok).toBe(false);
      expect(v.break_at_seq).toBe(target.seq);
    } finally {
      sdb.close();
    }
    // original untouched
    expect(verifyChain(env.db).ok).toBe(true);
  });
});

describe("append-only triggers", () => {
  test("UPDATE on audit_log aborts", () => {
    expect(() =>
      env.db.query("UPDATE audit_log SET action = 'x' WHERE seq = 1").run(),
    ).toThrow(/append-only/);
  });

  test("DELETE on audit_log aborts", () => {
    expect(() => env.db.query("DELETE FROM audit_log WHERE seq = 1").run()).toThrow(/append-only/);
  });
});

describe("GET /api/v1/compliance/audit-log", () => {
  test("?verify=1 returns a passing chain report", async () => {
    const r = await loginAs(env.base, ADMIN_EMAIL, ADMIN_PASSWORD);
    const res = await fetch(`${env.base}/api/v1/compliance/audit-log?verify=1&per_page=5`, {
      headers: authHeaders(r.token),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.verification.ok).toBe(true);
    expect(typeof body.verification.count).toBe("number");
    expect(body.meta.page).toBe(1);
  });

  test("filters narrow the result set", async () => {
    const r = await loginAs(env.base, ADMIN_EMAIL, ADMIN_PASSWORD);
    const res = await fetch(
      `${env.base}/api/v1/compliance/audit-log?action=auth.login&per_page=50`,
      { headers: authHeaders(r.token) },
    );
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.meta.total).toBeGreaterThan(0);
    for (const row of body.data) expect(row.action).toBe("auth.login");
  });

  test("before/after are parsed JSON, not raw strings", async () => {
    const r = await loginAs(env.base, ADMIN_EMAIL, ADMIN_PASSWORD);
    const res = await fetch(`${env.base}/api/v1/compliance/audit-log?per_page=1`, {
      headers: authHeaders(r.token),
    });
    const body = await res.json();
    const row = body.data[0];
    expect(typeof row.before === "object" || row.before === null).toBe(true);
    expect(row.before_json).toBeUndefined();
  });
});
