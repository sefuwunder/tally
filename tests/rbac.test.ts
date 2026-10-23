// RBAC matrix test (H-A2): every role x every resource x every action,
// asserted against the seeded permission table. Default-deny.

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { makeTestEnv, loginAs, authHeaders, createTestUser, type TestEnv } from "./helpers";
import { can, permissionsFor, roleNames, RESOURCES, ACTIONS } from "../src/rbac";
import { PERMISSION_MATRIX, ADMIN_EMAIL, ADMIN_PASSWORD } from "../src/seed";

let env: TestEnv;
beforeAll(async () => {
  env = await makeTestEnv();
});
afterAll(() => env.cleanup());

function expectedSet(role: string): Set<string> {
  const s = new Set<string>();
  for (const [resource, actions] of Object.entries(PERMISSION_MATRIX[role] ?? {})) {
    for (const action of actions) s.add(`${resource}:${action}`);
  }
  return s;
}

describe("seeded RBAC matrix", () => {
  test("all seven roles are seeded", () => {
    expect(roleNames(env.db).sort()).toEqual(
      ["admin", "accountant", "ap_clerk", "sales", "hr", "auditor", "viewer"].sort(),
    );
  });

  for (const role of Object.keys(PERMISSION_MATRIX)) {
    test(`role '${role}': DB permissions exactly match the seed matrix`, () => {
      const actual = permissionsFor(env.db, role);
      const expected = expectedSet(role);
      expect([...actual].sort()).toEqual([...expected].sort());
    });
  }

  test("exhaustive roles x resources x actions via can()", () => {
    for (const role of Object.keys(PERMISSION_MATRIX)) {
      for (const resource of RESOURCES) {
        for (const action of ACTIONS) {
          const should = (PERMISSION_MATRIX[role][resource] ?? []).includes(action);
          expect(can(env.db, role, resource, action)).toBe(should);
        }
      }
    }
  });

  test("default-deny: unknown role / resource / action", () => {
    expect(can(env.db, "ghost", "ledger", "read")).toBe(false);
    expect(can(env.db, "admin", "teleport", "read")).toBe(false);
    expect(can(env.db, "admin", "ledger", "vaporize")).toBe(false);
  });

  test("auditor is read-only everywhere", () => {
    for (const resource of RESOURCES) {
      expect(can(env.db, "auditor", resource, "read")).toBe(true);
      for (const action of ["write", "post", "approve", "admin"] as const) {
        expect(can(env.db, "auditor", resource, action)).toBe(false);
      }
    }
  });

  test("viewer cannot touch hr (PII least privilege) or audit", () => {
    expect(can(env.db, "viewer", "hr", "read")).toBe(false);
    expect(can(env.db, "viewer", "audit", "read")).toBe(false);
    expect(can(env.db, "viewer", "crm", "read")).toBe(true);
  });
});

describe("RBAC over HTTP", () => {
  test("sales user is forbidden from the audit log (403 forbidden)", async () => {
    await createTestUser(env.db, "salesrep@example.local", "Sales-Rep-12345", "sales");
    const r = await loginAs(env.base, "salesrep@example.local", "Sales-Rep-12345");
    expect(r.status).toBe(200);
    const res = await fetch(`${env.base}/api/v1/compliance/audit-log`, {
      headers: authHeaders(r.token),
    });
    expect(res.status).toBe(403);
    expect((await res.json()).error.code).toBe("forbidden");
  });

  test("auditor can read the audit log", async () => {
    await createTestUser(env.db, "auditor1@example.local", "Auditor-One-123", "auditor");
    const r = await loginAs(env.base, "auditor1@example.local", "Auditor-One-123");
    const res = await fetch(`${env.base}/api/v1/compliance/audit-log`, {
      headers: authHeaders(r.token),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(Array.isArray(body.data)).toBe(true);
    expect(typeof body.meta.total).toBe("number");
  });

  test("admin can read the audit log", async () => {
    const r = await loginAs(env.base, ADMIN_EMAIL, ADMIN_PASSWORD);
    const res = await fetch(`${env.base}/api/v1/compliance/audit-log`, {
      headers: authHeaders(r.token),
    });
    expect(res.status).toBe(200);
  });
});
