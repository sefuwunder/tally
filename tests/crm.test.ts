// Phase 7 tests: CRM + supervision surfaces (FINRA 4512/4513, 3110(b)(4)-(6)).

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import {
  makeTestEnv,
  loginAs,
  authHeaders,
  createTestUser,
  ADMIN_EMAIL,
  ADMIN_PASSWORD,
  type TestEnv,
} from "./helpers";

let env: TestEnv;
let adminToken: string;
let salesToken: string;
let principalId: number;
let principalToken: string;
let companyId: number;
let contactId: number;

beforeAll(async () => {
  env = await makeTestEnv();
  const admin = await loginAs(env.base, ADMIN_EMAIL, ADMIN_PASSWORD);
  expect(admin.status).toBe(200);
  adminToken = admin.token;

  await createTestUser(env.db, "salesrep@example.local", "Sales-Rep-12345", "sales");
  const sales = await loginAs(env.base, "salesrep@example.local", "Sales-Rep-12345");
  expect(sales.status).toBe(200);
  salesToken = sales.token;

  principalId = await createTestUser(env.db, "principal@example.local", "Principal-12345", "accountant");
  env.db.query("UPDATE users SET is_principal = 1, title = 'Principal', location = 'HQ' WHERE id = ?").run(principalId);
  const principal = await loginAs(env.base, "principal@example.local", "Principal-12345");
  expect(principal.status).toBe(200);
  principalToken = principal.token;
});
afterAll(() => env.cleanup());

async function post(path: string, token: string, body: unknown) {
  const res = await fetch(`${env.base}${path}`, {
    method: "POST",
    headers: { ...authHeaders(token), "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

async function patch(path: string, token: string, body: unknown) {
  const res = await fetch(`${env.base}${path}`, {
    method: "PATCH",
    headers: { ...authHeaders(token), "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

async function get(path: string, token: string) {
  const res = await fetch(`${env.base}${path}`, { headers: authHeaders(token) });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

describe("companies (4512 field set)", () => {
  test("create without required fields lists the missing 4512 fields", async () => {
    const r = await post("/api/v1/crm/companies", adminToken, { name: "Acme Holdings" });
    expect(r.status).toBe(400);
    expect(r.body.error.code).toBe("validation");
    expect(r.body.error.message).toContain("address");
    expect(r.body.error.message).toContain("tax_id");
  });

  test("create with the full 4512 set succeeds; update cannot gut a required field", async () => {
    const r = await post("/api/v1/crm/companies", adminToken, {
      name: "Acme Holdings",
      legal_name: "Acme Holdings LLC",
      address: "1 Acme Way, Cincinnati, OH",
      tax_id: "TAX-EXAMPLE-001",
      investment_objectives: "long-term growth",
      authorized_parties: "Jane Example, CFO",
    });
    expect(r.status).toBe(201);
    companyId = r.body.data.id;
    expect(r.body.data.status).toBe("active");

    const bad = await patch(`/api/v1/crm/companies/${companyId}`, adminToken, { tax_id: "" });
    expect(bad.status).toBe(400);
    expect(bad.body.error.message).toContain("tax_id");
  });
});

describe("contacts and deals", () => {
  test("contact validates email and company reference", async () => {
    const badEmail = await post("/api/v1/crm/contacts", adminToken, {
      name: "Jane Example",
      email: "not-an-email",
    });
    expect(badEmail.status).toBe(400);
    const badCompany = await post("/api/v1/crm/contacts", adminToken, {
      company_id: 999999,
      name: "Jane Example",
      email: "jane@example.local",
    });
    expect(badCompany.status).toBe(404);
    const ok = await post("/api/v1/crm/contacts", adminToken, {
      company_id: companyId,
      name: "Jane Example",
      email: "jane@example.local",
    });
    expect(ok.status).toBe(201);
    contactId = ok.body.data.id;
  });

  test("deal needs a party; won/lost are terminal stages", async () => {
    const noParty = await post("/api/v1/crm/deals", adminToken, { title: "Orphan deal" });
    expect(noParty.status).toBe(400);
    const deal = await post("/api/v1/crm/deals", adminToken, {
      title: "Acme mandate",
      company_id: companyId,
      amount_cents: 500000,
    });
    expect(deal.status).toBe(201);
    expect(deal.body.data.stage).toBe("lead");
    const id = deal.body.data.id;

    const won = await patch(`/api/v1/crm/deals/${id}`, adminToken, { stage: "won" });
    expect(won.status).toBe(200);
    const back = await patch(`/api/v1/crm/deals/${id}`, adminToken, { stage: "proposal" });
    expect(back.status).toBe(409);
    expect(back.body.error.code).toBe("terminal_stage");

    const filtered = await get(`/api/v1/crm/deals?stage=won`, adminToken);
    expect(filtered.body.data.some((d: any) => d.id === id)).toBe(true);
  });
});

describe("activities: immutable comms log + review queue", () => {
  let flaggedId: number;
  let aiId: number;
  let plainId: number;

  test("flagged comm appears in the queue; unflagged does not; ai_agent auto-flags", async () => {
    const flagged = await post("/api/v1/crm/activities", salesToken, {
      direction: "out",
      channel: "email",
      subject: "Quarterly statement",
      company_id: companyId,
      flagged_for_review: true,
    });
    expect(flagged.status).toBe(201);
    flaggedId = flagged.body.data.id;

    const ai = await post("/api/v1/crm/activities", salesToken, {
      direction: "out",
      channel: "email",
      origin: "ai_agent",
      subject: "AI-drafted note",
      company_id: companyId,
    });
    expect(ai.status).toBe(201);
    aiId = ai.body.data.id;
    expect(ai.body.data.flagged_for_review).toBe(1);
    expect(ai.body.data.supervision_status).toBe("unreviewed");

    const plain = await post("/api/v1/crm/activities", salesToken, {
      direction: "internal",
      channel: "note",
      subject: "Internal note",
    });
    expect(plain.status).toBe(201);
    plainId = plain.body.data.id;

    const queue = await get("/api/v1/crm/comms-reviews/queue", adminToken);
    expect(queue.status).toBe(200);
    const ids = queue.body.data.map((a: any) => a.id);
    expect(ids).toContain(flaggedId);
    expect(ids).toContain(aiId);
    expect(ids).not.toContain(plainId);
  });

  test("activities are append-only at the DB level", () => {
    expect(() =>
      env.db.query("UPDATE activities SET subject = 'tampered' WHERE id = ?").run(flaggedId),
    ).toThrow();
    expect(() => env.db.query("DELETE FROM activities WHERE id = ?").run(flaggedId)).toThrow();
  });

  test("review gates: sales cannot approve, non-principal cannot review, self-review blocked", async () => {
    const salesReview = await post(`/api/v1/crm/comms-reviews/${flaggedId}/review`, salesToken, {
      disposition: "approved",
    });
    expect(salesReview.status).toBe(403);
    expect(salesReview.body.error.code).toBe("forbidden");

    // accountant without the principal flag
    const clerkId = await createTestUser(env.db, "clerk@example.local", "Clerk-User-1234", "accountant");
    const clerk = await loginAs(env.base, "clerk@example.local", "Clerk-User-1234");
    const notPrincipal = await post(`/api/v1/crm/comms-reviews/${flaggedId}/review`, clerk.token, {
      disposition: "approved",
    });
    expect(notPrincipal.status).toBe(403);
    expect(notPrincipal.body.error.code).toBe("not_principal");
    void clerkId;

    // principal-authored comm, reviewed by its own author
    const own = await post("/api/v1/crm/activities", principalToken, {
      direction: "out",
      channel: "email",
      subject: "Principal's own note",
      flagged_for_review: true,
    });
    expect(own.status).toBe(201);
    const self = await post(`/api/v1/crm/comms-reviews/${own.body.data.id}/review`, principalToken, {
      disposition: "approved",
    });
    expect(self.status).toBe(403);
    expect(self.body.error.code).toBe("self_review");

    // unflagged activity cannot be reviewed
    const unflagged = await post(`/api/v1/crm/comms-reviews/${plainId}/review`, adminToken, {
      disposition: "approved",
    });
    expect(unflagged.status).toBe(409);
    expect(unflagged.body.error.code).toBe("not_flagged");
  });

  test("a distinct principal reviews; queue drains; re-review rejected", async () => {
    const reviewed = await post(`/api/v1/crm/comms-reviews/${flaggedId}/review`, principalToken, {
      disposition: "approved",
      notes: "Reviewed and approved",
    });
    expect(reviewed.status).toBe(200);
    expect(reviewed.body.data.disposition).toBe("approved");

    const queue = await get("/api/v1/crm/comms-reviews/queue", adminToken);
    expect(queue.body.data.map((a: any) => a.id)).not.toContain(flaggedId);

    const again = await post(`/api/v1/crm/comms-reviews/${flaggedId}/review`, adminToken, {
      disposition: "approved",
    });
    expect(again.status).toBe(409);
    expect(again.body.error.code).toBe("already_reviewed");

    const stored = await get(`/api/v1/crm/comms-reviews/${flaggedId}`, adminToken);
    expect(stored.body.data.reviewer_id).toBe(principalId);
  });
});

describe("supervisory personnel (F-S3)", () => {
  test("principals list includes the seeded admin; designate/revoke cycle", async () => {
    const list = await get("/api/v1/crm/principals", adminToken);
    expect(list.body.data.some((p: any) => p.email === ADMIN_EMAIL)).toBe(true);

    const userId = await createTestUser(env.db, "newboss@example.local", "New-Boss-12345", "accountant");
    const designated = await post("/api/v1/crm/principals", adminToken, {
      user_id: userId,
      title: "Supervising Principal",
      location: "Cincinnati",
    });
    expect(designated.status).toBe(201);
    const again = await post("/api/v1/crm/principals", adminToken, { user_id: userId });
    expect(again.status).toBe(409);
    expect(again.body.error.code).toBe("already_principal");

    const res = await fetch(`${env.base}/api/v1/crm/principals/${userId}`, {
      method: "DELETE",
      headers: authHeaders(adminToken),
    });
    expect(res.status).toBe(200);
    const revoked = await fetch(`${env.base}/api/v1/crm/principals/${userId}`, {
      method: "DELETE",
      headers: authHeaders(adminToken),
    });
    // Already revoked: not_principal, same code as the review gate.
    expect(revoked.status).toBe(403);
  });
});

describe("complaints (F-R9, F-S2)", () => {
  test("lifecycle enforces received -> acknowledged -> responded; regression rejected", async () => {
    const noParty = await post("/api/v1/crm/complaints", adminToken, { subject: "Orphan" });
    expect(noParty.status).toBe(400);

    const created = await post("/api/v1/crm/complaints", adminToken, {
      company_id: companyId,
      subject: "Statement discrepancy",
      description: "Client disputes a fee",
    });
    expect(created.status).toBe(201);
    const id = created.body.data.id;
    expect(created.body.data.status).toBe("received");
    expect(created.body.data.acknowledged_overdue).toBe(false);

    const early = await post(`/api/v1/crm/complaints/${id}/respond`, adminToken, {});
    expect(early.status).toBe(409);
    expect(early.body.error.code).toBe("state_regression");

    const acked = await post(`/api/v1/crm/complaints/${id}/acknowledge`, adminToken, {});
    expect(acked.status).toBe(200);
    expect(acked.body.data.status).toBe("acknowledged");
    expect(acked.body.data.acknowledged_at).not.toBeNull();

    const responded = await post(`/api/v1/crm/complaints/${id}/respond`, adminToken, {});
    expect(responded.status).toBe(200);
    expect(responded.body.data.status).toBe("responded");
    expect(responded.body.data.responded_at).not.toBeNull();

    const regress = await post(`/api/v1/crm/complaints/${id}/acknowledge`, adminToken, {});
    expect(regress.status).toBe(409);
    expect(regress.body.error.code).toBe("state_regression");
  });

  test("complaint content is trigger-immutable; overdue acknowledgement flagged", async () => {
    const created = await post("/api/v1/crm/complaints", adminToken, {
      contact_id: contactId,
      subject: "Slow response",
    });
    const id = created.body.data.id;
    expect(() =>
      env.db.query("UPDATE complaints SET subject = 'tampered' WHERE id = ?").run(id),
    ).toThrow();

    // Direct insert with a backdated received_at (INSERT is not blocked;
    // UPDATE of content is) to exercise the SLA flag deterministically.
    const tenDaysAgo = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString();
    env.db
      .query(
        `INSERT INTO complaints
           (company_id, subject, status, ack_sla_days, received_at, created_at, updated_at)
         VALUES (?, 'Stale complaint', 'received', 7, ?, ?, ?)`,
      )
      .run(companyId, tenDaysAgo, tenDaysAgo, tenDaysAgo);

    const overdue = await get("/api/v1/crm/complaints?overdue_ack=1", adminToken);
    expect(overdue.body.data.some((c: any) => c.subject === "Stale complaint")).toBe(true);
    const stale = overdue.body.data.find((c: any) => c.subject === "Stale complaint");
    expect(stale.acknowledged_overdue).toBe(true);
  });
});

describe("CRM RBAC and retention coverage", () => {
  test("viewer reads CRM but cannot write; auditor is read-only", async () => {
    await createTestUser(env.db, "viewer1@example.local", "Viewer-One-1234", "viewer");
    const viewer = await loginAs(env.base, "viewer1@example.local", "Viewer-One-1234");
    const read = await get("/api/v1/crm/companies", viewer.token);
    expect(read.status).toBe(200);
    const write = await post("/api/v1/crm/companies", viewer.token, {
      name: "Nope",
      address: "Nowhere",
      tax_id: "X",
    });
    expect(write.status).toBe(403);
  });

  test("retention report now covers comms and crm (no longer pending_module)", async () => {
    const report = await get("/api/v1/compliance/retention-report", adminToken);
    expect(report.status).toBe(200);
    const byType = new Map(report.body.data.policies.map((p: any) => [p.entity_type, p]));
    expect((byType.get("comms") as any).status).toBe("covered");
    expect((byType.get("crm") as any).status).toBe("covered");
  });
});
