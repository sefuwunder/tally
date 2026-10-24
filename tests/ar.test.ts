// Phase 3 tests: AR — customers, invoices, payments, credit memos,
// GL posting, application limits, void semantics, idempotency, RBAC.

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import {
  makeTestEnv,
  loginAs,
  authHeaders,
  createTestUser,
  type TestEnv,
} from "./helpers";

let env: TestEnv;
let adminToken: string;
let accountantToken: string;
let salesToken: string;
let auditorToken: string;
let apClerkToken: string;

beforeAll(async () => {
  env = await makeTestEnv();
  const admin = await loginAs(env.base, "admin@example.local", "Changeme-123456");
  expect(admin.status).toBe(200);
  adminToken = admin.token;

  const acctId = await createTestUser(env.db, "acct1@example.local", "Acctpass-123456", "accountant");
  const salesId = await createTestUser(env.db, "sales1@example.local", "Salespass-123456", "sales");
  const auditorId = await createTestUser(env.db, "auditor1@example.local", "Auditorpass-123456", "auditor");
  const clerkId = await createTestUser(env.db, "clerk1@example.local", "Clerkpass-123456", "ap_clerk");
  expect(acctId).toBeGreaterThan(0);
  expect(salesId).toBeGreaterThan(0);
  expect(auditorId).toBeGreaterThan(0);
  expect(clerkId).toBeGreaterThan(0);
  accountantToken = (await loginAs(env.base, "acct1@example.local", "Acctpass-123456")).token;
  salesToken = (await loginAs(env.base, "sales1@example.local", "Salespass-123456")).token;
  auditorToken = (await loginAs(env.base, "auditor1@example.local", "Auditorpass-123456")).token;
  apClerkToken = (await loginAs(env.base, "clerk1@example.local", "Clerkpass-123456")).token;
});

afterAll(() => env.cleanup());

const A = (t: string) => authHeaders(t);
const J = (o: unknown) => JSON.stringify(o);

async function api(
  method: string,
  path: string,
  token: string,
  body?: unknown,
  extraHeaders: Record<string, string> = {},
) {
  const res = await fetch(`${env.base}${path}`, {
    method,
    headers: { "content-type": "application/json", ...A(token), ...extraHeaders },
    body: body === undefined ? undefined : J(body),
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}

function today(): string {
  return new Date().toISOString().slice(0, 10);
}

function plusDays(d: string, n: number): string {
  const dt = new Date(`${d}T00:00:00Z`);
  dt.setUTCDate(dt.getUTCDate() + n);
  return dt.toISOString().slice(0, 10);
}

async function makeCustomer(token: string, name: string): Promise<any> {
  const { status, json } = await api("POST", "/api/v1/ar/customers", token, { name });
  expect(status).toBe(201);
  return json.data;
}

async function makeInvoice(
  token: string,
  customerId: number,
  over: Record<string, unknown> = {},
): Promise<any> {
  const { status, json } = await api("POST", "/api/v1/ar/invoices", token, {
    customer_id: customerId,
    issue_date: today(),
    due_date: plusDays(today(), 30),
    lines: [{ description: "Widget", quantity: 2, unit_price_cents: 5000 }],
    ...over,
  });
  expect(status).toBe(201);
  return json.data;
}

async function postInvoice(token: string, id: number, key?: string): Promise<{ status: number; json: any }> {
  return api("POST", `/api/v1/ar/invoices/${id}/post`, token, undefined, key ? { "idempotency-key": key } : {});
}

let accountIds: Record<string, number> = {};

async function arBalance(): Promise<number> {
  if (!accountIds["1100"]) {
    const { json } = await api("GET", "/api/v1/ledger/accounts", adminToken);
    for (const a of json.data) accountIds[a.code] = a.id;
  }
  const { json } = await api("GET", `/api/v1/ledger/accounts/${accountIds["1100"]}/ledger`, adminToken);
  return json.data.closing_balance_cents;
}

// --- customers ------------------------------------------------------------------

describe("customers", () => {
  test("create + get + list", async () => {
    const c = await makeCustomer(adminToken, "Acme Corp");
    expect(c.status).toBe("active");
    expect(c.credit_limit_cents).toBe(0);
    const { status, json } = await api("GET", `/api/v1/ar/customers/${c.id}`, adminToken);
    expect(status).toBe(200);
    expect(json.data.name).toBe("Acme Corp");
  });

  test("validation: empty name, bad email", async () => {
    const r1 = await api("POST", "/api/v1/ar/customers", adminToken, { name: "  " });
    expect(r1.status).toBe(400);
    expect(r1.json.error.code).toBe("validation");
    const r2 = await api("POST", "/api/v1/ar/customers", adminToken, {
      name: "Bad Email Co",
      email: "not-an-email",
    });
    expect(r2.status).toBe(400);
    expect(r2.json.error.code).toBe("validation");
  });

  test("patch + status filter", async () => {
    const c = await makeCustomer(adminToken, "Filterable LLC");
    const { status, json } = await api("PATCH", `/api/v1/ar/customers/${c.id}`, adminToken, {
      status: "inactive",
      phone: "555-0100",
    });
    expect(status).toBe(200);
    expect(json.data.status).toBe("inactive");
    expect(json.data.phone).toBe("555-0100");
    const list = await api("GET", "/api/v1/ar/customers?status=inactive", adminToken);
    expect(list.status).toBe(200);
    expect(list.json.data.some((x: any) => x.id === c.id)).toBe(true);
  });

  test("missing customer 404", async () => {
    const { status, json } = await api("GET", "/api/v1/ar/customers/999999", adminToken);
    expect(status).toBe(404);
    expect(json.error.code).toBe("not_found");
  });
});

// --- invoices -------------------------------------------------------------------

describe("invoices: create + draft rules", () => {
  test("totals == sum(lines) + tax", async () => {
    const c = await makeCustomer(adminToken, "Totals Inc");
    const inv = await makeInvoice(adminToken, c.id, {
      tax_cents: 800,
      lines: [
        { description: "A", quantity: 2, unit_price_cents: 5000 },
        { description: "B", quantity: 1, unit_price_cents: 2500 },
      ],
    });
    expect(inv.status).toBe("draft");
    expect(inv.subtotal_cents).toBe(12500);
    expect(inv.tax_cents).toBe(800);
    expect(inv.total_cents).toBe(13300);
    expect(inv.open_balance_cents).toBe(13300);
    expect(inv.lines.length).toBe(2);
    expect(inv.lines[0].amount_cents).toBe(10000);
  });

  test("validation: no lines, zero total, due before issue, unknown customer", async () => {
    const c = await makeCustomer(adminToken, "Validation Co");
    const base = { customer_id: c.id, issue_date: today(), due_date: plusDays(today(), 30) };
    const r1 = await api("POST", "/api/v1/ar/invoices", adminToken, { ...base, lines: [] });
    expect(r1.status).toBe(400);
    const r2 = await api("POST", "/api/v1/ar/invoices", adminToken, {
      ...base,
      lines: [{ description: "Free", quantity: 1, unit_price_cents: 0 }],
    });
    expect(r2.status).toBe(400);
    const r3 = await api("POST", "/api/v1/ar/invoices", adminToken, {
      ...base,
      due_date: plusDays(today(), -1),
      lines: [{ description: "X", quantity: 1, unit_price_cents: 100 }],
    });
    expect(r3.status).toBe(400);
    const r4 = await api("POST", "/api/v1/ar/invoices", adminToken, {
      ...base,
      customer_id: 999999,
      lines: [{ description: "X", quantity: 1, unit_price_cents: 100 }],
    });
    expect(r4.status).toBe(404);
  });

  test("draft edit recomputes totals; posted invoice edit rejected", async () => {
    const c = await makeCustomer(adminToken, "Edit Co");
    const inv = await makeInvoice(adminToken, c.id);
    const { status, json } = await api("PATCH", `/api/v1/ar/invoices/${inv.id}`, adminToken, {
      tax_cents: 500,
      lines: [{ description: "New", quantity: 3, unit_price_cents: 1000 }],
    });
    expect(status).toBe(200);
    expect(json.data.subtotal_cents).toBe(3000);
    expect(json.data.total_cents).toBe(3500);
    const posted = await postInvoice(accountantToken, inv.id);
    expect(posted.status).toBe(200);
    expect(posted.json.data.status).toBe("posted");
    const edit = await api("PATCH", `/api/v1/ar/invoices/${inv.id}`, adminToken, {
      tax_cents: 0,
    });
    expect(edit.status).toBe(409);
    expect(edit.json.error.code).toBe("not_draft");
  });
});

describe("invoices: posting + GL", () => {
  test("post creates Dr AR / Cr Revenue / Cr Tax entry", async () => {
    const c = await makeCustomer(adminToken, "Poster Co");
    const inv = await makeInvoice(adminToken, c.id, {
      tax_cents: 800,
      lines: [{ description: "Service", quantity: 1, unit_price_cents: 10000 }],
    });
    const before = await arBalance();
    const posted = await postInvoice(accountantToken, inv.id);
    expect(posted.status).toBe(200);
    expect(posted.json.data.posted_entry_id).toBeGreaterThan(0);
    const entry = await api(
      "GET",
      `/api/v1/ledger/journal/${posted.json.data.posted_entry_id}`,
      adminToken,
    );
    expect(entry.status).toBe(200);
    const lines = entry.json.data.lines;
    expect(lines.find((l: any) => l.account_code === "1100")?.debit_cents).toBe(10800);
    expect(lines.find((l: any) => l.account_code === "4000")?.credit_cents).toBe(10000);
    expect(lines.find((l: any) => l.account_code === "2100")?.credit_cents).toBe(800);
    expect(entry.json.data.source_type).toBe("ar");
    expect(await arBalance()).toBe(before + 10800);
  });

  test("double post rejected; post idempotency replays", async () => {
    const c = await makeCustomer(adminToken, "Idem Co");
    const inv = await makeInvoice(adminToken, c.id);
    const first = await postInvoice(accountantToken, inv.id, "idem-inv-1");
    expect(first.status).toBe(200);
    const replay = await postInvoice(accountantToken, inv.id, "idem-inv-1");
    expect(replay.status).toBe(200);
    expect(replay.json.data.posted_entry_id).toBe(first.json.data.posted_entry_id);
    const again = await postInvoice(accountantToken, inv.id);
    expect(again.status).toBe(409);
    expect(again.json.error.code).toBe("already_posted");
  });
});

// --- payments -------------------------------------------------------------------

describe("payments", () => {
  test("full payment marks invoice paid; AR returns to zero", async () => {
    const c = await makeCustomer(adminToken, "Payer Co");
    const inv = await makeInvoice(adminToken, c.id);
    await postInvoice(accountantToken, inv.id);
    const before = await arBalance();
    const { status, json } = await api("POST", "/api/v1/ar/payments", accountantToken, {
      customer_id: c.id,
      method: "check",
      amount_cents: 10000,
      received_on: today(),
      applications: [{ invoice_id: inv.id, amount_cents: 10000 }],
    });
    expect(status).toBe(201);
    expect(json.data.unapplied_cents).toBe(0);
    expect(json.data.applications.length).toBe(1);
    const invAfter = await api("GET", `/api/v1/ar/invoices/${inv.id}`, adminToken);
    expect(invAfter.json.data.status).toBe("paid");
    expect(invAfter.json.data.open_balance_cents).toBe(0);
    // 'before' was measured after the invoice posted, so the payment's
    // Cr AR 10000 brings the balance back down by exactly the invoice total.
    expect(await arBalance()).toBe(before - 10000);
  });

  test("partial payment -> partially_paid; later apply of credit completes it", async () => {
    const c = await makeCustomer(adminToken, "Partial Co");
    const inv = await makeInvoice(adminToken, c.id);
    await postInvoice(accountantToken, inv.id);
    const pay = await api("POST", "/api/v1/ar/payments", accountantToken, {
      customer_id: c.id,
      method: "wire",
      amount_cents: 10000,
      received_on: today(),
      applications: [{ invoice_id: inv.id, amount_cents: 4000 }],
    });
    expect(pay.status).toBe(201);
    expect(pay.json.data.unapplied_cents).toBe(6000);
    const mid = await api("GET", `/api/v1/ar/invoices/${inv.id}`, adminToken);
    expect(mid.json.data.status).toBe("partially_paid");
    expect(mid.json.data.open_balance_cents).toBe(6000);
    const apply = await api("POST", `/api/v1/ar/payments/${pay.json.data.id}/apply`, accountantToken, {
      invoice_id: inv.id,
      amount_cents: 6000,
    });
    expect(apply.status).toBe(200);
    expect(apply.json.data.unapplied_cents).toBe(0);
    const done = await api("GET", `/api/v1/ar/invoices/${inv.id}`, adminToken);
    expect(done.json.data.status).toBe("paid");
  });

  test("over-application rejected: single, combined, unapplied, wrong customer, draft", async () => {
    const c = await makeCustomer(adminToken, "Over Co");
    const other = await makeCustomer(adminToken, "Other Co");
    const inv = await makeInvoice(adminToken, c.id);
    await postInvoice(accountantToken, inv.id);
    const draft = await makeInvoice(adminToken, c.id);

    // single application over open balance
    const r1 = await api("POST", "/api/v1/ar/payments", accountantToken, {
      customer_id: c.id,
      method: "cash",
      amount_cents: 20000,
      received_on: today(),
      applications: [{ invoice_id: inv.id, amount_cents: 10001 }],
    });
    expect(r1.status).toBe(400);
    expect(r1.json.error.code).toBe("over_applied");

    // two applications to the same invoice jointly over-apply
    const r2 = await api("POST", "/api/v1/ar/payments", accountantToken, {
      customer_id: c.id,
      method: "cash",
      amount_cents: 20000,
      received_on: today(),
      applications: [
        { invoice_id: inv.id, amount_cents: 6000 },
        { invoice_id: inv.id, amount_cents: 5000 },
      ],
    });
    expect(r2.status).toBe(400);
    expect(r2.json.error.code).toBe("over_applied");

    // applications sum over payment amount
    const r3 = await api("POST", "/api/v1/ar/payments", accountantToken, {
      customer_id: c.id,
      method: "cash",
      amount_cents: 5000,
      received_on: today(),
      applications: [{ invoice_id: inv.id, amount_cents: 6000 }],
    });
    expect(r3.status).toBe(400);
    expect(r3.json.error.code).toBe("over_applied");

    // wrong-customer invoice
    const r4 = await api("POST", "/api/v1/ar/payments", accountantToken, {
      customer_id: other.id,
      method: "cash",
      amount_cents: 1000,
      received_on: today(),
      applications: [{ invoice_id: inv.id, amount_cents: 1000 }],
    });
    expect(r4.status).toBe(400);
    expect(r4.json.error.code).toBe("validation");

    // draft invoice cannot receive payments
    const r5 = await api("POST", "/api/v1/ar/payments", accountantToken, {
      customer_id: c.id,
      method: "cash",
      amount_cents: 1000,
      received_on: today(),
      applications: [{ invoice_id: draft.id, amount_cents: 1000 }],
    });
    expect(r5.status).toBe(400);
    expect(r5.json.error.code).toBe("validation");

    // apply beyond unapplied credit
    const pay = await api("POST", "/api/v1/ar/payments", accountantToken, {
      customer_id: c.id,
      method: "cash",
      amount_cents: 3000,
      received_on: today(),
    });
    expect(pay.status).toBe(201);
    expect(pay.json.data.unapplied_cents).toBe(3000);
    const r6 = await api("POST", `/api/v1/ar/payments/${pay.json.data.id}/apply`, accountantToken, {
      invoice_id: inv.id,
      amount_cents: 3001,
    });
    expect(r6.status).toBe(400);
    expect(r6.json.error.code).toBe("over_applied");

    // failed payments created nothing (only the on-account one exists)
    const list = await api("GET", `/api/v1/ar/payments?customer_id=${c.id}`, adminToken);
    expect(list.json.data.length).toBe(1);
  });

  test("payment idempotency: same key creates one payment", async () => {
    const c = await makeCustomer(adminToken, "PayIdem Co");
    const first = await api(
      "POST",
      "/api/v1/ar/payments",
      accountantToken,
      { customer_id: c.id, method: "card", amount_cents: 7000, received_on: today() },
      { "idempotency-key": "pay-1" },
    );
    expect(first.status).toBe(201);
    const replay = await api(
      "POST",
      "/api/v1/ar/payments",
      accountantToken,
      { customer_id: c.id, method: "card", amount_cents: 7000, received_on: today() },
      { "idempotency-key": "pay-1" },
    );
    expect(replay.status).toBe(201);
    expect(replay.json.data.payment_no).toBe(first.json.data.payment_no);
    const list = await api("GET", `/api/v1/ar/payments?customer_id=${c.id}`, adminToken);
    expect(list.json.data.length).toBe(1);
  });
});

// --- void -----------------------------------------------------------------------

describe("void", () => {
  test("void of clean invoice nets AR to zero; original entry untouched", async () => {
    const c = await makeCustomer(adminToken, "Void Co");
    const inv = await makeInvoice(adminToken, c.id);
    const posted = await postInvoice(accountantToken, inv.id);
    const originalId = posted.json.data.posted_entry_id;
    const before = await arBalance();
    const { status, json } = await api("POST", `/api/v1/ar/invoices/${inv.id}/void`, accountantToken);
    expect(status).toBe(200);
    expect(json.data.status).toBe("void");
    expect(json.data.void_entry_id).toBeGreaterThan(0);
    expect(await arBalance()).toBe(before - 10000);
    // original entry still there, untouched
    const orig = await api("GET", `/api/v1/ledger/journal/${originalId}`, adminToken);
    expect(orig.status).toBe(200);
    expect(orig.json.data.lines.find((l: any) => l.account_code === "1100")?.debit_cents).toBe(10000);
    // reversal entry links back
    const rev = await api("GET", `/api/v1/ledger/journal/${json.data.void_entry_id}`, adminToken);
    expect(rev.status).toBe(200);
    expect(rev.json.data.reversed_by).toBe(originalId);
    expect(rev.json.data.lines.find((l: any) => l.account_code === "1100")?.credit_cents).toBe(10000);
    // void is audited
    const log = await api("GET", "/api/v1/compliance/audit-log?action=invoice.void", auditorToken);
    expect(log.status).toBe(200);
    expect(log.json.data.some((r: any) => r.entity_id === inv.invoice_no)).toBe(true);
    // second void rejected
    const again = await api("POST", `/api/v1/ar/invoices/${inv.id}/void`, accountantToken);
    expect(again.status).toBe(409);
    expect(again.json.error.code).toBe("already_void");
  });

  test("void blocked while payments applied", async () => {
    const c = await makeCustomer(adminToken, "VoidBlocked Co");
    const inv = await makeInvoice(adminToken, c.id);
    await postInvoice(accountantToken, inv.id);
    const pay = await api("POST", "/api/v1/ar/payments", accountantToken, {
      customer_id: c.id,
      method: "cash",
      amount_cents: 1000,
      received_on: today(),
      applications: [{ invoice_id: inv.id, amount_cents: 1000 }],
    });
    expect(pay.status).toBe(201);
    const v = await api("POST", `/api/v1/ar/invoices/${inv.id}/void`, accountantToken);
    expect(v.status).toBe(409);
    expect(v.json.error.code).toBe("void_blocked");
  });
});

// --- credit memos ---------------------------------------------------------------

describe("credit memos", () => {
  test("post reduces open balance; void restores it", async () => {
    const c = await makeCustomer(adminToken, "Credit Co");
    const inv = await makeInvoice(adminToken, c.id);
    await postInvoice(accountantToken, inv.id);
    const cm = await api("POST", "/api/v1/ar/credit-memos", accountantToken, {
      customer_id: c.id,
      invoice_id: inv.id,
      amount_cents: 3000,
      reason: "Damaged goods",
    });
    expect(cm.status).toBe(201);
    expect(cm.json.data.status).toBe("draft");
    const posted = await api("POST", `/api/v1/ar/credit-memos/${cm.json.data.id}/post`, accountantToken);
    expect(posted.status).toBe(200);
    expect(posted.json.data.status).toBe("posted");
    const mid = await api("GET", `/api/v1/ar/invoices/${inv.id}`, adminToken);
    expect(mid.json.data.credited_cents).toBe(3000);
    expect(mid.json.data.open_balance_cents).toBe(7000);
    expect(mid.json.data.status).toBe("partially_paid");
    // GL: Dr Revenue / Cr AR
    const entry = await api(
      "GET",
      `/api/v1/ledger/journal/${posted.json.data.posted_entry_id}`,
      adminToken,
    );
    expect(entry.json.data.lines.find((l: any) => l.account_code === "4000")?.debit_cents).toBe(3000);
    expect(entry.json.data.lines.find((l: any) => l.account_code === "1100")?.credit_cents).toBe(3000);
    // void restores
    const voided = await api("POST", `/api/v1/ar/credit-memos/${cm.json.data.id}/void`, accountantToken);
    expect(voided.status).toBe(200);
    expect(voided.json.data.status).toBe("void");
    const restored = await api("GET", `/api/v1/ar/invoices/${inv.id}`, adminToken);
    expect(restored.json.data.credited_cents).toBe(0);
    expect(restored.json.data.open_balance_cents).toBe(10000);
    expect(restored.json.data.status).toBe("posted");
  });

  test("over-credit rejected at create and at post (balance moved since)", async () => {
    const c = await makeCustomer(adminToken, "OverCredit Co");
    const inv = await makeInvoice(adminToken, c.id);
    await postInvoice(accountantToken, inv.id);
    const r1 = await api("POST", "/api/v1/ar/credit-memos", accountantToken, {
      customer_id: c.id,
      invoice_id: inv.id,
      amount_cents: 10001,
      reason: "Too much",
    });
    expect(r1.status).toBe(400);
    expect(r1.json.error.code).toBe("over_applied");
    // draft for the full balance, then a payment lands, then post must refuse
    const cm = await api("POST", "/api/v1/ar/credit-memos", accountantToken, {
      customer_id: c.id,
      invoice_id: inv.id,
      amount_cents: 10000,
      reason: "Full return",
    });
    expect(cm.status).toBe(201);
    const pay = await api("POST", "/api/v1/ar/payments", accountantToken, {
      customer_id: c.id,
      method: "cash",
      amount_cents: 4000,
      received_on: today(),
      applications: [{ invoice_id: inv.id, amount_cents: 4000 }],
    });
    expect(pay.status).toBe(201);
    const r2 = await api("POST", `/api/v1/ar/credit-memos/${cm.json.data.id}/post`, accountantToken);
    expect(r2.status).toBe(400);
    expect(r2.json.error.code).toBe("over_applied");
  });
});

// --- RBAC -----------------------------------------------------------------------

describe("ar RBAC", () => {
  test("sales cannot write; auditor reads; ap_clerk cannot post; accountant posts", async () => {
    const c = await makeCustomer(adminToken, "Rbac Co");
    const denied = await api("POST", "/api/v1/ar/customers", salesToken, { name: "Nope" });
    expect(denied.status).toBe(403);
    const read = await api("GET", `/api/v1/ar/customers/${c.id}`, auditorToken);
    expect(read.status).toBe(200);
    const inv = await makeInvoice(adminToken, c.id);
    const clerkPost = await postInvoice(apClerkToken, inv.id);
    expect(clerkPost.status).toBe(403);
    const acctPost = await postInvoice(accountantToken, inv.id);
    expect(acctPost.status).toBe(200);
    const salesVoid = await api("POST", `/api/v1/ar/invoices/${inv.id}/void`, salesToken);
    expect(salesVoid.status).toBe(403);
  });
});
