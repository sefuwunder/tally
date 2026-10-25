// Phase 4 tests: AP — vendors, bills with maker-checker approval,
// GL posting, payment application limits, void semantics, idempotency, RBAC.

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

async function makeVendor(token: string, name: string): Promise<any> {
  const { status, json } = await api("POST", "/api/v1/ap/vendors", token, { name });
  expect(status).toBe(201);
  return json.data;
}

async function makeBill(
  token: string,
  vendorId: number,
  over: Record<string, unknown> = {},
): Promise<any> {
  const { status, json } = await api("POST", "/api/v1/ap/bills", token, {
    vendor_id: vendorId,
    bill_date: today(),
    due_date: plusDays(today(), 30),
    lines: [{ description: "Office rent", quantity: 1, unit_price_cents: 10000, account_code: "6100" }],
    ...over,
  });
  expect(status).toBe(201);
  return json.data;
}

/** Full happy path: clerk creates, accountant approves, clerk posts. */
async function makePostedBill(token: string, vendorId: number, over: Record<string, unknown> = {}): Promise<any> {
  const bill = await makeBill(apClerkToken, vendorId, over);
  const approved = await api("POST", `/api/v1/ap/bills/${bill.id}/approve`, accountantToken);
  expect(approved.status).toBe(200);
  const posted = await api("POST", `/api/v1/ap/bills/${bill.id}/post`, token);
  expect(posted.status).toBe(200);
  return posted.json.data;
}

let accountIds: Record<string, number> = {};

async function accountBalance(code: string): Promise<number> {
  if (!accountIds[code]) {
    const { json } = await api("GET", "/api/v1/ledger/accounts", adminToken);
    for (const a of json.data) accountIds[a.code] = a.id;
  }
  const { json } = await api("GET", `/api/v1/ledger/accounts/${accountIds[code]}/ledger`, adminToken);
  return json.data.closing_balance_cents;
}

async function trialBalanced(): Promise<boolean> {
  const { json } = await api("GET", "/api/v1/ledger/periods", adminToken);
  const period = json.data[0];
  const { json: tb } = await api(
    "GET",
    `/api/v1/ledger/trial-balance?period_id=${period.id}`,
    adminToken,
  );
  return tb.data.balanced === true && tb.data.total_debits === tb.data.total_credits;
}

// --- vendors ------------------------------------------------------------------

describe("vendors", () => {
  test("create + get + list", async () => {
    const v = await makeVendor(adminToken, "Paper Supply Co");
    expect(v.status).toBe("active");
    const { status, json } = await api("GET", `/api/v1/ap/vendors/${v.id}`, adminToken);
    expect(status).toBe(200);
    expect(json.data.name).toBe("Paper Supply Co");
  });

  test("validation: empty name, bad email", async () => {
    const { status: s1, json: j1 } = await api("POST", "/api/v1/ap/vendors", adminToken, { name: "  " });
    expect(s1).toBe(400);
    expect(j1.error.code).toBe("validation");
    const { status: s2 } = await api("POST", "/api/v1/ap/vendors", adminToken, {
      name: "Bad Email Co",
      email: "not-an-email",
    });
    expect(s2).toBe(400);
  });

  test("update vendor", async () => {
    const v = await makeVendor(adminToken, "Update Me Ltd");
    const { status, json } = await api("PATCH", `/api/v1/ap/vendors/${v.id}`, adminToken, {
      status: "inactive",
    });
    expect(status).toBe(200);
    expect(json.data.status).toBe("inactive");
  });
});

// --- bills: creation + validation ---------------------------------------------

describe("bills", () => {
  test("totals equal sum of lines plus tax", async () => {
    const v = await makeVendor(adminToken, "Totals Vendor");
    const b = await makeBill(adminToken, v.id, {
      tax_cents: 1000,
      lines: [
        { description: "A", quantity: 2, unit_price_cents: 5000, account_code: "6200" },
        { description: "B", quantity: 1, unit_price_cents: 3000, account_code: "6300" },
      ],
    });
    expect(b.subtotal_cents).toBe(13000);
    expect(b.tax_cents).toBe(1000);
    expect(b.total_cents).toBe(14000);
    expect(b.open_balance_cents).toBe(14000);
    expect(b.status).toBe("draft");
  });

  test("validation: due before bill date, unknown account, no lines", async () => {
    const v = await makeVendor(adminToken, "Validation Vendor");
    const base = {
      vendor_id: v.id,
      bill_date: today(),
      due_date: plusDays(today(), 30),
      lines: [{ description: "X", quantity: 1, unit_price_cents: 100, account_code: "6200" }],
    };
    const { status: s1 } = await api("POST", "/api/v1/ap/bills", adminToken, {
      ...base,
      due_date: plusDays(today(), -1),
    });
    expect(s1).toBe(400);
    const { status: s2, json: j2 } = await api("POST", "/api/v1/ap/bills", adminToken, {
      ...base,
      lines: [{ description: "X", quantity: 1, unit_price_cents: 100, account_code: "9999" }],
    });
    expect(s2).toBe(400);
    expect(j2.error.code).toBe("validation");
    const { status: s3 } = await api("POST", "/api/v1/ap/bills", adminToken, { ...base, lines: [] });
    expect(s3).toBe(400);
  });

  test("draft edit recomputes totals; edit after approval rejected", async () => {
    const v = await makeVendor(adminToken, "Draft Edit Vendor");
    const b = await makeBill(apClerkToken, v.id);
    const { status, json } = await api("PATCH", `/api/v1/ap/bills/${b.id}`, apClerkToken, {
      lines: [{ description: "New", quantity: 3, unit_price_cents: 2000, account_code: "6200" }],
      tax_cents: 500,
    });
    expect(status).toBe(200);
    expect(json.data.total_cents).toBe(6500);
    const approved = await api("POST", `/api/v1/ap/bills/${b.id}/approve`, accountantToken);
    expect(approved.status).toBe(200);
    const { status: s2, json: j2 } = await api("PATCH", `/api/v1/ap/bills/${b.id}`, apClerkToken, {
      tax_cents: 0,
    });
    expect(s2).toBe(409);
    expect(j2.error.code).toBe("not_draft");
  });
});

// --- bills: maker-checker approval --------------------------------------------

describe("maker-checker", () => {
  test("unapproved bill cannot post", async () => {
    const v = await makeVendor(adminToken, "Unapproved Vendor");
    const b = await makeBill(apClerkToken, v.id);
    const { status, json } = await api("POST", `/api/v1/ap/bills/${b.id}/post`, apClerkToken);
    expect(status).toBe(409);
    expect(json.error.code).toBe("not_approved");
  });

  test("approval by second user required: clerk lacks approve, creator cannot self-approve", async () => {
    const v = await makeVendor(adminToken, "Checker Vendor");
    const clerkBill = await makeBill(apClerkToken, v.id);
    // ap_clerk has ap:post but NOT ap:approve → 403 at the permission layer.
    const { status: s1 } = await api("POST", `/api/v1/ap/bills/${clerkBill.id}/approve`, apClerkToken);
    expect(s1).toBe(403);
    // Second user with approve permission succeeds and is recorded.
    const { status: s2, json: j2 } = await api(
      "POST",
      `/api/v1/ap/bills/${clerkBill.id}/approve`,
      accountantToken,
    );
    expect(s2).toBe(200);
    expect(j2.data.status).toBe("approved");
    expect(j2.data.approved_by).not.toBeNull();
    expect(j2.data.approved_at).not.toBeNull();

    // Creator with approve permission still cannot approve their own bill.
    const ownBill = await makeBill(accountantToken, v.id);
    const { status: s3, json: j3 } = await api(
      "POST",
      `/api/v1/ap/bills/${ownBill.id}/approve`,
      accountantToken,
    );
    expect(s3).toBe(403);
    expect(j3.error.code).toBe("self_approval");
    // ...but a different approver can.
    const { status: s4 } = await api("POST", `/api/v1/ap/bills/${ownBill.id}/approve`, adminToken);
    expect(s4).toBe(200);
  });

  test("double approval rejected", async () => {
    const v = await makeVendor(adminToken, "Double Approve Vendor");
    const b = await makeBill(apClerkToken, v.id);
    expect((await api("POST", `/api/v1/ap/bills/${b.id}/approve`, accountantToken)).status).toBe(200);
    const { status, json } = await api("POST", `/api/v1/ap/bills/${b.id}/approve`, adminToken);
    expect(status).toBe(409);
    expect(json.error.code).toBe("already_approved");
  });
});

// --- bills: posting + GL ------------------------------------------------------

describe("bill posting and void", () => {
  test("post debits expense and credits AP; trial balance stays balanced", async () => {
    const v = await makeVendor(adminToken, "Post GL Vendor");
    const apBefore = await accountBalance("2000");
    const expBefore = await accountBalance("6100");
    const b = await makePostedBill(apClerkToken, v.id);
    expect(b.status).toBe("posted");
    expect(b.posted_entry_id).not.toBeNull();
    expect((await accountBalance("2000")) - apBefore).toBe(10000);
    expect((await accountBalance("6100")) - expBefore).toBe(10000);
    expect(await trialBalanced()).toBe(true);
  });

  test("post with multi-account lines debits each line account", async () => {
    const v = await makeVendor(adminToken, "Multi Account Vendor");
    const supBefore = await accountBalance("6200");
    const svcBefore = await accountBalance("6300");
    await makePostedBill(apClerkToken, v.id, {
      lines: [
        { description: "Supplies", quantity: 1, unit_price_cents: 4000, account_code: "6200" },
        { description: "Consulting", quantity: 1, unit_price_cents: 6000, account_code: "6300" },
      ],
    });
    expect((await accountBalance("6200")) - supBefore).toBe(4000);
    expect((await accountBalance("6300")) - svcBefore).toBe(6000);
    expect(await trialBalanced()).toBe(true);
  });

  test("void nets AP to zero and original entry untouched; double void rejected", async () => {
    const v = await makeVendor(adminToken, "Void Vendor");
    const apBefore = await accountBalance("2000");
    const b = await makePostedBill(apClerkToken, v.id);
    expect((await accountBalance("2000")) - apBefore).toBe(10000);
    const { status, json } = await api("POST", `/api/v1/ap/bills/${b.id}/void`, accountantToken);
    expect(status).toBe(200);
    expect(json.data.status).toBe("void");
    expect(json.data.void_entry_id).not.toBeNull();
    expect(json.data.void_entry_id).not.toBe(b.posted_entry_id);
    expect((await accountBalance("2000")) - apBefore).toBe(0);
    expect(await trialBalanced()).toBe(true);
    const { status: s2, json: j2 } = await api("POST", `/api/v1/ap/bills/${b.id}/void`, accountantToken);
    expect(s2).toBe(409);
    expect(j2.error.code).toBe("already_void");
  });

  test("void of draft bill rejected; void blocked while payments applied", async () => {
    const v = await makeVendor(adminToken, "Void Block Vendor");
    const draft = await makeBill(apClerkToken, v.id);
    const { status: s1, json: j1 } = await api("POST", `/api/v1/ap/bills/${draft.id}/void`, accountantToken);
    expect(s1).toBe(409);
    expect(j1.error.code).toBe("not_posted");

    const posted = await makePostedBill(apClerkToken, v.id);
    const { status: sp } = await api("POST", "/api/v1/ap/bill-payments", apClerkToken, {
      vendor_id: v.id,
      method: "check",
      amount_cents: 1000,
      paid_on: today(),
      applications: [{ bill_id: posted.id, amount_cents: 1000 }],
    });
    expect(sp).toBe(201);
    const { status: s2, json: j2 } = await api("POST", `/api/v1/ap/bills/${posted.id}/void`, accountantToken);
    expect(s2).toBe(409);
    expect(j2.error.code).toBe("void_blocked");
  });

  test("idempotent bill post replays the original", async () => {
    const v = await makeVendor(adminToken, "Idem Post Vendor");
    const b = await makeBill(apClerkToken, v.id);
    expect((await api("POST", `/api/v1/ap/bills/${b.id}/approve`, accountantToken)).status).toBe(200);
    const key = `idem-bill-${b.id}`;
    const first = await api("POST", `/api/v1/ap/bills/${b.id}/post`, apClerkToken, undefined, {
      "idempotency-key": key,
    });
    expect(first.status).toBe(200);
    const second = await api("POST", `/api/v1/ap/bills/${b.id}/post`, apClerkToken, undefined, {
      "idempotency-key": key,
    });
    expect(second.status).toBe(200);
    expect(second.json.data.posted_entry_id).toBe(first.json.data.posted_entry_id);
    // Only one posted entry exists for this bill (no double-post).
    const { json } = await api("GET", `/api/v1/ap/bills/${b.id}`, adminToken);
    expect(json.data.status).toBe("posted");
  });
});

// --- bill payments ------------------------------------------------------------

describe("bill payments", () => {
  test("partial then full payment tracks open balance exactly", async () => {
    const v = await makeVendor(adminToken, "Pay Vendor");
    const b = await makePostedBill(apClerkToken, v.id);
    expect(b.open_balance_cents).toBe(10000);
    const { status: s1, json: j1 } = await api("POST", "/api/v1/ap/bill-payments", apClerkToken, {
      vendor_id: v.id,
      method: "wire",
      amount_cents: 4000,
      paid_on: today(),
      applications: [{ bill_id: b.id, amount_cents: 4000 }],
    });
    expect(s1).toBe(201);
    expect(j1.data.unapplied_cents).toBe(0);
    let { json: got } = await api("GET", `/api/v1/ap/bills/${b.id}`, adminToken);
    expect(got.data.status).toBe("partially_paid");
    expect(got.data.open_balance_cents).toBe(6000);
    const { status: s2 } = await api("POST", "/api/v1/ap/bill-payments", apClerkToken, {
      vendor_id: v.id,
      method: "wire",
      amount_cents: 6000,
      paid_on: today(),
      applications: [{ bill_id: b.id, amount_cents: 6000 }],
    });
    expect(s2).toBe(201);
    got = (await api("GET", `/api/v1/ap/bills/${b.id}`, adminToken)).json;
    expect(got.data.status).toBe("paid");
    expect(got.data.open_balance_cents).toBe(0);
    expect(await trialBalanced()).toBe(true);
  });

  test("over-application rejected: single, combined, and wrong vendor", async () => {
    const v = await makeVendor(adminToken, "Over Vendor");
    const other = await makeVendor(adminToken, "Other Vendor");
    const b = await makePostedBill(apClerkToken, v.id);
    const base = { vendor_id: v.id, method: "check", paid_on: today() };
    const { status: s1, json: j1 } = await api("POST", "/api/v1/ap/bill-payments", apClerkToken, {
      ...base,
      amount_cents: 10001,
      applications: [{ bill_id: b.id, amount_cents: 10001 }],
    });
    expect(s1).toBe(400);
    expect(j1.error.code).toBe("over_applied");
    const { status: s2 } = await api("POST", "/api/v1/ap/bill-payments", apClerkToken, {
      ...base,
      amount_cents: 11000,
      applications: [
        { bill_id: b.id, amount_cents: 6000 },
        { bill_id: b.id, amount_cents: 5000 },
      ],
    });
    expect(s2).toBe(400);
    const { status: s3 } = await api("POST", "/api/v1/ap/bill-payments", apClerkToken, {
      ...base,
      vendor_id: other.id,
      amount_cents: 1000,
      applications: [{ bill_id: b.id, amount_cents: 1000 }],
    });
    expect(s3).toBe(400);
  });

  test("unapplied credit then later apply; payment to draft bill rejected", async () => {
    const v = await makeVendor(adminToken, "Credit Vendor");
    const b = await makePostedBill(apClerkToken, v.id);
    const draft = await makeBill(apClerkToken, v.id);
    const { status: sd } = await api("POST", "/api/v1/ap/bill-payments", apClerkToken, {
      vendor_id: v.id,
      method: "cash",
      amount_cents: 1000,
      paid_on: today(),
      applications: [{ bill_id: draft.id, amount_cents: 1000 }],
    });
    expect(sd).toBe(400);
    const { status, json } = await api("POST", "/api/v1/ap/bill-payments", apClerkToken, {
      vendor_id: v.id,
      method: "cash",
      amount_cents: 12000,
      paid_on: today(),
      applications: [{ bill_id: b.id, amount_cents: 10000 }],
    });
    expect(status).toBe(201);
    expect(json.data.unapplied_cents).toBe(2000);
    const b2 = await makePostedBill(apClerkToken, v.id);
    const { status: s2, json: j2 } = await api(
      "POST",
      `/api/v1/ap/bill-payments/${json.data.id}/apply`,
      apClerkToken,
      { bill_id: b2.id, amount_cents: 2000 },
    );
    expect(s2).toBe(200);
    expect(j2.data.unapplied_cents).toBe(0);
    const got = (await api("GET", `/api/v1/ap/bills/${b2.id}`, adminToken)).json;
    expect(got.data.paid_cents).toBe(2000);
    expect(got.data.open_balance_cents).toBe(8000);
  });

  test("idempotent payment create replays the original", async () => {
    const v = await makeVendor(adminToken, "Idem Pay Vendor");
    const b = await makePostedBill(apClerkToken, v.id);
    const key = `idem-bpay-${b.id}`;
    const body = {
      vendor_id: v.id,
      method: "check",
      amount_cents: 5000,
      paid_on: today(),
      applications: [{ bill_id: b.id, amount_cents: 5000 }],
    };
    const first = await api("POST", "/api/v1/ap/bill-payments", apClerkToken, body, {
      "idempotency-key": key,
    });
    expect(first.status).toBe(201);
    const second = await api("POST", "/api/v1/ap/bill-payments", apClerkToken, body, {
      "idempotency-key": key,
    });
    expect(second.status).toBe(201);
    expect(second.json.data.id).toBe(first.json.data.id);
    const got = (await api("GET", `/api/v1/ap/bills/${b.id}`, adminToken)).json;
    expect(got.data.paid_cents).toBe(5000);
  });
});

// --- RBAC -----------------------------------------------------------------------

describe("ap rbac", () => {
  test("sales and auditor cannot write; auditor can read", async () => {
    const { status: s1 } = await api("POST", "/api/v1/ap/vendors", salesToken, { name: "Nope" });
    expect(s1).toBe(403);
    const { status: s2 } = await api("POST", "/api/v1/ap/vendors", auditorToken, { name: "Nope" });
    expect(s2).toBe(403);
    const v = await makeVendor(adminToken, "Readable Vendor");
    const { status: s3 } = await api("GET", `/api/v1/ap/vendors/${v.id}`, auditorToken);
    expect(s3).toBe(200);
    const { status: s4 } = await api("POST", "/api/v1/ap/bills", salesToken, {
      vendor_id: v.id,
      bill_date: today(),
      due_date: plusDays(today(), 30),
      lines: [{ description: "X", quantity: 1, unit_price_cents: 100, account_code: "6200" }],
    });
    expect(s4).toBe(403);
  });
});
