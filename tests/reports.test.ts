// Phase 9 tests: reporting — P&L, balance sheet, cash flow, AR/AP aging
// with GL reconciliation, and pinned report_runs (sha256 + reproduce).

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
let adminToken = "";
let accountantToken = "";
let salesToken = "";
let periodId = 0;

async function api(
  method: string,
  path: string,
  token: string,
  body?: unknown,
  extraHeaders: Record<string, string> = {},
) {
  const res = await fetch(`${env.base}${path}`, {
    method,
    headers: { "content-type": "application/json", ...authHeaders(token), ...extraHeaders },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}

async function postJournal(token: string, memo: string, postedOn: string, lines: any[]) {
  const { status, json } = await api("POST", "/api/v1/ledger/journal", token, {
    memo,
    posted_on: postedOn,
    lines,
  });
  expect(status).toBe(201);
  return json.data;
}

beforeAll(async () => {
  env = await makeTestEnv();
  adminToken = (await loginAs(env.base, ADMIN_EMAIL, ADMIN_PASSWORD)).token;
  await createTestUser(env.db, "acct9@example.local", "Acctpass-123456", "accountant");
  await createTestUser(env.db, "sales9@example.local", "Salespass-123456", "sales");
  accountantToken = (await loginAs(env.base, "acct9@example.local", "Acctpass-123456")).token;
  salesToken = (await loginAs(env.base, "sales9@example.local", "Salespass-123456")).token;

  const year = new Date().getUTCFullYear();
  const periods = (await api("GET", "/api/v1/ledger/periods", adminToken)).json.data;
  periodId = periods.find((p: any) => p.name === `FY ${year}`).id;

  // Seed GL activity for the P&L / BS / cash-flow tests (all inside FY).
  await postJournal(adminToken, "Owner contribution", `${year}-01-05`, [
    { account_code: "1000", debit_cents: 100000 },
    { account_code: "3000", credit_cents: 100000 },
  ]);
  await postJournal(adminToken, "Cash sale", `${year}-02-10`, [
    { account_code: "1000", debit_cents: 50000 },
    { account_code: "4000", credit_cents: 50000 },
  ]);
  await postJournal(adminToken, "Pay rent", `${year}-02-12`, [
    { account_code: "6100", debit_cents: 12000 },
    { account_code: "1000", credit_cents: 12000 },
  ]);
  await postJournal(adminToken, "Buy equipment", `${year}-03-01`, [
    { account_code: "1500", debit_cents: 80000 },
    { account_code: "1000", credit_cents: 80000 },
  ]);
});

afterAll(() => env.cleanup());

// --- profit & loss + balance sheet ---------------------------------------------

describe("profit & loss", () => {
  test("period P&L: revenue, expenses, net income", async () => {
    const { status, json } = await api(
      "GET",
      `/api/v1/reports/profit-loss?period_id=${periodId}`,
      adminToken,
    );
    expect(status).toBe(200);
    const d = json.data;
    expect(d.report_type).toBe("profit_loss");
    expect(d.total_revenue_cents).toBe(50000);
    expect(d.total_expenses_cents).toBe(12000);
    expect(d.net_income_cents).toBe(38000);
    expect(d.revenue.find((r: any) => r.code === "4000").balance_cents).toBe(50000);
    expect(d.expenses.find((r: any) => r.code === "6100").balance_cents).toBe(12000);
  });

  test("from/to window restricts activity", async () => {
    const year = new Date().getUTCFullYear();
    const feb = await api(
      "GET",
      `/api/v1/reports/profit-loss?from=${year}-02-01&to=${year}-02-28`,
      adminToken,
    );
    expect(feb.json.data.net_income_cents).toBe(38000);
    const mar = await api(
      "GET",
      `/api/v1/reports/profit-loss?from=${year}-03-01&to=${year}-03-31`,
      adminToken,
    );
    // March holds only the equipment purchase (a balance-sheet move, not P&L).
    expect(mar.json.data.total_revenue_cents).toBe(0);
    expect(mar.json.data.total_expenses_cents).toBe(0);
    expect(mar.json.data.net_income_cents).toBe(0);
  });
});

describe("balance sheet", () => {
  test("balances at period end; net income matches P&L (acceptance)", async () => {
    const year = new Date().getUTCFullYear();
    const { status, json } = await api(
      "GET",
      `/api/v1/reports/balance-sheet?as_of=${year}-03-31`,
      adminToken,
    );
    expect(status).toBe(200);
    const d = json.data;
    expect(d.total_assets_cents).toBe(138000); // cash 58000 + equipment 80000
    expect(d.total_liabilities_cents).toBe(0);
    expect(d.total_equity_cents).toBe(138000); // owner equity 100000 + net income 38000
    expect(d.net_income_cents).toBe(38000);
    expect(d.balanced).toBe(true);
    const pl = await api("GET", `/api/v1/reports/profit-loss?period_id=${periodId}`, adminToken);
    expect(d.net_income_cents).toBe(pl.json.data.net_income_cents);
  });

  test("early as_of shows only the activity to that date", async () => {
    const year = new Date().getUTCFullYear();
    const { json } = await api(
      "GET",
      `/api/v1/reports/balance-sheet?as_of=${year}-01-31`,
      adminToken,
    );
    expect(json.data.total_assets_cents).toBe(100000);
    expect(json.data.total_equity_cents).toBe(100000);
    expect(json.data.net_income_cents).toBe(0);
    expect(json.data.balanced).toBe(true);
  });
});

// --- cash flow -----------------------------------------------------------------

describe("cash flow", () => {
  test("sections sum to the GL cash movement; ending equals GL cash balance", async () => {
    const year = new Date().getUTCFullYear();
    const { status, json } = await api(
      "GET",
      `/api/v1/reports/cash-flow?period_id=${periodId}`,
      adminToken,
    );
    expect(status).toBe(200);
    const d = json.data;
    expect(d.operating_cents).toBe(38000); // +50000 sale, -12000 rent
    expect(d.investing_cents).toBe(-80000); // equipment
    expect(d.financing_cents).toBe(100000); // owner contribution
    expect(d.net_change_cents).toBe(58000);
    expect(d.beginning_cash_cents).toBe(0);
    expect(d.ending_cash_cents).toBe(58000);
    // Cross-check against the GL cash account ledger.
    const accounts = (await api("GET", "/api/v1/ledger/accounts", adminToken)).json.data;
    const cash = accounts.find((a: any) => a.code === "1000");
    const ledger = await api(
      "GET",
      `/api/v1/ledger/accounts/${cash.id}/ledger`,
      adminToken,
    );
    expect(ledger.json.data.closing_balance_cents).toBe(d.ending_cash_cents);
  });

  test("beginning cash picks up pre-window activity", async () => {
    const year = new Date().getUTCFullYear();
    const { json } = await api(
      "GET",
      `/api/v1/reports/cash-flow?from=${year}-02-01&to=${year}-03-31`,
      adminToken,
    );
    const d = json.data;
    expect(d.beginning_cash_cents).toBe(100000); // January contribution
    expect(d.net_change_cents).toBe(-42000); // +50000 -12000 -80000
    expect(d.ending_cash_cents).toBe(58000);
  });
});

// --- AR aging ------------------------------------------------------------------

describe("AR aging", () => {
  let customerId = 0;

  async function makeInvoice(over: Record<string, unknown>) {
    const { status, json } = await api("POST", "/api/v1/ar/invoices", adminToken, {
      customer_id: customerId,
      lines: [{ description: "Item", quantity: 1, unit_price_cents: over.total }],
      ...over,
    });
    expect(status).toBe(201);
    const posted = await api("POST", `/api/v1/ar/invoices/${json.data.id}/post`, adminToken);
    expect(posted.status).toBe(200);
    return json.data;
  }

  test("buckets by days past due; reconciliation to GL AR holds (acceptance)", async () => {
    const year = new Date().getUTCFullYear();
    const cust = await api("POST", "/api/v1/ar/customers", adminToken, { name: "Aging Co" });
    expect(cust.status).toBe(201);
    customerId = cust.json.data.id;
    // as_of = Jun 30: A current, B 1-30, C 31-60, D 61-90, E 90+.
    const a = await makeInvoice({ issue_date: `${year}-06-01`, due_date: `${year}-07-15`, total: 10000 });
    const b = await makeInvoice({ issue_date: `${year}-05-01`, due_date: `${year}-06-15`, total: 20000 });
    await makeInvoice({ issue_date: `${year}-04-01`, due_date: `${year}-05-20`, total: 30000 });
    await makeInvoice({ issue_date: `${year}-03-01`, due_date: `${year}-04-10`, total: 40000 });
    await makeInvoice({ issue_date: `${year}-01-15`, due_date: `${year}-02-01`, total: 50000 });
    void a;
    // Pay 25000, apply only 15000 to B: B open drops to 5000, 10000 stays unapplied.
    const pay = await api("POST", "/api/v1/ar/payments", adminToken, {
      customer_id: customerId,
      method: "check",
      amount_cents: 25000,
      received_on: `${year}-06-20`,
      applications: [{ invoice_id: b.id, amount_cents: 15000 }],
    });
    expect(pay.status).toBe(201);
    expect(pay.json.data.unapplied_cents).toBe(10000);

    const { status, json } = await api(
      "GET",
      `/api/v1/reports/ar-aging?as_of=${year}-06-30`,
      adminToken,
    );
    expect(status).toBe(200);
    const d = json.data;
    expect(d.buckets.current_cents).toBe(10000);
    expect(d.buckets.days_1_30_cents).toBe(5000);
    expect(d.buckets.days_31_60_cents).toBe(30000);
    expect(d.buckets.days_61_90_cents).toBe(40000);
    expect(d.buckets.days_90_plus_cents).toBe(50000);
    expect(d.total_open_cents).toBe(135000);
    expect(d.total_unapplied_cents).toBe(10000);
    // GL AR = invoices 150000 - payment 25000 = 125000 = open - unapplied.
    expect(d.gl_balance_cents).toBe(125000);
    expect(d.reconciles).toBe(true);
    expect(d.customers.length).toBe(1);
    expect(d.customers[0].total_open_cents).toBe(135000);
  });
});

// --- AP aging ------------------------------------------------------------------

describe("AP aging", () => {
  test("buckets + reconciliation to GL AP", async () => {
    const year = new Date().getUTCFullYear();
    const v = await api("POST", "/api/v1/ap/vendors", adminToken, { name: "Aging Vendor" });
    expect(v.status).toBe(201);
    const vendorId = v.json.data.id;
    async function makePostedBill(over: Record<string, unknown>) {
      const bill = await api("POST", "/api/v1/ap/bills", adminToken, {
        vendor_id: vendorId,
        lines: [{ description: "Supplies", quantity: 1, unit_price_cents: over.total, account_code: "6200" }],
        ...over,
      });
      expect(bill.status).toBe(201);
      const approved = await api("POST", `/api/v1/ap/bills/${bill.json.data.id}/approve`, accountantToken);
      expect(approved.status).toBe(200);
      const posted = await api("POST", `/api/v1/ap/bills/${bill.json.data.id}/post`, adminToken);
      expect(posted.status).toBe(200);
      return bill.json.data;
    }
    await makePostedBill({ bill_date: `${year}-05-01`, due_date: `${year}-07-20`, total: 60000 });
    const y = await makePostedBill({ bill_date: `${year}-03-01`, due_date: `${year}-05-15`, total: 40000 });
    // Pay 50000, apply 25000 to Y: Y open 15000, 25000 unapplied.
    const pay = await api("POST", "/api/v1/ap/bill-payments", adminToken, {
      vendor_id: vendorId,
      method: "check",
      amount_cents: 50000,
      paid_on: `${year}-06-20`,
      applications: [{ bill_id: y.id, amount_cents: 25000 }],
    });
    expect(pay.status).toBe(201);
    expect(pay.json.data.unapplied_cents).toBe(25000);

    const { status, json } = await api(
      "GET",
      `/api/v1/reports/ap-aging?as_of=${year}-06-30`,
      adminToken,
    );
    expect(status).toBe(200);
    const d = json.data;
    expect(d.buckets.current_cents).toBe(60000);
    expect(d.buckets.days_31_60_cents).toBe(15000);
    expect(d.total_open_cents).toBe(75000);
    expect(d.total_unapplied_cents).toBe(25000);
    // GL AP = bills 100000 - payment 50000 = 50000 = open - unapplied.
    expect(d.gl_balance_cents).toBe(50000);
    expect(d.reconciles).toBe(true);
  });
});

// --- pinned report runs ---------------------------------------------------------

describe("pinned report runs", () => {
  let runId = 0;
  let pinnedNet = 0;

  test("pin stores output + sha256; reproduce matches while books are unchanged", async () => {
    const live = await api("GET", `/api/v1/reports/profit-loss?period_id=${periodId}`, adminToken);
    expect(live.status).toBe(200);
    const { status, json } = await api("POST", "/api/v1/reports/report-runs", adminToken, {
      report_type: "profit_loss",
      params: { period_id: periodId },
    });
    expect(status).toBe(201);
    const run = json.data;
    runId = run.id;
    pinnedNet = run.output.net_income_cents;
    expect(run.report_type).toBe("profit_loss");
    expect(run.output_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(run.output).toEqual(live.json.data);
    expect(run.generated_by).toBeGreaterThan(0);

    const got = await api("GET", `/api/v1/reports/report-runs/${runId}`, adminToken);
    expect(got.status).toBe(200);
    expect(got.json.data.output_sha256).toBe(run.output_sha256);

    const rep = await api("GET", `/api/v1/reports/report-runs/${runId}/reproduce`, adminToken);
    expect(rep.status).toBe(200);
    expect(rep.json.data.matches).toBe(true);
    expect(rep.json.data.recomputed_sha256).toBe(run.output_sha256);
  });

  test("after the books move, reproduce mismatches but the pin never changes", async () => {
    const year = new Date().getUTCFullYear();
    await postJournal(adminToken, "Extra supplies", `${year}-04-01`, [
      { account_code: "6200", debit_cents: 5000 },
      { account_code: "1000", credit_cents: 5000 },
    ]);
    const rep = await api("GET", `/api/v1/reports/report-runs/${runId}/reproduce`, adminToken);
    expect(rep.json.data.matches).toBe(false);
    expect(rep.json.data.recomputed_sha256).not.toBe(rep.json.data.stored_sha256);
    const got = await api("GET", `/api/v1/reports/report-runs/${runId}`, adminToken);
    expect(got.json.data.output.net_income_cents).toBe(pinnedNet);
  });

  test("pinned runs are trigger-immutable at the DB level", () => {
    expect(() =>
      env.db.query("UPDATE report_runs SET output_sha256 = 'x' WHERE id = ?").run(runId),
    ).toThrow();
    expect(() => env.db.query("DELETE FROM report_runs WHERE id = ?").run(runId)).toThrow();
  });

  test("list filters by report_type", async () => {
    const { json } = await api(
      "GET",
      "/api/v1/reports/report-runs?report_type=profit_loss",
      adminToken,
    );
    expect(json.data.rows.length).toBeGreaterThanOrEqual(1);
    expect(json.data.rows.every((r: any) => r.report_type === "profit_loss")).toBe(true);
  });
});

// --- validation + RBAC -----------------------------------------------------------

describe("validation + RBAC", () => {
  test("unknown report type, missing window, bad dates, missing period", async () => {
    const pin = await api("POST", "/api/v1/reports/report-runs", adminToken, {
      report_type: "magic",
      params: {},
    });
    expect(pin.status).toBe(400);
    expect(pin.json.error.code).toBe("unknown_report");

    const noWindow = await api("GET", "/api/v1/reports/profit-loss", adminToken);
    expect(noWindow.status).toBe(400);
    expect(noWindow.json.error.code).toBe("validation");

    const badDate = await api(
      "GET",
      "/api/v1/reports/profit-loss?from=2026-13-01&to=2026-02-01",
      adminToken,
    );
    expect(badDate.status).toBe(400);

    const badAsOf = await api("GET", "/api/v1/reports/balance-sheet?as_of=nope", adminToken);
    expect(badAsOf.status).toBe(400);

    const noPeriod = await api("GET", "/api/v1/reports/profit-loss?period_id=999999", adminToken);
    expect(noPeriod.status).toBe(404);
    expect(noPeriod.json.error.code).toBe("not_found");

    const noRun = await api("GET", "/api/v1/reports/report-runs/999999", adminToken);
    expect(noRun.status).toBe(404);

    const noRoute = await api("GET", "/api/v1/reports/nope", adminToken);
    expect(noRoute.status).toBe(404);
  });

  test("sales reads reports but cannot pin; unauthenticated reads fail", async () => {
    const read = await api("GET", `/api/v1/reports/profit-loss?period_id=${periodId}`, salesToken);
    expect(read.status).toBe(200);
    const pin = await api("POST", "/api/v1/reports/report-runs", salesToken, {
      report_type: "profit_loss",
      params: { period_id: periodId },
    });
    expect(pin.status).toBe(403);
    const res = await fetch(`${env.base}/api/v1/reports/profit-loss?period_id=${periodId}`);
    expect(res.status).toBe(401);
  });
});
