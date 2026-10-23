// Phase 1 tests: ledger core — accounts, journal posting, reversals,
// periods, trial balance, idempotency, immutability, RBAC.

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import {
  makeTestEnv,
  loginAs,
  authHeaders,
  createTestUser,
  type TestEnv,
} from "./helpers";
import { verifyChain } from "../src/audit";
import { postJournal, closePeriod, trialBalance, LedgerError } from "../src/ledger";

let env: TestEnv;
let adminToken: string;
let salesToken: string;
let auditorToken: string;
let apClerkToken: string;

beforeAll(async () => {
  env = await makeTestEnv();
  const admin = await loginAs(env.base, "admin@example.local", "Changeme-123456");
  expect(admin.status).toBe(200);
  adminToken = admin.token;

  const salesId = await createTestUser(env.db, "sales1@example.local", "Salespass-123456", "sales");
  const auditorId = await createTestUser(env.db, "auditor1@example.local", "Auditorpass-123456", "auditor");
  const clerkId = await createTestUser(env.db, "clerk1@example.local", "Clerkpass-123456", "ap_clerk");
  expect(salesId).toBeGreaterThan(0);
  expect(auditorId).toBeGreaterThan(0);
  expect(clerkId).toBeGreaterThan(0);
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

const CASH = "1000";
const REVENUE = "4000";

function goodEntry(over: Record<string, unknown> = {}) {
  return {
    memo: "test sale",
    lines: [
      { account_code: CASH, debit_cents: 5000 },
      { account_code: REVENUE, credit_cents: 5000 },
    ],
    ...over,
  };
}

// --- seed ---------------------------------------------------------------------

describe("seed: chart of accounts + open period", () => {
  test("seeded chart of accounts present", async () => {
    const { status, json } = await api("GET", "/api/v1/ledger/accounts", adminToken);
    expect(status).toBe(200);
    expect(json.data.length).toBe(17);
    const codes = json.data.map((a: any) => a.code);
    expect(codes).toContain(CASH);
    expect(codes).toContain(REVENUE);
  });

  test("current-year period seeded open", async () => {
    const { status, json } = await api("GET", "/api/v1/ledger/periods", adminToken);
    expect(status).toBe(200);
    const year = new Date().getUTCFullYear();
    const p = json.data.find((x: any) => x.name === `FY ${year}`);
    expect(p).toBeDefined();
    expect(p.closed_at).toBeNull();
  });
});

// --- accounts -------------------------------------------------------------------

describe("accounts", () => {
  test("create account", async () => {
    const { status, json } = await api("POST", "/api/v1/ledger/accounts", adminToken, {
      code: "1015",
      name: "Savings",
      type: "asset",
    });
    expect(status).toBe(201);
    expect(json.data.code).toBe("1015");
    expect(json.data.type).toBe("asset");
  });

  test("duplicate code rejected", async () => {
    const { status, json } = await api("POST", "/api/v1/ledger/accounts", adminToken, {
      code: "1000",
      name: "Dup",
      type: "asset",
    });
    expect(status).toBe(400);
    expect(json.error.code).toBe("validation");
  });

  test("invalid type rejected", async () => {
    const { status, json } = await api("POST", "/api/v1/ledger/accounts", adminToken, {
      code: "9999",
      name: "Bogus",
      type: "qux",
    });
    expect(status).toBe(400);
    expect(json.error.code).toBe("validation");
  });

  test("child with mismatched parent type rejected", async () => {
    const cash = (
      await api("GET", "/api/v1/ledger/accounts", adminToken)
    ).json.data.find((a: any) => a.code === CASH);
    const { status } = await api("POST", "/api/v1/ledger/accounts", adminToken, {
      code: "9001",
      name: "Bad child",
      type: "revenue",
      parent_id: cash.id,
    });
    expect(status).toBe(400);
  });

  test("rename account", async () => {
    const created = (
      await api("POST", "/api/v1/ledger/accounts", adminToken, {
        code: "1016",
        name: "Rename Me",
        type: "asset",
      })
    ).json.data;
    const { status, json } = await api("PATCH", `/api/v1/ledger/accounts/${created.id}`, adminToken, {
      name: "Renamed",
    });
    expect(status).toBe(200);
    expect(json.data.name).toBe("Renamed");
    const row = env.db.query("SELECT action FROM audit_log WHERE action = 'account.rename' ORDER BY seq DESC LIMIT 1").get();
    expect(row).not.toBeNull();
  });

  test("soft-delete account with no lines", async () => {
    const created = (
      await api("POST", "/api/v1/ledger/accounts", adminToken, {
        code: "1017",
        name: "Deletable",
        type: "asset",
      })
    ).json.data;
    const { status } = await api("DELETE", `/api/v1/ledger/accounts/${created.id}`, adminToken);
    expect(status).toBe(200);
    const got = await api("GET", `/api/v1/ledger/accounts/${created.id}`, adminToken);
    expect(got.status).toBe(404);
  });

  test("delete account with posted lines -> 409 in_use", async () => {
    const r = await api("POST", "/api/v1/ledger/journal", adminToken, goodEntry());
    expect(r.status).toBe(201);
    const cash = (await api("GET", "/api/v1/ledger/accounts", adminToken)).json.data.find(
      (a: any) => a.code === CASH,
    );
    const { status, json } = await api("DELETE", `/api/v1/ledger/accounts/${cash.id}`, adminToken);
    expect(status).toBe(409);
    expect(json.error.code).toBe("in_use");
  });

  test("delete account with live child -> 409 in_use", async () => {
    const parent = (
      await api("POST", "/api/v1/ledger/accounts", adminToken, {
        code: "1020",
        name: "Parent",
        type: "asset",
      })
    ).json.data;
    await api("POST", "/api/v1/ledger/accounts", adminToken, {
      code: "1021",
      name: "Child",
      type: "asset",
      parent_id: parent.id,
    });
    const { status, json } = await api("DELETE", `/api/v1/ledger/accounts/${parent.id}`, adminToken);
    expect(status).toBe(409);
    expect(json.error.code).toBe("in_use");
  });

  test("deleted account cannot be posted to", async () => {
    const created = (
      await api("POST", "/api/v1/ledger/accounts", adminToken, {
        code: "1018",
        name: "Gone",
        type: "asset",
      })
    ).json.data;
    await api("DELETE", `/api/v1/ledger/accounts/${created.id}`, adminToken);
    const { status, json } = await api("POST", "/api/v1/ledger/journal", adminToken, {
      memo: "to deleted",
      lines: [
        { account_id: created.id, debit_cents: 100 },
        { account_code: REVENUE, credit_cents: 100 },
      ],
    });
    expect(status).toBe(400);
    expect(json.error.code).toBe("validation");
  });

  test("RBAC: sales cannot read ledger, ap_clerk can read but not write, auditor read-only", async () => {
    const s = await api("GET", "/api/v1/ledger/accounts", salesToken);
    expect(s.status).toBe(403);
    const c = await api("GET", "/api/v1/ledger/accounts", apClerkToken);
    expect(c.status).toBe(200);
    const cw = await api("POST", "/api/v1/ledger/accounts", apClerkToken, {
      code: "8888",
      name: "Nope",
      type: "asset",
    });
    expect(cw.status).toBe(403);
    const a = await api("GET", "/api/v1/ledger/accounts", auditorToken);
    expect(a.status).toBe(200);
    const aw = await api("POST", "/api/v1/ledger/accounts", auditorToken, {
      code: "8889",
      name: "Nope",
      type: "asset",
    });
    expect(aw.status).toBe(403);
  });
});

// --- journal posting --------------------------------------------------------------

describe("journal posting", () => {
  test("balanced entry posts with entry_no", async () => {
    const { status, json } = await api("POST", "/api/v1/ledger/journal", adminToken, goodEntry({ memo: "entry one" }));
    expect(status).toBe(201);
    expect(json.data.entry_no).toMatch(/^JE-\d{6}$/);
    expect(json.data.lines).toHaveLength(2);
    expect(json.data.lines[0].account_code).toBe(CASH);
    const audit = env.db
      .query("SELECT id FROM audit_log WHERE action = 'journal.post' AND entity_id = ?")
      .get(json.data.entry_no);
    expect(audit).not.toBeNull();
  });

  test("unbalanced entry rejected, nothing inserted", async () => {
    const before = env.db.query("SELECT COUNT(*) n FROM journal_entries").get() as { n: number };
    const { status, json } = await api("POST", "/api/v1/ledger/journal", adminToken, {
      memo: "bad",
      lines: [
        { account_code: CASH, debit_cents: 5000 },
        { account_code: REVENUE, credit_cents: 4999 },
      ],
    });
    expect(status).toBe(400);
    expect(json.error.code).toBe("unbalanced");
    const after = env.db.query("SELECT COUNT(*) n FROM journal_entries").get() as { n: number };
    expect(after.n).toBe(before.n);
  });

  test("single-line entry rejected", async () => {
    const { status, json } = await api("POST", "/api/v1/ledger/journal", adminToken, {
      memo: "one line",
      lines: [{ account_code: CASH, debit_cents: 100 }],
    });
    expect(status).toBe(400);
    expect(json.error.code).toBe("validation");
  });

  test("line with both sides nonzero rejected", async () => {
    const { status, json } = await api("POST", "/api/v1/ledger/journal", adminToken, {
      memo: "both sides",
      lines: [
        { account_code: CASH, debit_cents: 100, credit_cents: 100 },
        { account_code: REVENUE, credit_cents: 100 },
      ],
    });
    expect(status).toBe(400);
    expect(json.error.code).toBe("validation");
  });

  test("unknown account rejected", async () => {
    const { status, json } = await api("POST", "/api/v1/ledger/journal", adminToken, {
      memo: "ghost",
      lines: [
        { account_code: "NOPE", debit_cents: 100 },
        { account_code: REVENUE, credit_cents: 100 },
      ],
    });
    expect(status).toBe(400);
    expect(json.error.code).toBe("validation");
  });

  test("non-integer cents rejected", async () => {
    const { status } = await api("POST", "/api/v1/ledger/journal", adminToken, {
      memo: "float",
      lines: [
        { account_code: CASH, debit_cents: 10.5 },
        { account_code: REVENUE, credit_cents: 10.5 },
      ],
    });
    expect(status).toBe(400);
  });

  test("empty memo rejected", async () => {
    const { status } = await api("POST", "/api/v1/ledger/journal", adminToken, {
      memo: "   ",
      lines: [
        { account_code: CASH, debit_cents: 100 },
        { account_code: REVENUE, credit_cents: 100 },
      ],
    });
    expect(status).toBe(400);
  });

  test("entry_no sequence is monotonic", async () => {
    const a = (await api("POST", "/api/v1/ledger/journal", adminToken, goodEntry())).json.data.entry_no;
    const b = (await api("POST", "/api/v1/ledger/journal", adminToken, goodEntry())).json.data.entry_no;
    expect(b > a).toBe(true);
  });

  test("idempotency key: duplicate POST replays original, single entry", async () => {
    const before = env.db.query("SELECT COUNT(*) n FROM journal_entries").get() as { n: number };
    const h = { "idempotency-key": "test-key-001" };
    const r1 = await api("POST", "/api/v1/ledger/journal", adminToken, goodEntry(), h);
    const r2 = await api("POST", "/api/v1/ledger/journal", adminToken, goodEntry(), h);
    expect(r1.status).toBe(201);
    expect(r2.status).toBe(201);
    expect(r2.json.data.entry_no).toBe(r1.json.data.entry_no);
    const after = env.db.query("SELECT COUNT(*) n FROM journal_entries").get() as { n: number };
    expect(after.n).toBe(before.n + 1);
  });

  test("RBAC: sales cannot post, ap_clerk cannot post, auditor cannot post", async () => {
    for (const tok of [salesToken, apClerkToken, auditorToken]) {
      const { status } = await api("POST", "/api/v1/ledger/journal", tok, goodEntry());
      expect(status).toBe(403);
    }
  });

  test("GET journal entry by id shows lines with account names", async () => {
    const posted = (await api("POST", "/api/v1/ledger/journal", adminToken, goodEntry())).json.data;
    const { status, json } = await api("GET", `/api/v1/ledger/journal/${posted.id}`, adminToken);
    expect(status).toBe(200);
    expect(json.data.entry_no).toBe(posted.entry_no);
    expect(json.data.lines[0].account_name).toBeDefined();
  });

  test("GET journal list paginates", async () => {
    const { status, json } = await api("GET", "/api/v1/ledger/journal?per_page=2&page=1", adminToken);
    expect(status).toBe(200);
    expect(json.data.length).toBeLessThanOrEqual(2);
    expect(json.meta.total).toBeGreaterThan(0);
    expect(json.meta.page).toBe(1);
  });
});

// --- immutability -----------------------------------------------------------------

describe("posted entries are immutable", () => {
  test("UPDATE on journal_entries aborts", () => {
    const row = env.db.query("SELECT id FROM journal_entries LIMIT 1").get() as { id: number };
    expect(() =>
      env.db.query("UPDATE journal_entries SET memo = 'tampered' WHERE id = ?").run(row.id),
    ).toThrow(/immutable/);
  });

  test("DELETE on journal_entries aborts", () => {
    const row = env.db.query("SELECT id FROM journal_entries LIMIT 1").get() as { id: number };
    expect(() =>
      env.db.query("DELETE FROM journal_entries WHERE id = ?").run(row.id),
    ).toThrow(/immutable/);
  });

  test("UPDATE on journal_lines aborts", () => {
    const row = env.db.query("SELECT id FROM journal_lines LIMIT 1").get() as { id: number };
    expect(() =>
      env.db.query("UPDATE journal_lines SET debit_cents = 1 WHERE id = ?").run(row.id),
    ).toThrow(/immutable/);
  });

  test("DELETE on journal_lines aborts", () => {
    const row = env.db.query("SELECT id FROM journal_lines LIMIT 1").get() as { id: number };
    expect(() =>
      env.db.query("DELETE FROM journal_lines WHERE id = ?").run(row.id),
    ).toThrow(/immutable/);
  });
});

// --- reversals ----------------------------------------------------------------------

describe("reversals", () => {
  test("reversal nets the account to zero", async () => {
    // fresh account so earlier tests don't pollute the balance
    const acc = (
      await api("POST", "/api/v1/ledger/accounts", adminToken, {
        code: "1050",
        name: "Reversal Test Cash",
        type: "asset",
      })
    ).json.data;
    const posted = (
      await api("POST", "/api/v1/ledger/journal", adminToken, {
        memo: "to reverse",
        lines: [
          { account_id: acc.id, debit_cents: 7777 },
          { account_code: REVENUE, credit_cents: 7777 },
        ],
      })
    ).json.data;
    const { status, json } = await api("POST", `/api/v1/ledger/journal/${posted.id}/reverse`, adminToken, {});
    expect(status).toBe(201);
    expect(json.data.reversed_by).toBe(posted.id);
    expect(json.data.reversed_entry_no).toBe(posted.entry_no);
    expect(json.data.memo).toContain(posted.entry_no);
    // original untouched
    const orig = (await api("GET", `/api/v1/ledger/journal/${posted.id}`, adminToken)).json.data;
    expect(orig.reversed_by).toBeNull();
    expect(orig.memo).toBe("to reverse");
    // net balance zero
    const ledger = (await api("GET", `/api/v1/ledger/accounts/${acc.id}/ledger`, adminToken)).json.data;
    expect(ledger.closing_balance_cents).toBe(0);
    expect(ledger.total_debits).toBe(7777);
    expect(ledger.total_credits).toBe(7777);
    // trial balance still balances
    const period = (
      await api("GET", "/api/v1/ledger/periods", adminToken)
    ).json.data.find((p: any) => p.name === `FY ${new Date().getUTCFullYear()}`);
    const tb = (await api("GET", `/api/v1/ledger/trial-balance?period_id=${period.id}`, adminToken)).json.data;
    expect(tb.balanced).toBe(true);
  });

  test("double reversal rejected", async () => {
    const posted = (await api("POST", "/api/v1/ledger/journal", adminToken, goodEntry())).json.data;
    const r1 = await api("POST", `/api/v1/ledger/journal/${posted.id}/reverse`, adminToken, {});
    expect(r1.status).toBe(201);
    const r2 = await api("POST", `/api/v1/ledger/journal/${posted.id}/reverse`, adminToken, {});
    expect(r2.status).toBe(409);
    expect(r2.json.error.code).toBe("already_reversed");
  });

  test("reverse of unknown entry -> 400", async () => {
    const { status, json } = await api("POST", "/api/v1/ledger/journal/999999/reverse", adminToken, {});
    expect(status).toBe(400);
    expect(json.error.code).toBe("validation");
  });

  test("reverse idempotency key replays", async () => {
    const posted = (await api("POST", "/api/v1/ledger/journal", adminToken, goodEntry())).json.data;
    const h = { "idempotency-key": "rev-key-1" };
    const r1 = await api("POST", `/api/v1/ledger/journal/${posted.id}/reverse`, adminToken, {}, h);
    const r2 = await api("POST", `/api/v1/ledger/journal/${posted.id}/reverse`, adminToken, {}, h);
    expect(r1.status).toBe(201);
    expect(r2.status).toBe(201);
    expect(r2.json.data.entry_no).toBe(r1.json.data.entry_no);
  });

  test("reversal posts to an explicitly chosen open period", async () => {
    const period = (
      await api("POST", "/api/v1/ledger/periods", adminToken, {
        name: "Q1 2027",
        starts_on: "2027-01-01",
        ends_on: "2027-03-31",
      })
    ).json.data;
    const posted = (await api("POST", "/api/v1/ledger/journal", adminToken, goodEntry())).json.data;
    const { status, json } = await api("POST", `/api/v1/ledger/journal/${posted.id}/reverse`, adminToken, {
      period_id: period.id,
      posted_on: "2027-02-15",
    });
    expect(status).toBe(201);
    expect(json.data.period_id).toBe(period.id);
  });
});

// --- periods -------------------------------------------------------------------------

describe("fiscal periods", () => {
  test("create period + overlap rejected", async () => {
    const { status, json } = await api("POST", "/api/v1/ledger/periods", adminToken, {
      name: "FY 2028",
      starts_on: "2028-01-01",
      ends_on: "2028-12-31",
    });
    expect(status).toBe(201);
    expect(json.data.name).toBe("FY 2028");
    const dup = await api("POST", "/api/v1/ledger/periods", adminToken, {
      name: "FY 2028 dup",
      starts_on: "2028-06-01",
      ends_on: "2029-05-31",
    });
    expect(dup.status).toBe(409);
    expect(dup.json.error.code).toBe("overlap");
  });

  test("invalid dates rejected", async () => {
    const { status } = await api("POST", "/api/v1/ledger/periods", adminToken, {
      name: "Bad",
      starts_on: "2028-02-30",
      ends_on: "2028-01-01",
    });
    expect(status).toBe(400);
  });

  test("posted_on outside the period rejected", async () => {
    const period = (
      await api("POST", "/api/v1/ledger/periods", adminToken, {
        name: "FY 2029",
        starts_on: "2029-01-01",
        ends_on: "2029-12-31",
      })
    ).json.data;
    const { status, json } = await api("POST", "/api/v1/ledger/journal", adminToken, {
      memo: "outside",
      period_id: period.id,
      posted_on: "2030-01-05",
      lines: [
        { account_code: CASH, debit_cents: 100 },
        { account_code: REVENUE, credit_cents: 100 },
      ],
    });
    expect(status).toBe(400);
    expect(json.error.code).toBe("validation");
  });

  test("close period: gate refuses unbalanced period", () => {
    // bypass the balanced postJournal to prove the close gate holds
    const period = env.db
      .query("SELECT id FROM fiscal_periods WHERE name = 'FY 2029'")
      .get() as { id: number };
    const now = new Date().toISOString();
    const e = env.db
      .query(
        "INSERT INTO journal_entries (entry_no, period_id, memo, posted_on, posted_at, created_at) VALUES (?,?,?,?,?,?)",
      )
      .run("JE-GATE-1", period.id, "unbalanced", "2029-06-01", now, now);
    env.db
      .query("INSERT INTO journal_lines (entry_id, account_id, debit_cents, credit_cents) VALUES (?,?,?,?)")
      .run(Number(e.lastInsertRowid), 1, 100, 0);
    expect(() => closePeriod(env.db, period.id, 1)).toThrowError(LedgerError);
    try {
      closePeriod(env.db, period.id, 1);
    } catch (err) {
      expect((err as LedgerError).code).toBe("unbalanced");
    }
  });

  test("close period happy path, then posting rejected with period_closed", async () => {
    const period = (
      await api("POST", "/api/v1/ledger/periods", adminToken, {
        name: "FY 2030",
        starts_on: "2030-01-01",
        ends_on: "2030-12-31",
      })
    ).json.data;
    await api("POST", "/api/v1/ledger/journal", adminToken, {
      memo: "before close",
      period_id: period.id,
      posted_on: "2030-06-01",
      lines: [
        { account_code: CASH, debit_cents: 200 },
        { account_code: REVENUE, credit_cents: 200 },
      ],
    });
    const { status, json } = await api("POST", `/api/v1/ledger/periods/${period.id}/close`, adminToken);
    expect(status).toBe(200);
    expect(json.data.closed_at).not.toBeNull();
    const post = await api("POST", "/api/v1/ledger/journal", adminToken, {
      memo: "after close",
      period_id: period.id,
      posted_on: "2030-07-01",
      lines: [
        { account_code: CASH, debit_cents: 200 },
        { account_code: REVENUE, credit_cents: 200 },
      ],
    });
    expect(post.status).toBe(409);
    expect(post.json.error.code).toBe("period_closed");
    const again = await api("POST", `/api/v1/ledger/periods/${period.id}/close`, adminToken);
    expect(again.status).toBe(409);
    expect(again.json.error.code).toBe("already_closed");
  });

  test("close requires ledger approve; ap_clerk cannot close", async () => {
    const period = (
      await api("POST", "/api/v1/ledger/periods", adminToken, {
        name: "FY 2031",
        starts_on: "2031-01-01",
        ends_on: "2031-12-31",
      })
    ).json.data;
    const { status } = await api("POST", `/api/v1/ledger/periods/${period.id}/close`, apClerkToken);
    expect(status).toBe(403);
  });

  test("reopen requires ledger admin; accountant cannot, admin can", async () => {
    const accountantId = await createTestUser(env.db, "acct1@example.local", "Acctpass-123456", "accountant");
    expect(accountantId).toBeGreaterThan(0);
    const acctToken = (await loginAs(env.base, "acct1@example.local", "Acctpass-123456")).token;
    const period = (
      await api("POST", "/api/v1/ledger/periods", adminToken, {
        name: "FY 2032",
        starts_on: "2032-01-01",
        ends_on: "2032-12-31",
      })
    ).json.data;
    await api("POST", `/api/v1/ledger/periods/${period.id}/close`, adminToken);
    const denied = await api("POST", `/api/v1/ledger/periods/${period.id}/reopen`, acctToken);
    expect(denied.status).toBe(403);
    const { status, json } = await api("POST", `/api/v1/ledger/periods/${period.id}/reopen`, adminToken);
    expect(status).toBe(200);
    expect(json.data.closed_at).toBeNull();
    const audit = env.db
      .query("SELECT id FROM audit_log WHERE action = 'period.reopen' AND entity_id = ?")
      .get(String(period.id));
    expect(audit).not.toBeNull();
    // posting works again after reopen
    const post = await api("POST", "/api/v1/ledger/journal", adminToken, {
      memo: "after reopen",
      period_id: period.id,
      posted_on: "2032-05-01",
      lines: [
        { account_code: CASH, debit_cents: 300 },
        { account_code: REVENUE, credit_cents: 300 },
      ],
    });
    expect(post.status).toBe(201);
  });
});

// --- trial balance + account ledger ---------------------------------------------------

describe("trial balance and account ledger", () => {
  test("trial balance totals balance and match postings", async () => {
    const period = (
      await api("GET", "/api/v1/ledger/periods", adminToken)
    ).json.data.find((p: any) => p.name === `FY ${new Date().getUTCFullYear()}`);
    const before = (await api("GET", `/api/v1/ledger/trial-balance?period_id=${period.id}`, adminToken)).json.data;
    await api("POST", "/api/v1/ledger/journal", adminToken, {
      memo: "tb check",
      lines: [
        { account_code: CASH, debit_cents: 1234 },
        { account_code: REVENUE, credit_cents: 1234 },
      ],
    });
    const { status, json } = await api("GET", `/api/v1/ledger/trial-balance?period_id=${period.id}`, adminToken);
    expect(status).toBe(200);
    expect(json.data.balanced).toBe(true);
    expect(json.data.total_debits).toBe(before.total_debits + 1234);
    expect(json.data.total_credits).toBe(before.total_credits + 1234);
    expect(json.data.total_debits).toBe(json.data.total_credits);
    const cashRow = json.data.rows.find((r: any) => r.code === CASH);
    expect(cashRow.debits).toBeGreaterThanOrEqual(1234);
  });

  test("trial balance requires period_id", async () => {
    const { status } = await api("GET", "/api/v1/ledger/trial-balance", adminToken);
    expect(status).toBe(400);
  });

  test("account ledger running balance, debit-normal and credit-normal", async () => {
    const acc = (
      await api("POST", "/api/v1/ledger/accounts", adminToken, {
        code: "1060",
        name: "Ledger Check",
        type: "asset",
      })
    ).json.data;
    const rev = (
      await api("POST", "/api/v1/ledger/accounts", adminToken, {
        code: "4010",
        name: "Ledger Rev",
        type: "revenue",
      })
    ).json.data;
    await api("POST", "/api/v1/ledger/journal", adminToken, {
      memo: "ledger one",
      lines: [
        { account_id: acc.id, debit_cents: 1000 },
        { account_id: rev.id, credit_cents: 1000 },
      ],
    });
    await api("POST", "/api/v1/ledger/journal", adminToken, {
      memo: "ledger two",
      lines: [
        { account_id: acc.id, debit_cents: 500 },
        { account_id: rev.id, credit_cents: 500 },
      ],
    });
    const assetLedger = (await api("GET", `/api/v1/ledger/accounts/${acc.id}/ledger`, adminToken)).json.data;
    expect(assetLedger.lines).toHaveLength(2);
    expect(assetLedger.lines[0].balance_cents).toBe(1000);
    expect(assetLedger.lines[1].balance_cents).toBe(1500);
    expect(assetLedger.closing_balance_cents).toBe(1500);
    const revLedger = (await api("GET", `/api/v1/ledger/accounts/${rev.id}/ledger`, adminToken)).json.data;
    expect(revLedger.closing_balance_cents).toBe(1500); // credit-normal: +1500
  });

  test("account ledger period filter", async () => {
    const acc = (
      await api("POST", "/api/v1/ledger/accounts", adminToken, {
        code: "1070",
        name: "Period Filter",
        type: "asset",
      })
    ).json.data;
    const p1 = (
      await api("POST", "/api/v1/ledger/periods", adminToken, {
        name: "FY 2033",
        starts_on: "2033-01-01",
        ends_on: "2033-12-31",
      })
    ).json.data;
    await api("POST", "/api/v1/ledger/journal", adminToken, {
      memo: "in p1",
      period_id: p1.id,
      posted_on: "2033-04-01",
      lines: [
        { account_id: acc.id, debit_cents: 900 },
        { account_code: REVENUE, credit_cents: 900 },
      ],
    });
    const filtered = (await api("GET", `/api/v1/ledger/accounts/${acc.id}/ledger?period_id=${p1.id}`, adminToken)).json.data;
    expect(filtered.lines).toHaveLength(1);
    expect(filtered.closing_balance_cents).toBe(900);
  });

  test("ledger postings are covered by the audit hash chain", () => {
    const v = verifyChain(env.db);
    expect(v.ok).toBe(true);
    const n = env.db
      .query("SELECT COUNT(*) n FROM audit_log WHERE action IN ('journal.post','journal.reverse','period.close','period.reopen','account.create')")
      .get() as { n: number };
    expect(n.n).toBeGreaterThan(0);
  });
});
