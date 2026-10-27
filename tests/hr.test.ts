// Phase 8 tests: HR / payroll — encrypted PII, deduction config,
// pay-run maker-checker approval + summary journal posting.

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
import { getEmployeeDecrypted } from "../src/hr";

let env: TestEnv;
let adminToken = "";
let hrToken = "";
let hr2Token = "";
let accountantToken = "";
let auditorToken = "";
let hrUserId = 0;
let hr2UserId = 0;

async function post(path: string, token: string, body: any, extra: Record<string, string> = {}) {
  const res = await fetch(`${env.base}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...authHeaders(token), ...extra },
    body: JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  return { res, json };
}

async function get(path: string, token: string) {
  const res = await fetch(`${env.base}${path}`, { headers: authHeaders(token) });
  const json = await res.json().catch(() => ({}));
  return { res, json };
}

beforeAll(async () => {
  env = await makeTestEnv();
  adminToken = (await loginAs(env.base, ADMIN_EMAIL, ADMIN_PASSWORD)).token;
  hrUserId = await createTestUser(env.db, "hr1@example.local", "Hrpass-123456", "hr");
  hr2UserId = await createTestUser(env.db, "hr2@example.local", "Hrpass-123456", "hr");
  const acct = await createTestUser(env.db, "acct@example.local", "Acctpass-123456", "accountant");
  void acct;
  const aud = await createTestUser(env.db, "aud@example.local", "Audpass-123456", "auditor");
  void aud;
  hrToken = (await loginAs(env.base, "hr1@example.local", "Hrpass-123456")).token;
  hr2Token = (await loginAs(env.base, "hr2@example.local", "Hrpass-123456")).token;
  accountantToken = (await loginAs(env.base, "acct@example.local", "Acctpass-123456")).token;
  auditorToken = (await loginAs(env.base, "aud@example.local", "Audpass-123456")).token;
});

afterAll(() => env.cleanup());

describe("employees + encrypted PII", () => {
  test("create stores SSN as ciphertext; HTTP view shows last4 only, never the blob", async () => {
    const { res, json } = await post(
      "/api/v1/hr/employees",
      hrToken,
      {
        first_name: "Ada",
        last_name: "Test",
        email: "ada@example.local",
        hire_date: "2026-01-05",
        pay_type: "salary",
        base_pay_cents: 100000,
        ssn: "123-45-6789",
        date_of_birth: "1990-04-01",
        bank_account: "987654321",
      },
    );
    expect(res.status).toBe(201);
    const id = json.data.id;
    expect(json.data.employee_no).toMatch(/^EMP-\d{4}$/);
    expect(json.data.ssn_last4).toBe("6789");
    expect(JSON.stringify(json.data)).not.toContain("123-45-6789");
    expect(JSON.stringify(json.data)).not.toContain("987654321");
    expect("ssn_enc" in json.data).toBe(false);
    expect("dob_enc" in json.data).toBe(false);

    // Raw DB: the stored blob is ciphertext, not the plaintext.
    const raw = env.db.query("SELECT ssn_enc, dob_enc, bank_account_enc FROM employees WHERE id = ?").get(id) as any;
    expect(raw.ssn_enc).not.toContain("123-45-6789");
    expect(raw.ssn_enc).toContain("."); // ivB64.ctB64
    expect(raw.dob_enc).not.toContain("1990-04-01");
    expect(raw.bank_account_enc).not.toContain("987654321");

    // Decryption round-trips to the original values (unit path, not routed).
    const dec = await getEmployeeDecrypted(env.db, id);
    expect(dec!.ssn).toBe("123-45-6789");
    expect(dec!.date_of_birth).toBe("1990-04-01");
    expect(dec!.bank_account).toBe("987654321");
  });

  test("employee without PII fields works; list omits blobs", async () => {
    const { res, json } = await post("/api/v1/hr/employees", hrToken, {
      first_name: "Bo",
      last_name: "Plain",
      pay_type: "hourly",
      base_pay_cents: 2500,
    });
    expect(res.status).toBe(201);
    expect(json.data.ssn_last4).toBeNull();
    const list = await get("/api/v1/hr/employees", auditorToken);
    expect(list.res.status).toBe(200);
    expect(JSON.stringify(list.json.data)).not.toContain("ssn_enc");
  });

  test("validation: bad email, bad pay_type, negative pay, bad hire date", async () => {
    for (const body of [
      { first_name: "X", last_name: "Y", email: "not-an-email" },
      { first_name: "X", last_name: "Y", pay_type: "weekly" },
      { first_name: "X", last_name: "Y", base_pay_cents: -1 },
      { first_name: "X", last_name: "Y", hire_date: "2026-13-01" },
      { last_name: "Y" },
    ]) {
      const { res } = await post("/api/v1/hr/employees", hrToken, body);
      expect(res.status).toBe(400);
    }
  });

  test("update re-encrypts SSN and updates last4; audit rows carry no secret", async () => {
    const { json } = await post("/api/v1/hr/employees", hrToken, {
      first_name: "Cy",
      last_name: "Rotate",
      ssn: "111-22-3333",
    });
    const id = json.data.id;
    const res = await fetch(`${env.base}/api/v1/hr/employees/${id}`, {
      method: "PATCH",
      headers: { "content-type": "application/json", ...authHeaders(hrToken) },
      body: JSON.stringify({ ssn: "999-88-7777" }),
    });
    const updated = await res.json();
    expect(res.status).toBe(200);
    expect(updated.data.ssn_last4).toBe("7777");
    const dec = await getEmployeeDecrypted(env.db, id);
    expect(dec!.ssn).toBe("999-88-7777");
    const audits = env.db
      .query("SELECT after_json FROM audit_log WHERE entity_type = 'employee' AND entity_id = ?")
      .all(String(id)) as { after_json: string }[];
    expect(audits.length).toBeGreaterThan(0);
    for (const a of audits) {
      expect(a.after_json).not.toContain("999-88-7777");
      expect(a.after_json).not.toContain("111-22-3333");
    }
  });

  test("RBAC: accountant cannot create employees (hr:write), sales cannot read HR", async () => {
    const { res } = await post("/api/v1/hr/employees", accountantToken, {
      first_name: "No",
      last_name: "Perm",
    });
    expect(res.status).toBe(403);
    const salesId = await createTestUser(env.db, "sales1@example.local", "Salespass-123456", "sales");
    void salesId;
    const salesToken = (await loginAs(env.base, "sales1@example.local", "Salespass-123456")).token;
    const list = await get("/api/v1/hr/employees", salesToken);
    expect(list.res.status).toBe(403);
  });
});

describe("deduction types", () => {
  test("percent + fixed types; duplicate code and mixed-kind rejected", async () => {
    const { res: r1 } = await post("/api/v1/hr/deduction-types", hrToken, {
      code: "tax10",
      name: "Tax 10%",
      kind: "percent",
      percent_bps: 1000,
    });
    expect(r1.status).toBe(201);
    const { res: r2 } = await post("/api/v1/hr/deduction-types", hrToken, {
      code: "flat500",
      name: "Flat 500",
      kind: "fixed",
      amount_cents: 500,
    });
    expect(r2.status).toBe(201);
    const dup = await post("/api/v1/hr/deduction-types", hrToken, {
      code: "tax10",
      name: "Dup",
      kind: "percent",
      percent_bps: 500,
    });
    expect(dup.res.status).toBe(400);
    const mixed = await post("/api/v1/hr/deduction-types", hrToken, {
      code: "mixed",
      name: "Mixed",
      kind: "percent",
      percent_bps: 500,
      amount_cents: 100,
    });
    expect(mixed.res.status).toBe(400);
    const over = await post("/api/v1/hr/deduction-types", hrToken, {
      code: "over",
      name: "Over",
      kind: "percent",
      percent_bps: 10001,
    });
    expect(over.res.status).toBe(400);
  });
});

describe("pay runs", () => {
  let runId = 0;
  let empId = 0;
  let emp2Id = 0;

  test("create run + lines compute deductions (percent rounds, fixed adds)", async () => {
    const e1 = await post("/api/v1/hr/employees", hrToken, { first_name: "Pay", last_name: "One" });
    empId = e1.json.data.id;
    const e2 = await post("/api/v1/hr/employees", hrToken, { first_name: "Pay", last_name: "Two" });
    emp2Id = e2.json.data.id;
    const run = await post("/api/v1/hr/pay-runs", hrToken, {
      period_start: "2026-10-01",
      period_end: "2026-10-15",
      pay_date: "2026-10-16",
    });
    expect(run.res.status).toBe(201);
    runId = run.json.data.id;
    const line = await post(`/api/v1/hr/pay-runs/${runId}/lines`, hrToken, {
      employee_id: empId,
      gross_cents: 100001,
      deduction_codes: ["tax10", "flat500"],
    });
    // tax10 = round(100001 * 0.10) = 10000; + flat 500 = 10500; net 89501.
    expect(line.res.status).toBe(201);
    expect(line.json.data.deductions_cents).toBe(10500);
    expect(line.json.data.net_cents).toBe(89501);
    const dup = await post(`/api/v1/hr/pay-runs/${runId}/lines`, hrToken, {
      employee_id: empId,
      gross_cents: 100,
    });
    expect(dup.res.status).toBe(409);
    expect(dup.json.error.code).toBe("duplicate_line");
    const unknown = await post(`/api/v1/hr/pay-runs/${runId}/lines`, hrToken, {
      employee_id: emp2Id,
      gross_cents: 1000,
      deduction_codes: ["nope"],
    });
    expect(unknown.res.status).toBe(404);
    const over = await post(`/api/v1/hr/pay-runs/${runId}/lines`, hrToken, {
      employee_id: emp2Id,
      gross_cents: 400,
      deduction_codes: ["flat500"],
    });
    expect(over.res.status).toBe(400);
    expect(over.json.error.code).toBe("deductions_exceed_gross");
  });

  test("pay before approve -> not_approved; self-approve -> self_approval; distinct approver ok", async () => {
    const payEarly = await post(`/api/v1/hr/pay-runs/${runId}/pay`, hrToken, {});
    expect(payEarly.res.status).toBe(409);
    expect(payEarly.json.error.code).toBe("not_approved");
    const self = await post(`/api/v1/hr/pay-runs/${runId}/approve`, hrToken, {});
    expect(self.res.status).toBe(403);
    expect(self.json.error.code).toBe("self_approval");
    const ok = await post(`/api/v1/hr/pay-runs/${runId}/approve`, hr2Token, {});
    expect(ok.res.status).toBe(200);
    expect(ok.json.data.status).toBe("approved");
    expect(ok.json.data.approved_by).toBe(hr2UserId);
    const again = await post(`/api/v1/hr/pay-runs/${runId}/approve`, hr2Token, {});
    expect(again.res.status).toBe(409);
    expect(again.json.error.code).toBe("already_approved");
  });

  test("approve of an empty run -> empty_run", async () => {
    const run = await post("/api/v1/hr/pay-runs", hrToken, {
      period_start: "2026-11-01",
      period_end: "2026-11-15",
      pay_date: "2026-11-16",
    });
    const empty = await post(`/api/v1/hr/pay-runs/${run.json.data.id}/approve`, hr2Token, {});
    expect(empty.res.status).toBe(409);
    expect(empty.json.error.code).toBe("empty_run");
  });

  test("pay posts ONE summary journal (Dr 6000 / Cr 1000 + 2200), balanced; detail never in GL", async () => {
    // Fresh run: the shared runId run is already approved, and approved
    // runs correctly refuse new lines — so build this run from scratch.
    const freshRun = await post("/api/v1/hr/pay-runs", hrToken, {
      period_start: "2026-10-01",
      period_end: "2026-10-15",
      pay_date: "2026-10-16",
    });
    runId = freshRun.json.data.id;
    const l1 = await post(`/api/v1/hr/pay-runs/${runId}/lines`, hrToken, {
      employee_id: empId,
      gross_cents: 100001,
      deduction_codes: ["tax10", "flat500"],
    });
    expect(l1.res.status).toBe(201);
    const line2 = await post(`/api/v1/hr/pay-runs/${runId}/lines`, hrToken, {
      employee_id: emp2Id,
      gross_cents: 50000,
      deduction_codes: ["tax10"],
    });
    expect(line2.res.status).toBe(201);
    const appr = await post(`/api/v1/hr/pay-runs/${runId}/approve`, hr2Token, {});
    expect(appr.res.status).toBe(200);
    const paid = await post(`/api/v1/hr/pay-runs/${runId}/pay`, hrToken, {}, { "idempotency-key": "pay-1" });
    expect(paid.res.status).toBe(200);
    expect(paid.json.data.status).toBe("paid");
    expect(paid.json.data.total_gross_cents).toBe(150001);
    expect(paid.json.data.total_deductions_cents).toBe(15500); // 10500 + 5000
    expect(paid.json.data.total_net_cents).toBe(134501);
    const entryId = paid.json.data.journal_entry_id;
    expect(entryId).not.toBeNull();
    const entry = await get(`/api/v1/ledger/journal/${entryId}`, adminToken);
    expect(entry.res.status).toBe(200);
    const lines = entry.json.data.lines;
    const byCode = Object.fromEntries(lines.map((l: any) => [l.account_code, l]));
    expect(byCode["6000"].debit_cents).toBe(150001);
    expect(byCode["1000"].credit_cents).toBe(134501);
    expect(byCode["2200"].credit_cents).toBe(15500);
    expect(lines.length).toBe(3); // summary only: no per-employee lines
    // Paying again -> already_paid, and the idempotency replay returns the same body.
    const again = await post(`/api/v1/hr/pay-runs/${runId}/pay`, hrToken, {}, { "idempotency-key": "pay-1" });
    expect(again.res.status).toBe(200);
    expect(again.json.data.journal_entry_id).toBe(entryId);
    const fresh = await post(`/api/v1/hr/pay-runs/${runId}/pay`, hrToken, {}, { "idempotency-key": "pay-2" });
    expect(fresh.res.status).toBe(409);
    expect(fresh.json.error.code).toBe("already_paid");
    const entries = env.db
      .query("SELECT COUNT(*) AS n FROM journal_entries WHERE source_type = 'pay_run' AND source_id = ?")
      .get(String(runId)) as { n: number };
    expect(entries.n).toBe(1);
  });

  test("frozen run: line edit/remove and raw-SQL line update abort after approval", async () => {
    const run = await post("/api/v1/hr/pay-runs", hrToken, {
      period_start: "2026-12-01",
      period_end: "2026-12-15",
      pay_date: "2026-12-16",
    });
    const rid = run.json.data.id;
    const line = await post(`/api/v1/hr/pay-runs/${rid}/lines`, hrToken, {
      employee_id: empId,
      gross_cents: 10000,
    });
    const lid = line.json.data.id;
    await post(`/api/v1/hr/pay-runs/${rid}/approve`, hr2Token, {});
    const edit = await fetch(`${env.base}/api/v1/hr/pay-runs/${rid}/lines/${lid}`, {
      method: "PATCH",
      headers: { "content-type": "application/json", ...authHeaders(hrToken) },
      body: JSON.stringify({ gross_cents: 20000 }),
    });
    expect(edit.status).toBe(409);
    const del = await fetch(`${env.base}/api/v1/hr/pay-runs/${rid}/lines/${lid}`, {
      method: "DELETE",
      headers: authHeaders(hrToken),
    });
    expect(del.status).toBe(409);
    expect(() =>
      env.db.query("UPDATE pay_lines SET gross_cents = 1 WHERE id = ?").run(lid),
    ).toThrow();
    expect(() =>
      env.db.query("UPDATE pay_runs SET period_start = '2026-12-02' WHERE id = ?").run(rid),
    ).toThrow();
  });

  test("draft line edit recomputes deductions; draft line remove works", async () => {
    const run = await post("/api/v1/hr/pay-runs", hrToken, {
      period_start: "2027-01-01",
      period_end: "2027-01-15",
      pay_date: "2027-01-16",
    });
    const rid = run.json.data.id;
    const line = await post(`/api/v1/hr/pay-runs/${rid}/lines`, hrToken, {
      employee_id: empId,
      gross_cents: 20000,
      deduction_codes: ["tax10"],
    });
    const lid = line.json.data.id;
    const edited = await fetch(`${env.base}/api/v1/hr/pay-runs/${rid}/lines/${lid}`, {
      method: "PATCH",
      headers: { "content-type": "application/json", ...authHeaders(hrToken) },
      body: JSON.stringify({ gross_cents: 30000 }),
    });
    const ej = await edited.json();
    expect(edited.status).toBe(200);
    expect(ej.data.deductions_cents).toBe(3000);
    expect(ej.data.net_cents).toBe(27000);
    const del = await fetch(`${env.base}/api/v1/hr/pay-runs/${rid}/lines/${lid}`, {
      method: "DELETE",
      headers: authHeaders(hrToken),
    });
    expect(del.status).toBe(200);
    const view = await get(`/api/v1/hr/pay-runs/${rid}`, hrToken);
    expect(view.json.data.lines.length).toBe(0);
  });

  test("inactive employee cannot get a pay line; bad run dates rejected", async () => {
    const e = await post("/api/v1/hr/employees", hrToken, { first_name: "Term", last_name: "Ed" });
    const eid = e.json.data.id;
    await fetch(`${env.base}/api/v1/hr/employees/${eid}`, {
      method: "PATCH",
      headers: { "content-type": "application/json", ...authHeaders(hrToken) },
      body: JSON.stringify({ status: "terminated" }),
    });
    const run = await post("/api/v1/hr/pay-runs", hrToken, {
      period_start: "2027-02-01",
      period_end: "2027-02-15",
      pay_date: "2027-02-16",
    });
    const line = await post(`/api/v1/hr/pay-runs/${run.json.data.id}/lines`, hrToken, {
      employee_id: eid,
      gross_cents: 1000,
    });
    expect(line.res.status).toBe(409);
    expect(line.json.error.code).toBe("employee_inactive");
    const bad = await post("/api/v1/hr/pay-runs", hrToken, {
      period_start: "2027-03-15",
      period_end: "2027-03-01",
      pay_date: "2027-03-16",
    });
    expect(bad.res.status).toBe(400);
  });
});

describe("retention coverage", () => {
  test("hr policy now covered by employees table", async () => {
    const res = await fetch(`${env.base}/api/v1/compliance/retention-report`, {
      headers: authHeaders(adminToken),
    });
    const json = await res.json();
    const byType = Object.fromEntries(json.data.policies.map((p: any) => [p.entity_type, p]));
    expect(byType.hr.status).toBe("covered");
    expect(byType.hr.covered_table).toBe("employees");
    expect(byType.hr.record_count).toBeGreaterThan(0);
  });
});
