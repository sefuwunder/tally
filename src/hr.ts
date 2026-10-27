// Tally ERP — hr.ts
// Phase 8: HR / payroll (HIPAA H-T4 on HR PII, FINRA supervision angle).
//
// - employees: PII (SSN, date of birth, bank account) is stored ONLY as
//   AES-256-GCM blobs via encryptField (H-T4, the Phase 0 mechanism).
//   Encryption happens BEFORE the SQLite transaction (crypto is async,
//   the transaction is sync — same ordering rule as the WORM store).
//   The HTTP surface never returns a blob or a plaintext secret: list/get
//   return ssn_last4 (display only). getEmployeeDecrypted() exists for
//   unit verification and for a future authorized-export path — it is
//   deliberately NOT wired to any route in v1.
//   Audit rows for employees carry employee_no + status only — never a
//   plaintext secret, never a ciphertext blob.
// - deduction_types: the pay-line deduction config. kind=percent stores
//   basis points (10000 = 100%); kind=fixed stores a flat amount.
//   Percent deductions round half-up in integer cents (same rule as
//   inventory weighted averages); total deductions may never exceed
//   gross (net >= 0, enforced by code AND the pay_lines CHECK).
// - pay_runs: draft -> approved -> paid. Approval is maker-checker:
//   hr:approve AND approver != creator (self_approval, 403), with
//   approved_by/approved_at recorded. Paying posts ONE summary journal
//   entry (Dr Wages Expense 6000 / Cr Cash 1000 / Cr Payroll
//   Liabilities 2200, posted_on = pay_date) — per-employee detail never
//   hits the GL directly, and a zero-gross run posts no journal entry
//   (a 0-cent entry would fail postJournal's balance rule, same rule
//   as zero-cost inventory issues). There is no pay-run void in v1:
//   correct a paid run with a reversing journal entry + a new run.
//   Pay lines freeze once the run leaves draft (triggers, F-R3).
//
// Conventions from phases 0–7: money in integer cents; all writes in
// transactions; audit row inside the same transaction; HrError with a
// stable .code the HTTP layer maps to a status.

import type { Database } from "bun:sqlite";
import { appendAudit } from "./audit";
import { nowIso } from "./db";
import { encryptField, decryptField } from "./crypto";
import { postJournal, LedgerError } from "./ledger";

export class HrError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "HrError";
    this.code = code;
  }
}

function isValidDate(d: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) return false;
  const dt = new Date(`${d}T00:00:00Z`);
  return !Number.isNaN(dt.getTime()) && dt.toISOString().slice(0, 10) === d;
}

function reqStr(v: unknown, label: string, max = 2000): string {
  if (typeof v !== "string" || !v.trim()) {
    throw new HrError("validation", `${label} is required`);
  }
  return v.trim().slice(0, max);
}

function optStr(v: unknown, max = 2000): string | null {
  return typeof v === "string" && v.trim() ? v.trim().slice(0, max) : null;
}

function reqInt(v: unknown, label: string, opts: { min?: number } = {}): number {
  if (typeof v !== "number" || !Number.isInteger(v)) {
    throw new HrError("validation", `${label} must be an integer`);
  }
  if (opts.min !== undefined && v < opts.min) {
    throw new HrError("validation", `${label} must be >= ${opts.min}`);
  }
  return v;
}

function emailScreen(email: string | null): void {
  if (email !== null && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new HrError("validation", `email '${email}' is not a valid email address`);
  }
}

function last4Of(secret: string): string | null {
  const digits = secret.replace(/\D/g, "");
  return digits.length >= 4 ? digits.slice(-4) : null;
}

function nextEmployeeNo(db: Database): string {
  const row = db
    .query(
      `INSERT INTO sequences (name, next_val) VALUES ('employee', 1)
       ON CONFLICT (name) DO UPDATE SET next_val = next_val + 1
       RETURNING next_val`,
    )
    .get() as { next_val: number };
  return `EMP-${String(row.next_val).padStart(4, "0")}`;
}

// --- employees ---------------------------------------------------------------

interface EmployeeRowRaw {
  id: number;
  employee_no: string;
  first_name: string;
  last_name: string;
  email: string | null;
  status: string;
  hire_date: string | null;
  pay_type: string;
  base_pay_cents: number;
  ssn_enc: string | null;
  ssn_last4: string | null;
  dob_enc: string | null;
  bank_account_enc: string | null;
  created_by: number | null;
  created_at: string;
  updated_at: string;
}

/** The HTTP-safe view: encrypted blobs and plaintext secrets never leave. */
export interface EmployeeView {
  id: number;
  employee_no: string;
  first_name: string;
  last_name: string;
  email: string | null;
  status: string;
  hire_date: string | null;
  pay_type: string;
  base_pay_cents: number;
  ssn_last4: string | null;
  created_by: number | null;
  created_at: string;
  updated_at: string;
}

/** The decrypted view: unit verification + future authorized export only. NOT routed. */
export interface EmployeeDecrypted extends EmployeeView {
  ssn: string | null;
  date_of_birth: string | null;
  bank_account: string | null;
}

function toView(r: EmployeeRowRaw): EmployeeView {
  const { ssn_enc: _s, dob_enc: _d, bank_account_enc: _b, ...view } = r;
  void _s;
  void _d;
  void _b;
  return view;
}

function employeeRaw(db: Database, id: number): EmployeeRowRaw | null {
  const row = db.query("SELECT * FROM employees WHERE id = ?").get(id) as
    | EmployeeRowRaw
    | undefined;
  return row ?? null;
}

export function getEmployee(db: Database, id: number): EmployeeView | null {
  const r = employeeRaw(db, id);
  return r ? toView(r) : null;
}

/** Decrypt an employee's PII fields. Throws on a wrong data key (GCM auth). */
export async function getEmployeeDecrypted(db: Database, id: number): Promise<EmployeeDecrypted | null> {
  const r = employeeRaw(db, id);
  if (!r) return null;
  return {
    ...toView(r),
    ssn: r.ssn_enc ? await decryptField(r.ssn_enc) : null,
    date_of_birth: r.dob_enc ? await decryptField(r.dob_enc) : null,
    bank_account: r.bank_account_enc ? await decryptField(r.bank_account_enc) : null,
  };
}

export function listEmployees(db: Database, opts: { status?: string } = {}): EmployeeView[] {
  if (opts.status !== undefined && !["active", "inactive", "terminated"].includes(opts.status)) {
    throw new HrError("validation", `unknown employee status '${opts.status}'`);
  }
  const clause = opts.status !== undefined ? "WHERE status = ?" : "";
  const params = opts.status !== undefined ? [opts.status] : [];
  const rows = db
    .query(`SELECT * FROM employees ${clause} ORDER BY id DESC`)
    .all(...params) as EmployeeRowRaw[];
  return rows.map(toView);
}

export interface EmployeeInput {
  first_name?: unknown;
  last_name?: unknown;
  email?: unknown;
  status?: unknown;
  hire_date?: unknown;
  pay_type?: unknown;
  base_pay_cents?: unknown;
  ssn?: unknown;
  date_of_birth?: unknown;
  bank_account?: unknown;
}

function validateEmployeeFields(
  input: EmployeeInput,
  before: EmployeeRowRaw | null,
): {
  first_name: string;
  last_name: string;
  email: string | null;
  status: string;
  hire_date: string | null;
  pay_type: string;
  base_pay_cents: number;
} {
  const first_name =
    input.first_name === undefined
      ? (before?.first_name ?? reqStr(undefined, "first_name"))
      : reqStr(input.first_name, "first_name", 500);
  const last_name =
    input.last_name === undefined
      ? (before?.last_name ?? reqStr(undefined, "last_name"))
      : reqStr(input.last_name, "last_name", 500);
  const email = input.email === undefined ? (before?.email ?? null) : optStr(input.email, 500);
  emailScreen(email);
  const status =
    input.status === undefined ? (before?.status ?? "active") : reqStr(input.status, "status");
  if (!["active", "inactive", "terminated"].includes(status)) {
    throw new HrError("validation", `unknown employee status '${status}'`);
  }
  const hire_date =
    input.hire_date === undefined ? (before?.hire_date ?? null) : optStr(input.hire_date, 10);
  if (hire_date !== null && !isValidDate(hire_date)) {
    throw new HrError("validation", `hire_date must be YYYY-MM-DD`);
  }
  const pay_type =
    input.pay_type === undefined ? (before?.pay_type ?? "salary") : reqStr(input.pay_type, "pay_type");
  if (!["salary", "hourly"].includes(pay_type)) {
    throw new HrError("validation", `pay_type must be 'salary' or 'hourly'`);
  }
  const base_pay_cents =
    input.base_pay_cents === undefined
      ? (before?.base_pay_cents ?? 0)
      : reqInt(input.base_pay_cents, "base_pay_cents", { min: 0 });
  return { first_name, last_name, email, status, hire_date, pay_type, base_pay_cents };
}

/**
 * Encrypt the PII inputs BEFORE any transaction (async crypto, sync
 * transaction — same ordering rule as the WORM store). Returns the blobs
 * plus ssn_last4; null input means "clear the field" on update, undefined
 * means "unchanged" — callers resolve that before insert/update.
 */
async function encryptPii(input: EmployeeInput): Promise<{
  ssn_enc: string | null;
  ssn_last4: string | null;
  dob_enc: string | null;
  bank_enc: string | null;
}> {
  const ssn =
    input.ssn === undefined ? undefined : input.ssn === null ? null : reqStr(input.ssn, "ssn", 100);
  const dob =
    input.date_of_birth === undefined
      ? undefined
      : input.date_of_birth === null
        ? null
        : reqStr(input.date_of_birth, "date_of_birth", 100);
  const bank =
    input.bank_account === undefined
      ? undefined
      : input.bank_account === null
        ? null
        : reqStr(input.bank_account, "bank_account", 500);
  return {
    ssn_enc: ssn === undefined ? undefined as unknown as null : ssn === null ? null : await encryptField(ssn),
    ssn_last4: ssn === undefined ? undefined as unknown as null : ssn === null ? null : last4Of(ssn),
    dob_enc: dob === undefined ? undefined as unknown as null : dob === null ? null : await encryptField(dob),
    bank_enc: bank === undefined ? undefined as unknown as null : bank === null ? null : await encryptField(bank),
  };
}

export async function createEmployee(
  db: Database,
  input: EmployeeInput,
  actorId: number | null,
): Promise<EmployeeView> {
  const fields = validateEmployeeFields(input, null);
  const pii = await encryptPii(input);
  const now = nowIso();
  return db.transaction((): EmployeeView => {
    const employeeNo = nextEmployeeNo(db);
    const info = db
      .query(
        `INSERT INTO employees
           (employee_no, first_name, last_name, email, status, hire_date,
            pay_type, base_pay_cents, ssn_enc, ssn_last4, dob_enc,
            bank_account_enc, created_by, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        employeeNo,
        fields.first_name,
        fields.last_name,
        fields.email,
        fields.status,
        fields.hire_date,
        fields.pay_type,
        fields.base_pay_cents,
        input.ssn === undefined ? null : pii.ssn_enc,
        input.ssn === undefined ? null : pii.ssn_last4,
        input.date_of_birth === undefined ? null : pii.dob_enc,
        input.bank_account === undefined ? null : pii.bank_enc,
        actorId,
        now,
        now,
      );
    const id = Number(info.lastInsertRowid);
    // Audit carries employee_no + status only — never a secret, never a blob.
    appendAudit(db, {
      actor_id: actorId,
      action: "employee.create",
      entity_type: "employee",
      entity_id: id,
      after: { employee_no: employeeNo, status: fields.status },
    });
    return employeeRaw(db, id) ? toView(employeeRaw(db, id)!) : (null as unknown as EmployeeView);
  })();
}

export async function updateEmployee(
  db: Database,
  id: number,
  input: EmployeeInput,
  actorId: number | null,
): Promise<EmployeeView> {
  const before = employeeRaw(db, id);
  if (!before) throw new HrError("not_found", `employee ${id} not found`);
  const fields = validateEmployeeFields(input, before);
  const pii = await encryptPii(input);
  return db.transaction((): EmployeeView => {
    db.query(
      `UPDATE employees SET first_name = ?, last_name = ?, email = ?, status = ?,
         hire_date = ?, pay_type = ?, base_pay_cents = ?,
         ssn_enc = ?, ssn_last4 = ?, dob_enc = ?, bank_account_enc = ?,
         updated_at = ? WHERE id = ?`,
    ).run(
      fields.first_name,
      fields.last_name,
      fields.email,
      fields.status,
      fields.hire_date,
      fields.pay_type,
      fields.base_pay_cents,
      input.ssn === undefined ? before.ssn_enc : pii.ssn_enc,
      input.ssn === undefined ? before.ssn_last4 : pii.ssn_last4,
      input.date_of_birth === undefined ? before.dob_enc : pii.dob_enc,
      input.bank_account === undefined ? before.bank_account_enc : pii.bank_enc,
      nowIso(),
      id,
    );
    appendAudit(db, {
      actor_id: actorId,
      action: "employee.update",
      entity_type: "employee",
      entity_id: id,
      before: { employee_no: before.employee_no, status: before.status },
      after: { employee_no: before.employee_no, status: fields.status },
    });
    return toView(employeeRaw(db, id)!);
  })();
}

// --- deduction types -----------------------------------------------------------

export interface DeductionTypeRow {
  id: number;
  code: string;
  name: string;
  kind: string;
  percent_bps: number | null;
  amount_cents: number | null;
  active: number;
  created_by: number | null;
  created_at: string;
  updated_at: string;
}

export interface DeductionTypeInput {
  code?: unknown;
  name?: unknown;
  kind?: unknown;
  percent_bps?: unknown;
  amount_cents?: unknown;
  active?: unknown;
}

function deductionRow(db: Database, id: number): DeductionTypeRow | null {
  const row = db.query("SELECT * FROM deduction_types WHERE id = ?").get(id) as
    | DeductionTypeRow
    | undefined;
  return row ?? null;
}

export function getDeductionType(db: Database, id: number): DeductionTypeRow | null {
  return deductionRow(db, id);
}

export function listDeductionTypes(db: Database, opts: { active?: boolean } = {}): DeductionTypeRow[] {
  const clause = opts.active === undefined ? "" : "WHERE active = ?";
  const params = opts.active === undefined ? [] : [opts.active ? 1 : 0];
  return db
    .query(`SELECT * FROM deduction_types ${clause} ORDER BY code ASC`)
    .all(...params) as DeductionTypeRow[];
}

export function createDeductionType(
  db: Database,
  input: DeductionTypeInput,
  actorId: number | null,
): DeductionTypeRow {
  const code = reqStr(input.code, "code", 100);
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(code)) {
    throw new HrError("validation", "deduction code must be 1-100 chars: letters, digits, . _ -");
  }
  const name = reqStr(input.name, "name", 500);
  const kind = reqStr(input.kind, "kind");
  if (!["percent", "fixed"].includes(kind)) {
    throw new HrError("validation", `kind must be 'percent' or 'fixed'`);
  }
  let percent_bps: number | null = null;
  let amount_cents: number | null = null;
  if (kind === "percent") {
    percent_bps = reqInt(input.percent_bps, "percent_bps", { min: 0 });
    if (percent_bps > 10000) throw new HrError("validation", "percent_bps must be <= 10000");
    if (input.amount_cents !== undefined && input.amount_cents !== null) {
      throw new HrError("validation", "percent deductions take percent_bps, not amount_cents");
    }
  } else {
    amount_cents = reqInt(input.amount_cents, "amount_cents", { min: 0 });
    if (input.percent_bps !== undefined && input.percent_bps !== null) {
      throw new HrError("validation", "fixed deductions take amount_cents, not percent_bps");
    }
  }
  const active = input.active === undefined ? 1 : input.active === true || input.active === 1 ? 1 : 0;
  const now = nowIso();
  return db.transaction((): DeductionTypeRow => {
    let info;
    try {
      info = db
        .query(
          `INSERT INTO deduction_types
             (code, name, kind, percent_bps, amount_cents, active, created_by, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(code, name, kind, percent_bps, amount_cents, active, actorId, now, now);
    } catch (e) {
      if (e instanceof Error && /UNIQUE constraint failed: deduction_types.code/.test(e.message)) {
        throw new HrError("validation", `deduction code '${code}' already exists`);
      }
      throw e;
    }
    const id = Number(info.lastInsertRowid);
    appendAudit(db, {
      actor_id: actorId,
      action: "deduction_type.create",
      entity_type: "deduction_type",
      entity_id: id,
      after: { code, kind },
    });
    return deductionRow(db, id)!;
  })();
}

/** Resolve deduction codes to computed amounts for a gross. Unknown/inactive -> not_found. */
export function computeDeductions(
  db: Database,
  grossCents: number,
  codes: string[],
): { code: string; amount_cents: number }[] {
  const seen = new Set<string>();
  const out: { code: string; amount_cents: number }[] = [];
  for (const code of codes) {
    if (seen.has(code)) throw new HrError("validation", `duplicate deduction code '${code}'`);
    seen.add(code);
    const t = db
      .query("SELECT * FROM deduction_types WHERE code = ? AND active = 1")
      .get(code) as DeductionTypeRow | undefined;
    if (!t) throw new HrError("not_found", `deduction type '${code}' not found or inactive`);
    const amount =
      t.kind === "percent"
        ? Math.floor((grossCents * (t.percent_bps ?? 0) + 5000) / 10000)
        : (t.amount_cents ?? 0);
    out.push({ code, amount_cents: amount });
  }
  return out;
}

// --- pay runs ------------------------------------------------------------------

export interface PayLineRow {
  id: number;
  pay_run_id: number;
  employee_id: number;
  employee_no: string | null;
  gross_cents: number;
  deductions: { code: string; amount_cents: number }[];
  deductions_cents: number;
  net_cents: number;
  created_at: string;
  updated_at: string;
}

export interface PayRunRow {
  id: number;
  period_start: string;
  period_end: string;
  pay_date: string;
  status: string;
  created_by: number | null;
  approved_by: number | null;
  approved_at: string | null;
  paid_at: string | null;
  journal_entry_id: number | null;
  journal_entry_no: string | null;
  created_at: string;
  updated_at: string;
}

export interface PayRunView extends PayRunRow {
  lines: PayLineRow[];
  total_gross_cents: number;
  total_deductions_cents: number;
  total_net_cents: number;
}

function payRunRaw(db: Database, id: number): PayRunRow | null {
  const r = db.query("SELECT * FROM pay_runs WHERE id = ?").get(id) as
    | (Omit<PayRunRow, "journal_entry_no"> & { journal_entry_no?: string })
    | undefined;
  if (!r) return null;
  const entryNo = r.journal_entry_id
    ? (db.query("SELECT entry_no FROM journal_entries WHERE id = ?").get(r.journal_entry_id) as
      | { entry_no: string }
      | undefined)
    : undefined;
  return { ...r, journal_entry_no: entryNo?.entry_no ?? null };
}

function payLines(db: Database, runId: number): PayLineRow[] {
  const rows = db
    .query(
      `SELECT l.*, e.employee_no FROM pay_lines l
       LEFT JOIN employees e ON e.id = l.employee_id
       WHERE l.pay_run_id = ? ORDER BY l.id ASC`,
    )
    .all(runId) as (Omit<PayLineRow, "deductions"> & { deductions_json: string })[];
  return rows.map((r) => ({
    id: r.id,
    pay_run_id: r.pay_run_id,
    employee_id: r.employee_id,
    employee_no: r.employee_no,
    gross_cents: r.gross_cents,
    deductions: JSON.parse(r.deductions_json) as { code: string; amount_cents: number }[],
    deductions_cents: r.deductions_cents,
    net_cents: r.net_cents,
    created_at: r.created_at,
    updated_at: r.updated_at,
  }));
}

export function getPayRun(db: Database, id: number): PayRunView | null {
  const run = payRunRaw(db, id);
  if (!run) return null;
  const lines = payLines(db, id);
  return {
    ...run,
    lines,
    total_gross_cents: lines.reduce((s, l) => s + l.gross_cents, 0),
    total_deductions_cents: lines.reduce((s, l) => s + l.deductions_cents, 0),
    total_net_cents: lines.reduce((s, l) => s + l.net_cents, 0),
  };
}

export function listPayRuns(db: Database, opts: { status?: string } = {}): PayRunView[] {
  if (opts.status !== undefined && !["draft", "approved", "paid"].includes(opts.status)) {
    throw new HrError("validation", `unknown pay run status '${opts.status}'`);
  }
  const clause = opts.status !== undefined ? "WHERE status = ?" : "";
  const params = opts.status !== undefined ? [opts.status] : [];
  const ids = db
    .query(`SELECT id FROM pay_runs ${clause} ORDER BY id DESC`)
    .all(...params) as { id: number }[];
  return ids.map((r) => getPayRun(db, r.id)!);
}

export interface PayRunInput {
  period_start?: unknown;
  period_end?: unknown;
  pay_date?: unknown;
}

export function createPayRun(db: Database, input: PayRunInput, actorId: number | null): PayRunView {
  const period_start = reqStr(input.period_start, "period_start", 10);
  const period_end = reqStr(input.period_end, "period_end", 10);
  const pay_date = reqStr(input.pay_date, "pay_date", 10);
  for (const [label, d] of [["period_start", period_start], ["period_end", period_end], ["pay_date", pay_date]] as const) {
    if (!isValidDate(d)) throw new HrError("validation", `${label} must be YYYY-MM-DD`);
  }
  if (period_start > period_end) {
    throw new HrError("validation", "period_start must not be after period_end");
  }
  const now = nowIso();
  return db.transaction((): PayRunView => {
    const info = db
      .query(
        `INSERT INTO pay_runs
           (period_start, period_end, pay_date, status, created_by, created_at, updated_at)
         VALUES (?, ?, ?, 'draft', ?, ?, ?)`,
      )
      .run(period_start, period_end, pay_date, actorId, now, now);
    const id = Number(info.lastInsertRowid);
    appendAudit(db, {
      actor_id: actorId,
      action: "pay_run.create",
      entity_type: "pay_run",
      entity_id: id,
      after: { period_start, period_end, pay_date },
    });
    return getPayRun(db, id)!;
  })();
}

function requireDraftRun(db: Database, runId: number): PayRunRow {
  const run = payRunRaw(db, runId);
  if (!run) throw new HrError("not_found", `pay run ${runId} not found`);
  if (run.status !== "draft") {
    throw new HrError("not_draft", `pay run ${runId} is ${run.status}, not draft`);
  }
  return run;
}

export interface PayLineInput {
  employee_id?: unknown;
  gross_cents?: unknown;
  deduction_codes?: unknown;
}

export function addPayLine(
  db: Database,
  runId: number,
  input: PayLineInput,
  actorId: number | null,
): PayLineRow {
  requireDraftRun(db, runId);
  const employeeId = reqInt(input.employee_id, "employee_id", { min: 1 });
  const employee = employeeRaw(db, employeeId);
  if (!employee) throw new HrError("not_found", `employee ${employeeId} not found`);
  if (employee.status !== "active") {
    throw new HrError("employee_inactive", `employee ${employee.employee_no} is ${employee.status}`);
  }
  const gross = reqInt(input.gross_cents, "gross_cents", { min: 0 });
  const codes: string[] = [];
  if (input.deduction_codes !== undefined) {
    if (!Array.isArray(input.deduction_codes)) {
      throw new HrError("validation", "deduction_codes must be an array of codes");
    }
    for (const c of input.deduction_codes) {
      if (typeof c !== "string" || !c.trim()) {
        throw new HrError("validation", "deduction_codes must be an array of codes");
      }
      codes.push(c.trim());
    }
  }
  const deductions = computeDeductions(db, gross, codes);
  const deductionsTotal = deductions.reduce((s, d) => s + d.amount_cents, 0);
  if (deductionsTotal > gross) {
    throw new HrError(
      "deductions_exceed_gross",
      `deductions ${deductionsTotal} exceed gross ${gross}`,
    );
  }
  const now = nowIso();
  return db.transaction((): PayLineRow => {
    let info;
    try {
      info = db
        .query(
          `INSERT INTO pay_lines
             (pay_run_id, employee_id, gross_cents, deductions_json,
              deductions_cents, net_cents, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          runId,
          employeeId,
          gross,
          JSON.stringify(deductions),
          deductionsTotal,
          gross - deductionsTotal,
          now,
          now,
        );
    } catch (e) {
      if (e instanceof Error && /UNIQUE constraint failed: pay_lines.pay_run_id, pay_lines.employee_id/.test(e.message)) {
        throw new HrError("duplicate_line", `employee ${employee.employee_no} already has a line in pay run ${runId}`);
      }
      throw e;
    }
    const id = Number(info.lastInsertRowid);
    appendAudit(db, {
      actor_id: actorId,
      action: "pay_line.add",
      entity_type: "pay_run",
      entity_id: runId,
      after: { pay_line_id: id, employee_id: employeeId, gross_cents: gross, deductions_cents: deductionsTotal },
    });
    return payLines(db, runId).find((l) => l.id === id)!;
  })();
}

export function updatePayLineDraft(
  db: Database,
  runId: number,
  lineId: number,
  input: PayLineInput,
  actorId: number | null,
): PayLineRow {
  requireDraftRun(db, runId);
  const existing = db
    .query("SELECT * FROM pay_lines WHERE id = ? AND pay_run_id = ?")
    .get(lineId, runId) as (Omit<PayLineRow, "deductions"> & { deductions_json: string }) | undefined;
  if (!existing) throw new HrError("not_found", `pay line ${lineId} not found in pay run ${runId}`);
  if (input.employee_id !== undefined && input.employee_id !== existing.employee_id) {
    throw new HrError("validation", "pay line employee cannot change; remove and re-add instead");
  }
  const gross = input.gross_cents === undefined ? existing.gross_cents : reqInt(input.gross_cents, "gross_cents", { min: 0 });
  let codes: string[];
  if (input.deduction_codes === undefined) {
    codes = (JSON.parse(existing.deductions_json) as { code: string }[]).map((d) => d.code);
  } else {
    if (!Array.isArray(input.deduction_codes)) {
      throw new HrError("validation", "deduction_codes must be an array of codes");
    }
    codes = input.deduction_codes.map((c) => {
      if (typeof c !== "string" || !c.trim()) throw new HrError("validation", "deduction_codes must be an array of codes");
      return c.trim();
    });
  }
  const deductions = computeDeductions(db, gross, codes);
  const deductionsTotal = deductions.reduce((s, d) => s + d.amount_cents, 0);
  if (deductionsTotal > gross) {
    throw new HrError("deductions_exceed_gross", `deductions ${deductionsTotal} exceed gross ${gross}`);
  }
  return db.transaction((): PayLineRow => {
    db.query(
      `UPDATE pay_lines SET gross_cents = ?, deductions_json = ?,
         deductions_cents = ?, net_cents = ?, updated_at = ? WHERE id = ?`,
    ).run(gross, JSON.stringify(deductions), deductionsTotal, gross - deductionsTotal, nowIso(), lineId);
    appendAudit(db, {
      actor_id: actorId,
      action: "pay_line.update",
      entity_type: "pay_run",
      entity_id: runId,
      after: { pay_line_id: lineId, gross_cents: gross, deductions_cents: deductionsTotal },
    });
    return payLines(db, runId).find((l) => l.id === lineId)!;
  })();
}

export function removePayLine(db: Database, runId: number, lineId: number, actorId: number | null): void {
  requireDraftRun(db, runId);
  const existing = db
    .query("SELECT id FROM pay_lines WHERE id = ? AND pay_run_id = ?")
    .get(lineId, runId) as { id: number } | undefined;
  if (!existing) throw new HrError("not_found", `pay line ${lineId} not found in pay run ${runId}`);
  db.transaction(() => {
    db.query("DELETE FROM pay_lines WHERE id = ?").run(lineId);
    appendAudit(db, {
      actor_id: actorId,
      action: "pay_line.remove",
      entity_type: "pay_run",
      entity_id: runId,
      after: { pay_line_id: lineId },
    });
  })();
}

/** Maker-checker approval: approver must differ from the run's creator. */
export function approvePayRun(db: Database, runId: number, actorId: number | null): PayRunView {
  const run = payRunRaw(db, runId);
  if (!run) throw new HrError("not_found", `pay run ${runId} not found`);
  if (run.status === "approved") throw new HrError("already_approved", `pay run ${runId} is already approved`);
  if (run.status === "paid") throw new HrError("already_paid", `pay run ${runId} is already paid`);
  const lines = payLines(db, runId);
  if (lines.length === 0) throw new HrError("empty_run", `pay run ${runId} has no pay lines`);
  if (actorId !== null && run.created_by !== null && actorId === run.created_by) {
    throw new HrError("self_approval", "pay run approver must differ from its creator");
  }
  const now = nowIso();
  return db.transaction((): PayRunView => {
    db.query(
      "UPDATE pay_runs SET status = 'approved', approved_by = ?, approved_at = ?, updated_at = ? WHERE id = ?",
    ).run(actorId, now, now, runId);
    appendAudit(db, {
      actor_id: actorId,
      action: "pay_run.approve",
      entity_type: "pay_run",
      entity_id: runId,
      after: { approved_by: actorId, approved_at: now, lines: lines.length },
    });
    return getPayRun(db, runId)!;
  })();
}

/**
 * Pay an approved run: post ONE summary journal entry (Dr Wages 6000 /
 * Cr Cash 1000 / Cr Payroll Liabilities 2200, posted_on = pay_date).
 * A zero-gross run posts no journal entry (same zero rule as inventory).
 * The journal post + status move + audit are one transaction, so a
 * closed period rolls the whole payment back.
 */
export function payPayRun(db: Database, runId: number, actorId: number | null): PayRunView {
  const run = payRunRaw(db, runId);
  if (!run) throw new HrError("not_found", `pay run ${runId} not found`);
  if (run.status === "paid") throw new HrError("already_paid", `pay run ${runId} is already paid`);
  if (run.status !== "approved") throw new HrError("not_approved", `pay run ${runId} is ${run.status}, not approved`);
  const view = getPayRun(db, runId)!;
  const now = nowIso();
  return db.transaction((): PayRunView => {
    let journalId: number | null = null;
    let journalNo: string | null = null;
    if (view.total_gross_cents > 0) {
      const lines: { account_code: string; debit_cents?: number; credit_cents?: number }[] = [
        { account_code: "6000", debit_cents: view.total_gross_cents },
      ];
      if (view.total_net_cents > 0) lines.push({ account_code: "1000", credit_cents: view.total_net_cents });
      if (view.total_deductions_cents > 0) lines.push({ account_code: "2200", credit_cents: view.total_deductions_cents });
      // postJournal runs its own transaction (savepoint-nested); a
      // LedgerError propagates and rolls this outer transaction back.
      const posted = postJournal(db, {
        memo: `Payroll ${run.period_start} to ${run.period_end} (pay run ${runId})`,
        lines,
        actor_id: actorId,
        posted_on: run.pay_date,
        source_type: "pay_run",
        source_id: String(runId),
      });
      journalId = posted.id;
      journalNo = posted.entry_no;
    }
    db.query(
      "UPDATE pay_runs SET status = 'paid', paid_at = ?, journal_entry_id = ?, updated_at = ? WHERE id = ?",
    ).run(now, journalId, now, runId);
    appendAudit(db, {
      actor_id: actorId,
      action: "pay_run.pay",
      entity_type: "pay_run",
      entity_id: runId,
      after: {
        journal_entry_id: journalId,
        journal_entry_no: journalNo,
        total_gross_cents: view.total_gross_cents,
        total_deductions_cents: view.total_deductions_cents,
        total_net_cents: view.total_net_cents,
      },
    });
    return getPayRun(db, runId)!;
  })();
}

// Re-exported so the HTTP layer can delegate LedgerError mapping without
// importing the ledger module twice in the same error path.
export { LedgerError };
