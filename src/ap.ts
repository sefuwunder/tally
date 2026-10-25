// Tally ERP — ap.ts
// Accounts payable: vendors, bills (+lines, each line carries the account
// debited at post time), bill payments (with application logic).
// Maker-checker: draft → approved → posted; the approver must differ from
// the creator (FINRA 3110 supervision angle). Every GL effect flows
// through postJournal()/reverseJournal() (ledger.ts) — this module never
// touches journal_entries directly. Posted bills are never edited in
// place: corrections happen via void (reversing entry).
//
// Conventions from phases 0–3:
//  - Money in integer cents; rejects non-integers.
//  - All financial writes inside one SQLite transaction, audit row inside
//    the same transaction (sync appendAudit).
//  - Errors are ApError with a stable machine .code the HTTP layer maps
//    to a status (validation 400, not_found 404, self_approval 403,
//    state conflicts 409). LedgerError passes through untouched so the
//    HTTP layer can map it with ledgerError().

import type { Database } from "bun:sqlite";
import { appendAudit } from "./audit";
import { nowIso } from "./db";
import { postJournal, reverseJournal, LedgerError } from "./ledger";

export class ApError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "ApError";
    this.code = code;
  }
}

function isValidDate(d: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) return false;
  const dt = new Date(`${d}T00:00:00Z`);
  return !Number.isNaN(dt.getTime()) && dt.toISOString().slice(0, 10) === d;
}

function todayDate(): string {
  return new Date().toISOString().slice(0, 10);
}

function reqInt(v: unknown, label: string, opts: { min?: number } = {}): number {
  if (typeof v !== "number" || !Number.isInteger(v)) {
    throw new ApError("validation", `${label} must be an integer`);
  }
  if (opts.min !== undefined && v < opts.min) {
    throw new ApError("validation", `${label} must be >= ${opts.min}`);
  }
  return v;
}

function reqDate(v: unknown, label: string): string {
  if (typeof v !== "string" || !isValidDate(v)) {
    throw new ApError("validation", `${label} must be YYYY-MM-DD`);
  }
  return v;
}

/** Monotonic document numbers, allocated inside the caller's transaction. */
function nextDocNo(db: Database, name: string, prefix: string): string {
  const row = db
    .query(
      `INSERT INTO sequences (name, next_val) VALUES (?, 1)
       ON CONFLICT (name) DO UPDATE SET next_val = next_val + 1
       RETURNING next_val`,
    )
    .get(name) as { next_val: number };
  return `${prefix}-${String(row.next_val).padStart(6, "0")}`;
}

/** A bill line's account must exist and not be soft-deleted. */
function assertAccountExists(db: Database, code: string, label: string): void {
  const row = db
    .query("SELECT id FROM accounts WHERE code = ? AND deleted_at IS NULL")
    .get(code) as { id: number } | undefined;
  if (!row) throw new ApError("validation", `${label}: account code '${code}' not found`);
}

// --- vendors ------------------------------------------------------------------

export interface VendorRow {
  id: number;
  name: string;
  email: string | null;
  phone: string | null;
  remittance_address: string | null;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface VendorInput {
  name: string;
  email?: string | null;
  phone?: string | null;
  remittance_address?: string | null;
  status?: string;
}

function validateVendorInput(input: Partial<VendorInput>, partial: boolean): VendorInput {
  const out: VendorInput = { name: "" };
  if (input.name !== undefined || !partial) {
    const name = typeof input.name === "string" ? input.name.trim() : "";
    if (!name) throw new ApError("validation", "vendor name is required");
    if (name.length > 500) throw new ApError("validation", "vendor name is too long (max 500 chars)");
    out.name = name;
  }
  if (input.email !== undefined) {
    if (input.email !== null && typeof input.email !== "string") {
      throw new ApError("validation", "email must be a string or null");
    }
    const email = typeof input.email === "string" ? input.email.trim() : null;
    if (email !== null && email !== "" && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      throw new ApError("validation", "email does not look like an email address");
    }
    out.email = email === "" ? null : email;
  }
  if (input.phone !== undefined) {
    out.phone = typeof input.phone === "string" ? input.phone.trim().slice(0, 100) : null;
  }
  if (input.remittance_address !== undefined) {
    out.remittance_address =
      typeof input.remittance_address === "string" ? input.remittance_address.trim().slice(0, 2000) : null;
  }
  if (input.status !== undefined) {
    if (input.status !== "active" && input.status !== "inactive") {
      throw new ApError("validation", "status must be active or inactive");
    }
    out.status = input.status;
  }
  return out;
}

export function createVendor(db: Database, input: VendorInput, actorId: number | null): VendorRow {
  const v = validateVendorInput(input, false);
  const now = nowIso();
  return db.transaction((): VendorRow => {
    const info = db
      .query(
        `INSERT INTO vendors (name, email, phone, remittance_address, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(v.name, v.email ?? null, v.phone ?? null, v.remittance_address ?? null, v.status ?? "active", now, now);
    const id = Number(info.lastInsertRowid);
    appendAudit(db, {
      actor_id: actorId,
      action: "vendor.create",
      entity_type: "vendor",
      entity_id: id,
      after: { name: v.name, email: v.email ?? null },
    });
    return getVendor(db, id)!;
  })();
}

export function getVendor(db: Database, id: number): VendorRow | null {
  const row = db.query("SELECT * FROM vendors WHERE id = ?").get(id) as VendorRow | undefined;
  return row ?? null;
}

export function listVendors(db: Database, opts: { status?: string } = {}): VendorRow[] {
  const where: string[] = [];
  const params: string[] = [];
  if (opts.status) {
    if (opts.status !== "active" && opts.status !== "inactive") {
      throw new ApError("validation", "status must be active or inactive");
    }
    where.push("status = ?");
    params.push(opts.status);
  }
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
  return db.query(`SELECT * FROM vendors ${clause} ORDER BY name ASC, id ASC`).all(...params) as VendorRow[];
}

export function updateVendor(
  db: Database,
  id: number,
  input: Partial<VendorInput>,
  actorId: number | null,
): VendorRow {
  const before = getVendor(db, id);
  if (!before) throw new ApError("not_found", `vendor ${id} not found`);
  const v = validateVendorInput(input, true);
  return db.transaction((): VendorRow => {
    const sets: string[] = ["updated_at = ?"];
    const params: (string | number | null)[] = [nowIso()];
    if (v.name !== undefined && v.name !== "") {
      sets.push("name = ?");
      params.push(v.name);
    }
    if (v.email !== undefined) {
      sets.push("email = ?");
      params.push(v.email);
    }
    if (v.phone !== undefined) {
      sets.push("phone = ?");
      params.push(v.phone);
    }
    if (v.remittance_address !== undefined) {
      sets.push("remittance_address = ?");
      params.push(v.remittance_address);
    }
    if (v.status !== undefined) {
      sets.push("status = ?");
      params.push(v.status);
    }
    params.push(id);
    db.query(`UPDATE vendors SET ${sets.join(", ")} WHERE id = ?`).run(...params);
    appendAudit(db, {
      actor_id: actorId,
      action: "vendor.update",
      entity_type: "vendor",
      entity_id: id,
      before: { name: before.name, status: before.status },
      after: { name: v.name || before.name, status: v.status || before.status },
    });
    return getVendor(db, id)!;
  })();
}

// --- bills ----------------------------------------------------------------------

export interface BillLineInput {
  description: string;
  quantity: number;
  unit_price_cents: number;
  account_code: string;
}

export interface BillLineRow {
  id: number;
  bill_id: number;
  description: string;
  quantity: number;
  unit_price_cents: number;
  amount_cents: number;
  account_code: string;
}

export interface BillRow {
  id: number;
  bill_no: string;
  vendor_id: number;
  status: string;
  bill_date: string;
  due_date: string;
  subtotal_cents: number;
  tax_cents: number;
  total_cents: number;
  paid_cents: number;
  posted_entry_id: number | null;
  void_entry_id: number | null;
  created_by: number | null;
  approved_by: number | null;
  approved_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface BillView extends BillRow {
  open_balance_cents: number;
  lines: BillLineRow[];
}

export interface BillInput {
  vendor_id: number;
  bill_date: string;
  due_date: string;
  tax_cents?: number;
  lines: BillLineInput[];
}

function validateBillLines(db: Database, raw: unknown): { lines: BillLineInput[]; subtotal: number } {
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new ApError("validation", "a bill needs at least one line");
  }
  const lines: BillLineInput[] = [];
  let subtotal = 0;
  let i = 0;
  for (const ln of raw) {
    i++;
    if (typeof ln !== "object" || ln === null) {
      throw new ApError("validation", `line ${i}: must be an object`);
    }
    const l = ln as Record<string, unknown>;
    const description = typeof l.description === "string" ? l.description.trim() : "";
    if (!description) throw new ApError("validation", `line ${i}: description is required`);
    if (description.length > 1000) {
      throw new ApError("validation", `line ${i}: description is too long (max 1000 chars)`);
    }
    const quantity = reqInt(l.quantity, `line ${i}: quantity`, { min: 1 });
    const unitPrice = reqInt(l.unit_price_cents, `line ${i}: unit_price_cents`, { min: 0 });
    const accountCode = typeof l.account_code === "string" ? l.account_code.trim() : "";
    if (!accountCode) throw new ApError("validation", `line ${i}: account_code is required`);
    assertAccountExists(db, accountCode, `line ${i}`);
    lines.push({ description, quantity, unit_price_cents: unitPrice, account_code: accountCode });
    subtotal += quantity * unitPrice;
  }
  return { lines, subtotal };
}

function getBillRow(db: Database, id: number): BillRow | null {
  const row = db.query("SELECT * FROM bills WHERE id = ?").get(id) as BillRow | undefined;
  return row ?? null;
}

function billLines(db: Database, billId: number): BillLineRow[] {
  return db
    .query("SELECT * FROM bill_lines WHERE bill_id = ? ORDER BY id ASC")
    .all(billId) as BillLineRow[];
}

/** Open balance: what is still owed on this bill. */
export function openBalance(bill: BillRow): number {
  return bill.total_cents - bill.paid_cents;
}

export function billView(db: Database, bill: BillRow): BillView {
  return { ...bill, open_balance_cents: openBalance(bill), lines: billLines(db, bill.id) };
}

export function getBill(db: Database, id: number): BillView | null {
  const row = getBillRow(db, id);
  return row ? billView(db, row) : null;
}

export function listBills(
  db: Database,
  opts: { vendor_id?: number; status?: string } = {},
): BillView[] {
  const where: string[] = [];
  const params: (number | string)[] = [];
  if (opts.vendor_id !== undefined) {
    where.push("vendor_id = ?");
    params.push(opts.vendor_id);
  }
  if (opts.status !== undefined) {
    if (!["draft", "approved", "posted", "partially_paid", "paid", "void"].includes(opts.status)) {
      throw new ApError("validation", `unknown bill status '${opts.status}'`);
    }
    where.push("status = ?");
    params.push(opts.status);
  }
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const rows = db.query(`SELECT * FROM bills ${clause} ORDER BY id DESC`).all(...params) as BillRow[];
  return rows.map((r) => billView(db, r));
}

export function createBill(db: Database, input: BillInput, actorId: number | null): BillView {
  const vendorId = reqInt(input.vendor_id, "vendor_id", { min: 1 });
  const vendor = getVendor(db, vendorId);
  if (!vendor) throw new ApError("not_found", `vendor ${vendorId} not found`);
  const billDate = reqDate(input.bill_date, "bill_date");
  const dueDate = reqDate(input.due_date, "due_date");
  if (dueDate < billDate) {
    throw new ApError("validation", "due_date must not be before bill_date");
  }
  const tax = input.tax_cents === undefined ? 0 : reqInt(input.tax_cents, "tax_cents", { min: 0 });
  const { lines, subtotal } = validateBillLines(db, input.lines);
  const total = subtotal + tax;
  if (total <= 0) {
    throw new ApError("validation", "bill total must be positive");
  }
  const now = nowIso();
  return db.transaction((): BillView => {
    const billNo = nextDocNo(db, "bill", "BILL");
    const info = db
      .query(
        `INSERT INTO bills
           (bill_no, vendor_id, status, bill_date, due_date,
            subtotal_cents, tax_cents, total_cents, created_by, created_at, updated_at)
         VALUES (?, ?, 'draft', ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(billNo, vendorId, billDate, dueDate, subtotal, tax, total, actorId, now, now);
    const id = Number(info.lastInsertRowid);
    const insertLine = db.query(
      "INSERT INTO bill_lines (bill_id, description, quantity, unit_price_cents, amount_cents, account_code) VALUES (?, ?, ?, ?, ?, ?)",
    );
    for (const l of lines) {
      insertLine.run(id, l.description, l.quantity, l.unit_price_cents, l.quantity * l.unit_price_cents, l.account_code);
    }
    appendAudit(db, {
      actor_id: actorId,
      action: "bill.create",
      entity_type: "bill",
      entity_id: billNo,
      after: { vendor_id: vendorId, total_cents: total, lines: lines.length },
    });
    return getBill(db, id)!;
  })();
}

/** Draft-only edit: due_date, tax_cents, and/or a full line replacement. */
export function updateBillDraft(
  db: Database,
  id: number,
  input: { due_date?: string; tax_cents?: number; lines?: BillLineInput[] },
  actorId: number | null,
): BillView {
  const bill = getBillRow(db, id);
  if (!bill) throw new ApError("not_found", `bill ${id} not found`);
  if (bill.status !== "draft") {
    throw new ApError("not_draft", `bill ${bill.bill_no} is ${bill.status} and cannot be edited (void it instead)`);
  }
  let dueDate = bill.due_date;
  if (input.due_date !== undefined) {
    dueDate = reqDate(input.due_date, "due_date");
    if (dueDate < bill.bill_date) {
      throw new ApError("validation", "due_date must not be before bill_date");
    }
  }
  let tax = bill.tax_cents;
  if (input.tax_cents !== undefined) tax = reqInt(input.tax_cents, "tax_cents", { min: 0 });
  let lines: BillLineInput[] | null = null;
  let subtotal = bill.subtotal_cents;
  if (input.lines !== undefined) {
    const v = validateBillLines(db, input.lines);
    lines = v.lines;
    subtotal = v.subtotal;
  }
  const total = subtotal + tax;
  if (total <= 0) throw new ApError("validation", "bill total must be positive");
  return db.transaction((): BillView => {
    if (lines !== null) {
      db.query("DELETE FROM bill_lines WHERE bill_id = ?").run(id);
      const insertLine = db.query(
        "INSERT INTO bill_lines (bill_id, description, quantity, unit_price_cents, amount_cents, account_code) VALUES (?, ?, ?, ?, ?, ?)",
      );
      for (const l of lines) {
        insertLine.run(id, l.description, l.quantity, l.unit_price_cents, l.quantity * l.unit_price_cents, l.account_code);
      }
    }
    db.query(
      "UPDATE bills SET due_date = ?, tax_cents = ?, subtotal_cents = ?, total_cents = ?, updated_at = ? WHERE id = ?",
    ).run(dueDate, tax, subtotal, total, nowIso(), id);
    appendAudit(db, {
      actor_id: actorId,
      action: "bill.update",
      entity_type: "bill",
      entity_id: bill.bill_no,
      before: { due_date: bill.due_date, tax_cents: bill.tax_cents, total_cents: bill.total_cents },
      after: { due_date: dueDate, tax_cents: tax, total_cents: total },
    });
    return getBill(db, id)!;
  })();
}

/**
 * Maker-checker approval: draft → approved. The approver must differ from
 * the creator (self_approval, 403) — a bill no one created via the API
 * (created_by NULL, e.g. a system import) may be approved by anyone.
 * Approval is recorded (approved_by/at) so supervision can prove the
 * second pair of eyes existed.
 */
export function approveBill(db: Database, id: number, actorId: number | null): BillView {
  const bill = getBillRow(db, id);
  if (!bill) throw new ApError("not_found", `bill ${id} not found`);
  if (bill.status === "approved") {
    throw new ApError("already_approved", `bill ${bill.bill_no} is already approved`);
  }
  if (bill.status !== "draft") {
    throw new ApError("not_draft", `bill ${bill.bill_no} is ${bill.status} and cannot be approved`);
  }
  if (actorId !== null && bill.created_by !== null && actorId === bill.created_by) {
    throw new ApError(
      "self_approval",
      `bill ${bill.bill_no} was created by this user; approval requires a second user (maker-checker)`,
    );
  }
  const now = nowIso();
  return db.transaction((): BillView => {
    db.query("UPDATE bills SET status = 'approved', approved_by = ?, approved_at = ?, updated_at = ? WHERE id = ?").run(
      actorId,
      now,
      now,
      id,
    );
    appendAudit(db, {
      actor_id: actorId,
      action: "bill.approve",
      entity_type: "bill",
      entity_id: bill.bill_no,
      before: { status: "draft" },
      after: { status: "approved", approved_by: actorId },
    });
    return getBill(db, id)!;
  })();
}

/**
 * Post an approved bill: Dr each line's account / Cr Accounts Payable
 * (2000) for the total. GL posted_on = bill_date, so the bill must fall
 * in an open period (LedgerError period_closed / no_open_period
 * propagate). Zero-amount lines are skipped — postJournal requires
 * exactly one nonzero side per line.
 */
export function postBill(db: Database, id: number, actorId: number | null): BillView {
  const bill = getBillRow(db, id);
  if (!bill) throw new ApError("not_found", `bill ${id} not found`);
  if (bill.status !== "approved") {
    throw new ApError("not_approved", `bill ${bill.bill_no} is ${bill.status}, not approved — approve it first`);
  }
  const lines = billLines(db, id);
  return db.transaction((): BillView => {
    const journalLines: { account_code: string; debit_cents?: number; credit_cents?: number }[] = [];
    for (const l of lines) {
      if (l.amount_cents > 0) journalLines.push({ account_code: l.account_code, debit_cents: l.amount_cents });
    }
    journalLines.push({ account_code: "2000", credit_cents: bill.total_cents });
    // postJournal runs in a nested transaction (savepoint) — atomic with
    // the status change below.
    const posted = postJournal(db, {
      memo: `Bill ${bill.bill_no}`,
      lines: journalLines,
      actor_id: actorId,
      posted_on: bill.bill_date,
      source_type: "ap",
      source_id: `bill:${bill.id}`,
    });
    db.query("UPDATE bills SET status = 'posted', posted_entry_id = ?, updated_at = ? WHERE id = ?").run(
      posted.id,
      nowIso(),
      id,
    );
    appendAudit(db, {
      actor_id: actorId,
      action: "bill.post",
      entity_type: "bill",
      entity_id: bill.bill_no,
      after: { entry_no: posted.entry_no, total_cents: bill.total_cents },
    });
    return getBill(db, id)!;
  })();
}

/**
 * Void a posted bill: posts a reversing entry (original untouched) and
 * marks the bill void. Refused while any payment is applied — voiding
 * would strand those GL entries; the payments stand and the bill stays
 * payable. (void_blocked, 409.) Draft/approved bills cannot be voided —
 * they were never posted, so there is nothing to reverse.
 */
export function voidBill(db: Database, id: number, actorId: number | null): BillView {
  const bill = getBillRow(db, id);
  if (!bill) throw new ApError("not_found", `bill ${id} not found`);
  if (bill.status === "void") throw new ApError("already_void", `bill ${bill.bill_no} is already void`);
  if (bill.status === "draft" || bill.status === "approved") {
    throw new ApError("not_posted", `bill ${bill.bill_no} is ${bill.status} and cannot be voided`);
  }
  if (bill.paid_cents > 0) {
    throw new ApError(
      "void_blocked",
      `bill ${bill.bill_no} has payments applied (${bill.paid_cents} cents); it cannot be voided`,
    );
  }
  if (bill.posted_entry_id === null) {
    throw new ApError("validation", `bill ${bill.bill_no} has no posted entry to reverse`);
  }
  return db.transaction((): BillView => {
    const reversal = reverseJournal(db, bill.posted_entry_id!, {
      actor_id: actorId,
      memo: `Void of ${bill.bill_no}`,
    });
    db.query("UPDATE bills SET status = 'void', void_entry_id = ?, updated_at = ? WHERE id = ?").run(
      reversal.id,
      nowIso(),
      id,
    );
    appendAudit(db, {
      actor_id: actorId,
      action: "bill.void",
      entity_type: "bill",
      entity_id: bill.bill_no,
      after: { reversal_entry_no: reversal.entry_no },
    });
    return getBill(db, id)!;
  })();
}

// --- bill payments --------------------------------------------------------------

export interface BillPaymentApplicationInput {
  bill_id: number;
  amount_cents: number;
}

export interface BillPaymentRow {
  id: number;
  payment_no: string;
  vendor_id: number;
  method: string;
  amount_cents: number;
  unapplied_cents: number;
  paid_on: string;
  posted_entry_id: number | null;
  created_by: number | null;
  created_at: string;
}

export interface BillPaymentApplicationRow {
  id: number;
  payment_id: number;
  bill_id: number;
  bill_no: string;
  amount_cents: number;
  applied_at: string;
}

export interface BillPaymentView extends BillPaymentRow {
  applications: BillPaymentApplicationRow[];
}

export interface BillPaymentInput {
  vendor_id: number;
  method: string;
  amount_cents: number;
  paid_on: string;
  applications?: BillPaymentApplicationInput[];
}

const PAYMENT_METHODS = ["cash", "check", "card", "wire", "other"] as const;

/** Recompute posted/partially_paid/paid from paid coverage. */
function deriveBillStatus(bill: BillRow): string {
  if (bill.status === "void" || bill.status === "draft" || bill.status === "approved") return bill.status;
  if (bill.paid_cents >= bill.total_cents) return "paid";
  if (bill.paid_cents > 0) return "partially_paid";
  return "posted";
}

/**
 * Validate one application against a bill: same vendor, posted-family
 * status (not draft/approved/void), and never more than the bill's open
 * balance.
 */
function assertApplicationFits(
  db: Database,
  billId: number,
  vendorId: number,
  amount: number,
): BillRow {
  const bill = getBillRow(db, billId);
  if (!bill) throw new ApError("not_found", `bill ${billId} not found`);
  if (bill.vendor_id !== vendorId) {
    throw new ApError("validation", `bill ${bill.bill_no} belongs to a different vendor`);
  }
  if (bill.status === "draft" || bill.status === "approved" || bill.status === "void") {
    throw new ApError("validation", `bill ${bill.bill_no} is ${bill.status} and cannot receive payments`);
  }
  const open = openBalance(bill);
  if (amount > open) {
    throw new ApError(
      "over_applied",
      `application of ${amount} exceeds open balance ${open} on ${bill.bill_no}`,
    );
  }
  return bill;
}

function billPaymentView(db: Database, p: BillPaymentRow): BillPaymentView {
  const applications = db
    .query(
      `SELECT pa.id, pa.payment_id, pa.bill_id, b.bill_no, pa.amount_cents, pa.applied_at
       FROM bill_payment_applications pa JOIN bills b ON b.id = pa.bill_id
       WHERE pa.payment_id = ? ORDER BY pa.id ASC`,
    )
    .all(p.id) as BillPaymentApplicationRow[];
  return { ...p, applications };
}

export function getBillPayment(db: Database, id: number): BillPaymentView | null {
  const row = db.query("SELECT * FROM bill_payments WHERE id = ?").get(id) as
    | BillPaymentRow
    | undefined;
  return row ? billPaymentView(db, row) : null;
}

export function listBillPayments(db: Database, opts: { vendor_id?: number } = {}): BillPaymentView[] {
  const where: string[] = [];
  const params: number[] = [];
  if (opts.vendor_id !== undefined) {
    where.push("vendor_id = ?");
    params.push(opts.vendor_id);
  }
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const rows = db.query(`SELECT * FROM bill_payments ${clause} ORDER BY id DESC`).all(...params) as BillPaymentRow[];
  return rows.map((r) => billPaymentView(db, r));
}

/**
 * Create a bill payment: Dr Accounts Payable (2000) / Cr Cash (1000) for
 * the full amount, then apply to bills (each application ≤ open balance,
 * and the applications' sum ≤ payment amount; the remainder stays
 * unapplied as on-account credit). One atomic transaction.
 */
export function createBillPayment(db: Database, input: BillPaymentInput, actorId: number | null): BillPaymentView {
  const vendorId = reqInt(input.vendor_id, "vendor_id", { min: 1 });
  const vendor = getVendor(db, vendorId);
  if (!vendor) throw new ApError("not_found", `vendor ${vendorId} not found`);
  if (typeof input.method !== "string" || !(PAYMENT_METHODS as readonly string[]).includes(input.method)) {
    throw new ApError("validation", `method must be one of ${PAYMENT_METHODS.join(", ")}`);
  }
  const amount = reqInt(input.amount_cents, "amount_cents", { min: 1 });
  const paidOn = reqDate(input.paid_on, "paid_on");
  const applications: BillPaymentApplicationInput[] = [];
  if (input.applications !== undefined) {
    if (!Array.isArray(input.applications)) {
      throw new ApError("validation", "applications must be an array");
    }
    let sum = 0;
    for (const [i, a] of input.applications.entries()) {
      if (typeof a !== "object" || a === null) {
        throw new ApError("validation", `application ${i + 1}: must be an object`);
      }
      const billId = reqInt(a.bill_id, `application ${i + 1}: bill_id`, { min: 1 });
      const appAmount = reqInt(a.amount_cents, `application ${i + 1}: amount_cents`, { min: 1 });
      sum += appAmount;
      applications.push({ bill_id: billId, amount_cents: appAmount });
    }
    if (sum > amount) {
      throw new ApError(
        "over_applied",
        `applications total ${sum} exceeds payment amount ${amount}`,
      );
    }
  }
  // Validate every application BEFORE writing anything.
  const targets = applications.map((a) => ({
    app: a,
    bill: assertApplicationFits(db, a.bill_id, vendorId, a.amount_cents),
  }));
  // Two applications to the same bill must not jointly over-apply.
  const perBill = new Map<number, number>();
  for (const t of targets) {
    const running = (perBill.get(t.bill.id) ?? 0) + t.app.amount_cents;
    if (running > openBalance(t.bill)) {
      throw new ApError(
        "over_applied",
        `combined applications of ${running} exceed open balance ${openBalance(t.bill)} on ${t.bill.bill_no}`,
      );
    }
    perBill.set(t.bill.id, running);
  }

  const now = nowIso();
  return db.transaction((): BillPaymentView => {
    const paymentNo = nextDocNo(db, "bill_payment", "BPMT");
    const unapplied = amount - targets.reduce((s, t) => s + t.app.amount_cents, 0);
    const info = db
      .query(
        `INSERT INTO bill_payments
           (payment_no, vendor_id, method, amount_cents, unapplied_cents,
            paid_on, created_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(paymentNo, vendorId, input.method, amount, unapplied, paidOn, actorId, now);
    const paymentId = Number(info.lastInsertRowid);
    const insertApp = db.query(
      "INSERT INTO bill_payment_applications (payment_id, bill_id, amount_cents, applied_at) VALUES (?, ?, ?, ?)",
    );
    for (const t of targets) {
      insertApp.run(paymentId, t.bill.id, t.app.amount_cents, now);
    }
    // Apply to bills: bump paid_cents, recompute status.
    for (const [billId, appTotal] of perBill) {
      const bill = getBillRow(db, billId)!;
      const paid = bill.paid_cents + appTotal;
      const updated: BillRow = { ...bill, paid_cents: paid };
      db.query("UPDATE bills SET paid_cents = ?, status = ?, updated_at = ? WHERE id = ?").run(
        paid,
        deriveBillStatus(updated),
        now,
        billId,
      );
    }
    // GL: full payment amount hits AP/Cash (applications are AP allocation,
    // not separate postings — one entry, no double-count).
    const posted = postJournal(db, {
      memo: `Bill payment ${paymentNo}`,
      lines: [
        { account_code: "2000", debit_cents: amount },
        { account_code: "1000", credit_cents: amount },
      ],
      actor_id: actorId,
      posted_on: paidOn,
      source_type: "ap",
      source_id: `bill_payment:${paymentId}`,
    });
    db.query("UPDATE bill_payments SET posted_entry_id = ? WHERE id = ?").run(posted.id, paymentId);
    appendAudit(db, {
      actor_id: actorId,
      action: "bill_payment.create",
      entity_type: "bill_payment",
      entity_id: paymentNo,
      after: {
        vendor_id: vendorId,
        amount_cents: amount,
        unapplied_cents: unapplied,
        entry_no: posted.entry_no,
        applications: targets.map((t) => ({ bill_id: t.bill.id, amount_cents: t.app.amount_cents })),
      },
    });
    return getBillPayment(db, paymentId)!;
  })();
}

/**
 * Apply leftover on-account credit to a bill. No new GL entry — the cash
 * was already recognized when the payment was created; this only reallocates
 * the AP side between the payment's unapplied balance and the bill.
 */
export function applyBillPayment(
  db: Database,
  paymentId: number,
  billId: number,
  amount: number,
  actorId: number | null,
): BillPaymentView {
  const payment = db.query("SELECT * FROM bill_payments WHERE id = ?").get(paymentId) as
    | BillPaymentRow
    | undefined;
  if (!payment) throw new ApError("not_found", `bill payment ${paymentId} not found`);
  const appAmount = reqInt(amount, "amount_cents", { min: 1 });
  if (appAmount > payment.unapplied_cents) {
    throw new ApError(
      "over_applied",
      `application of ${appAmount} exceeds unapplied credit ${payment.unapplied_cents} on ${payment.payment_no}`,
    );
  }
  const bill = assertApplicationFits(db, billId, payment.vendor_id, appAmount);
  const now = nowIso();
  return db.transaction((): BillPaymentView => {
    db.query(
      "INSERT INTO bill_payment_applications (payment_id, bill_id, amount_cents, applied_at) VALUES (?, ?, ?, ?)",
    ).run(paymentId, billId, appAmount, now);
    db.query("UPDATE bill_payments SET unapplied_cents = ? WHERE id = ?").run(
      payment.unapplied_cents - appAmount,
      paymentId,
    );
    const paid = bill.paid_cents + appAmount;
    const updated: BillRow = { ...bill, paid_cents: paid };
    db.query("UPDATE bills SET paid_cents = ?, status = ?, updated_at = ? WHERE id = ?").run(
      paid,
      deriveBillStatus(updated),
      now,
      billId,
    );
    appendAudit(db, {
      actor_id: actorId,
      action: "bill_payment.apply",
      entity_type: "bill_payment",
      entity_id: payment.payment_no,
      after: { bill_id: billId, amount_cents: appAmount, unapplied_cents: payment.unapplied_cents - appAmount },
    });
    return getBillPayment(db, paymentId)!;
  })();
}

// Re-exported so callers can distinguish ledger failures from AP failures.
export { LedgerError };
