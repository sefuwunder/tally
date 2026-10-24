// Tally ERP — ar.ts
// Accounts receivable: customers, invoices (+lines), payments (with
// application logic), credit memos. Every GL effect flows through
// postJournal()/reverseJournal() (ledger.ts) — this module never touches
// journal_entries directly. Posted invoices are never edited in place:
// corrections happen via void (reversing entry) or credit memo.
//
// Conventions from phases 0–2:
//  - Money in integer cents; rejects non-integers.
//  - All financial writes inside one SQLite transaction, audit row inside
//    the same transaction (sync appendAudit).
//  - Errors are ArError with a stable machine .code the HTTP layer maps
//    to a status (validation 400, not_found 404, over_applied 400,
//    state conflicts 409). LedgerError passes through untouched so the
//    HTTP layer can map it with ledgerError().

import type { Database } from "bun:sqlite";
import { appendAudit } from "./audit";
import { nowIso } from "./db";
import { postJournal, reverseJournal, LedgerError } from "./ledger";

export class ArError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "ArError";
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
    throw new ArError("validation", `${label} must be an integer`);
  }
  if (opts.min !== undefined && v < opts.min) {
    throw new ArError("validation", `${label} must be >= ${opts.min}`);
  }
  return v;
}

function reqDate(v: unknown, label: string): string {
  if (typeof v !== "string" || !isValidDate(v)) {
    throw new ArError("validation", `${label} must be YYYY-MM-DD`);
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

// --- customers ----------------------------------------------------------------

export interface CustomerRow {
  id: number;
  name: string;
  email: string | null;
  phone: string | null;
  billing_address: string | null;
  credit_limit_cents: number;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface CustomerInput {
  name: string;
  email?: string | null;
  phone?: string | null;
  billing_address?: string | null;
  credit_limit_cents?: number;
  status?: string;
}

function validateCustomerInput(input: Partial<CustomerInput>, partial: boolean): CustomerInput {
  const out: CustomerInput = { name: "" };
  if (input.name !== undefined || !partial) {
    const name = typeof input.name === "string" ? input.name.trim() : "";
    if (!name) throw new ArError("validation", "customer name is required");
    if (name.length > 500) throw new ArError("validation", "customer name is too long (max 500 chars)");
    out.name = name;
  }
  if (input.email !== undefined) {
    if (input.email !== null && typeof input.email !== "string") {
      throw new ArError("validation", "email must be a string or null");
    }
    const email = typeof input.email === "string" ? input.email.trim() : null;
    if (email !== null && email !== "" && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      throw new ArError("validation", "email does not look like an email address");
    }
    out.email = email === "" ? null : email;
  }
  if (input.phone !== undefined) {
    out.phone = typeof input.phone === "string" ? input.phone.trim().slice(0, 100) : null;
  }
  if (input.billing_address !== undefined) {
    out.billing_address =
      typeof input.billing_address === "string" ? input.billing_address.trim().slice(0, 2000) : null;
  }
  if (input.credit_limit_cents !== undefined) {
    out.credit_limit_cents = reqInt(input.credit_limit_cents, "credit_limit_cents", { min: 0 });
  }
  if (input.status !== undefined) {
    if (input.status !== "active" && input.status !== "inactive") {
      throw new ArError("validation", "status must be active or inactive");
    }
    out.status = input.status;
  }
  return out;
}

export function createCustomer(db: Database, input: CustomerInput, actorId: number | null): CustomerRow {
  const v = validateCustomerInput(input, false);
  const now = nowIso();
  return db.transaction((): CustomerRow => {
    const info = db
      .query(
        `INSERT INTO customers (name, email, phone, billing_address, credit_limit_cents, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        v.name,
        v.email ?? null,
        v.phone ?? null,
        v.billing_address ?? null,
        v.credit_limit_cents ?? 0,
        v.status ?? "active",
        now,
        now,
      );
    const id = Number(info.lastInsertRowid);
    appendAudit(db, {
      actor_id: actorId,
      action: "customer.create",
      entity_type: "customer",
      entity_id: id,
      after: { name: v.name, email: v.email ?? null },
    });
    return getCustomer(db, id)!;
  })();
}

export function getCustomer(db: Database, id: number): CustomerRow | null {
  const row = db.query("SELECT * FROM customers WHERE id = ?").get(id) as CustomerRow | undefined;
  return row ?? null;
}

export function listCustomers(db: Database, opts: { status?: string } = {}): CustomerRow[] {
  const where: string[] = [];
  const params: string[] = [];
  if (opts.status) {
    if (opts.status !== "active" && opts.status !== "inactive") {
      throw new ArError("validation", "status must be active or inactive");
    }
    where.push("status = ?");
    params.push(opts.status);
  }
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
  return db.query(`SELECT * FROM customers ${clause} ORDER BY name ASC, id ASC`).all(...params) as CustomerRow[];
}

export function updateCustomer(
  db: Database,
  id: number,
  input: Partial<CustomerInput>,
  actorId: number | null,
): CustomerRow {
  const before = getCustomer(db, id);
  if (!before) throw new ArError("not_found", `customer ${id} not found`);
  const v = validateCustomerInput(input, true);
  return db.transaction((): CustomerRow => {
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
    if (v.billing_address !== undefined) {
      sets.push("billing_address = ?");
      params.push(v.billing_address);
    }
    if (v.credit_limit_cents !== undefined) {
      sets.push("credit_limit_cents = ?");
      params.push(v.credit_limit_cents);
    }
    if (v.status !== undefined) {
      sets.push("status = ?");
      params.push(v.status);
    }
    params.push(id);
    db.query(`UPDATE customers SET ${sets.join(", ")} WHERE id = ?`).run(...params);
    appendAudit(db, {
      actor_id: actorId,
      action: "customer.update",
      entity_type: "customer",
      entity_id: id,
      before: { name: before.name, status: before.status },
      after: { name: v.name || before.name, status: v.status || before.status },
    });
    return getCustomer(db, id)!;
  })();
}

// --- invoices -----------------------------------------------------------------

export interface InvoiceLineInput {
  description: string;
  quantity: number;
  unit_price_cents: number;
}

export interface InvoiceLineRow {
  id: number;
  invoice_id: number;
  description: string;
  quantity: number;
  unit_price_cents: number;
  amount_cents: number;
}

export interface InvoiceRow {
  id: number;
  invoice_no: string;
  customer_id: number;
  status: string;
  issue_date: string;
  due_date: string;
  subtotal_cents: number;
  tax_cents: number;
  total_cents: number;
  paid_cents: number;
  credited_cents: number;
  posted_entry_id: number | null;
  void_entry_id: number | null;
  created_by: number | null;
  created_at: string;
  updated_at: string;
}

export interface InvoiceView extends InvoiceRow {
  open_balance_cents: number;
  lines: InvoiceLineRow[];
}

export interface InvoiceInput {
  customer_id: number;
  issue_date: string;
  due_date: string;
  tax_cents?: number;
  lines: InvoiceLineInput[];
}

function validateLines(raw: unknown): { lines: InvoiceLineInput[]; subtotal: number } {
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new ArError("validation", "an invoice needs at least one line");
  }
  const lines: InvoiceLineInput[] = [];
  let subtotal = 0;
  let i = 0;
  for (const ln of raw) {
    i++;
    if (typeof ln !== "object" || ln === null) {
      throw new ArError("validation", `line ${i}: must be an object`);
    }
    const l = ln as Record<string, unknown>;
    const description = typeof l.description === "string" ? l.description.trim() : "";
    if (!description) throw new ArError("validation", `line ${i}: description is required`);
    if (description.length > 1000) {
      throw new ArError("validation", `line ${i}: description is too long (max 1000 chars)`);
    }
    const quantity = reqInt(l.quantity, `line ${i}: quantity`, { min: 1 });
    const unitPrice = reqInt(l.unit_price_cents, `line ${i}: unit_price_cents`, { min: 0 });
    lines.push({ description, quantity, unit_price_cents: unitPrice });
    subtotal += quantity * unitPrice;
  }
  return { lines, subtotal };
}

function getInvoiceRow(db: Database, id: number): InvoiceRow | null {
  const row = db.query("SELECT * FROM invoices WHERE id = ?").get(id) as InvoiceRow | undefined;
  return row ?? null;
}

function invoiceLines(db: Database, invoiceId: number): InvoiceLineRow[] {
  return db
    .query("SELECT * FROM invoice_lines WHERE invoice_id = ? ORDER BY id ASC")
    .all(invoiceId) as InvoiceLineRow[];
}

/** Open balance: what the customer still owes on this invoice. */
export function openBalance(inv: InvoiceRow): number {
  return inv.total_cents - inv.paid_cents - inv.credited_cents;
}

export function invoiceView(db: Database, inv: InvoiceRow): InvoiceView {
  return { ...inv, open_balance_cents: openBalance(inv), lines: invoiceLines(db, inv.id) };
}

export function getInvoice(db: Database, id: number): InvoiceView | null {
  const row = getInvoiceRow(db, id);
  return row ? invoiceView(db, row) : null;
}

export function listInvoices(
  db: Database,
  opts: { customer_id?: number; status?: string } = {},
): InvoiceView[] {
  const where: string[] = [];
  const params: (number | string)[] = [];
  if (opts.customer_id !== undefined) {
    where.push("customer_id = ?");
    params.push(opts.customer_id);
  }
  if (opts.status !== undefined) {
    if (!["draft", "posted", "partially_paid", "paid", "void"].includes(opts.status)) {
      throw new ArError("validation", `unknown invoice status '${opts.status}'`);
    }
    where.push("status = ?");
    params.push(opts.status);
  }
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const rows = db
    .query(`SELECT * FROM invoices ${clause} ORDER BY id DESC`)
    .all(...params) as InvoiceRow[];
  return rows.map((r) => invoiceView(db, r));
}

export function createInvoice(db: Database, input: InvoiceInput, actorId: number | null): InvoiceView {
  const customerId = reqInt(input.customer_id, "customer_id", { min: 1 });
  const customer = getCustomer(db, customerId);
  if (!customer) throw new ArError("not_found", `customer ${customerId} not found`);
  const issueDate = reqDate(input.issue_date, "issue_date");
  const dueDate = reqDate(input.due_date, "due_date");
  if (dueDate < issueDate) {
    throw new ArError("validation", "due_date must not be before issue_date");
  }
  const tax = input.tax_cents === undefined ? 0 : reqInt(input.tax_cents, "tax_cents", { min: 0 });
  const { lines, subtotal } = validateLines(input.lines);
  const total = subtotal + tax;
  if (total <= 0) {
    throw new ArError("validation", "invoice total must be positive");
  }
  const now = nowIso();
  return db.transaction((): InvoiceView => {
    const invoiceNo = nextDocNo(db, "invoice", "INV");
    const info = db
      .query(
        `INSERT INTO invoices
           (invoice_no, customer_id, status, issue_date, due_date,
            subtotal_cents, tax_cents, total_cents, created_by, created_at, updated_at)
         VALUES (?, ?, 'draft', ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(invoiceNo, customerId, issueDate, dueDate, subtotal, tax, total, actorId, now, now);
    const id = Number(info.lastInsertRowid);
    const insertLine = db.query(
      "INSERT INTO invoice_lines (invoice_id, description, quantity, unit_price_cents, amount_cents) VALUES (?, ?, ?, ?, ?)",
    );
    for (const l of lines) {
      insertLine.run(id, l.description, l.quantity, l.unit_price_cents, l.quantity * l.unit_price_cents);
    }
    appendAudit(db, {
      actor_id: actorId,
      action: "invoice.create",
      entity_type: "invoice",
      entity_id: invoiceNo,
      after: { customer_id: customerId, total_cents: total, lines: lines.length },
    });
    return getInvoice(db, id)!;
  })();
}

/** Draft-only edit: due_date, tax_cents, and/or a full line replacement. */
export function updateInvoiceDraft(
  db: Database,
  id: number,
  input: { due_date?: string; tax_cents?: number; lines?: InvoiceLineInput[] },
  actorId: number | null,
): InvoiceView {
  const inv = getInvoiceRow(db, id);
  if (!inv) throw new ArError("not_found", `invoice ${id} not found`);
  if (inv.status !== "draft") {
    throw new ArError("not_draft", `invoice ${inv.invoice_no} is ${inv.status} and cannot be edited (void it or credit it instead)`);
  }
  let dueDate = inv.due_date;
  if (input.due_date !== undefined) {
    dueDate = reqDate(input.due_date, "due_date");
    if (dueDate < inv.issue_date) {
      throw new ArError("validation", "due_date must not be before issue_date");
    }
  }
  let tax = inv.tax_cents;
  if (input.tax_cents !== undefined) tax = reqInt(input.tax_cents, "tax_cents", { min: 0 });
  let lines: InvoiceLineInput[] | null = null;
  let subtotal = inv.subtotal_cents;
  if (input.lines !== undefined) {
    const v = validateLines(input.lines);
    lines = v.lines;
    subtotal = v.subtotal;
  }
  const total = subtotal + tax;
  if (total <= 0) throw new ArError("validation", "invoice total must be positive");
  return db.transaction((): InvoiceView => {
    if (lines !== null) {
      db.query("DELETE FROM invoice_lines WHERE invoice_id = ?").run(id);
      const insertLine = db.query(
        "INSERT INTO invoice_lines (invoice_id, description, quantity, unit_price_cents, amount_cents) VALUES (?, ?, ?, ?, ?)",
      );
      for (const l of lines) {
        insertLine.run(id, l.description, l.quantity, l.unit_price_cents, l.quantity * l.unit_price_cents);
      }
    }
    db.query(
      "UPDATE invoices SET due_date = ?, tax_cents = ?, subtotal_cents = ?, total_cents = ?, updated_at = ? WHERE id = ?",
    ).run(dueDate, tax, subtotal, total, nowIso(), id);
    appendAudit(db, {
      actor_id: actorId,
      action: "invoice.update",
      entity_type: "invoice",
      entity_id: inv.invoice_no,
      before: { due_date: inv.due_date, tax_cents: inv.tax_cents, total_cents: inv.total_cents },
      after: { due_date: dueDate, tax_cents: tax, total_cents: total },
    });
    return getInvoice(db, id)!;
  })();
}

/**
 * Post a draft invoice: Dr Accounts Receivable (1100) / Cr Sales Revenue
 * (4000) / Cr Sales Tax Payable (2100). GL posted_on = issue_date, so the
 * invoice must fall in an open period (LedgerError period_closed /
 * no_open_period propagate).
 */
export function postInvoice(db: Database, id: number, actorId: number | null): InvoiceView {
  const inv = getInvoiceRow(db, id);
  if (!inv) throw new ArError("not_found", `invoice ${id} not found`);
  if (inv.status !== "draft") {
    throw new ArError("already_posted", `invoice ${inv.invoice_no} is ${inv.status}, not draft`);
  }
  return db.transaction((): InvoiceView => {
    const journalLines: { account_code: string; debit_cents?: number; credit_cents?: number }[] = [
      { account_code: "1100", debit_cents: inv.total_cents },
    ];
    if (inv.subtotal_cents > 0) {
      journalLines.push({ account_code: "4000", credit_cents: inv.subtotal_cents });
    }
    if (inv.tax_cents > 0) {
      journalLines.push({ account_code: "2100", credit_cents: inv.tax_cents });
    }
    // postJournal runs in a nested transaction (savepoint) — atomic with
    // the status change below.
    const posted = postJournal(db, {
      memo: `Invoice ${inv.invoice_no}`,
      lines: journalLines,
      actor_id: actorId,
      posted_on: inv.issue_date,
      source_type: "ar",
      source_id: `invoice:${inv.id}`,
    });
    db.query("UPDATE invoices SET status = 'posted', posted_entry_id = ?, updated_at = ? WHERE id = ?").run(
      posted.id,
      nowIso(),
      id,
    );
    appendAudit(db, {
      actor_id: actorId,
      action: "invoice.post",
      entity_type: "invoice",
      entity_id: inv.invoice_no,
      after: { entry_no: posted.entry_no, total_cents: inv.total_cents },
    });
    return getInvoice(db, id)!;
  })();
}

/**
 * Void a posted invoice: posts a reversing entry (original untouched) and
 * marks the invoice void. Refused while any payment or credit memo is
 * applied — voiding would strand those GL entries; credit the balance
 * instead. (void_blocked, 409.)
 */
export function voidInvoice(db: Database, id: number, actorId: number | null): InvoiceView {
  const inv = getInvoiceRow(db, id);
  if (!inv) throw new ArError("not_found", `invoice ${id} not found`);
  if (inv.status === "void") throw new ArError("already_void", `invoice ${inv.invoice_no} is already void`);
  if (inv.status === "draft") {
    throw new ArError("not_posted", `invoice ${inv.invoice_no} is still draft and cannot be voided`);
  }
  if (inv.paid_cents > 0 || inv.credited_cents > 0) {
    throw new ArError(
      "void_blocked",
      `invoice ${inv.invoice_no} has payments/credits applied (${inv.paid_cents + inv.credited_cents} cents); issue a credit memo instead of voiding`,
    );
  }
  if (inv.posted_entry_id === null) {
    throw new ArError("validation", `invoice ${inv.invoice_no} has no posted entry to reverse`);
  }
  return db.transaction((): InvoiceView => {
    const reversal = reverseJournal(db, inv.posted_entry_id!, {
      actor_id: actorId,
      memo: `Void of ${inv.invoice_no}`,
    });
    db.query("UPDATE invoices SET status = 'void', void_entry_id = ?, updated_at = ? WHERE id = ?").run(
      reversal.id,
      nowIso(),
      id,
    );
    appendAudit(db, {
      actor_id: actorId,
      action: "invoice.void",
      entity_type: "invoice",
      entity_id: inv.invoice_no,
      after: { reversal_entry_no: reversal.entry_no },
    });
    return getInvoice(db, id)!;
  })();
}

// --- payments ---------------------------------------------------------------

export interface PaymentApplicationInput {
  invoice_id: number;
  amount_cents: number;
}

export interface PaymentRow {
  id: number;
  payment_no: string;
  customer_id: number;
  method: string;
  amount_cents: number;
  unapplied_cents: number;
  received_on: string;
  posted_entry_id: number | null;
  created_by: number | null;
  created_at: string;
}

export interface PaymentApplicationRow {
  id: number;
  payment_id: number;
  invoice_id: number;
  invoice_no: string;
  amount_cents: number;
  applied_at: string;
}

export interface PaymentView extends PaymentRow {
  applications: PaymentApplicationRow[];
}

export interface PaymentInput {
  customer_id: number;
  method: string;
  amount_cents: number;
  received_on: string;
  applications?: PaymentApplicationInput[];
}

const PAYMENT_METHODS = ["cash", "check", "card", "wire", "other"] as const;

/** Recompute posted/partially_paid/paid from paid + credited coverage. */
function deriveInvoiceStatus(inv: InvoiceRow): string {
  if (inv.status === "void" || inv.status === "draft") return inv.status;
  const covered = inv.paid_cents + inv.credited_cents;
  if (covered >= inv.total_cents) return "paid";
  if (covered > 0) return "partially_paid";
  return "posted";
}

/**
 * Validate one application against an invoice: same customer, posted (not
 * draft/void), and never more than the invoice's open balance.
 */
function assertApplicationFits(
  db: Database,
  invoiceId: number,
  customerId: number,
  amount: number,
): InvoiceRow {
  const inv = getInvoiceRow(db, invoiceId);
  if (!inv) throw new ArError("not_found", `invoice ${invoiceId} not found`);
  if (inv.customer_id !== customerId) {
    throw new ArError("validation", `invoice ${inv.invoice_no} belongs to a different customer`);
  }
  if (inv.status === "draft" || inv.status === "void") {
    throw new ArError("validation", `invoice ${inv.invoice_no} is ${inv.status} and cannot receive payments`);
  }
  const open = openBalance(inv);
  if (amount > open) {
    throw new ArError(
      "over_applied",
      `application of ${amount} exceeds open balance ${open} on ${inv.invoice_no}`,
    );
  }
  return inv;
}

function paymentView(db: Database, p: PaymentRow): PaymentView {
  const applications = db
    .query(
      `SELECT pa.id, pa.payment_id, pa.invoice_id, i.invoice_no, pa.amount_cents, pa.applied_at
       FROM payment_applications pa JOIN invoices i ON i.id = pa.invoice_id
       WHERE pa.payment_id = ? ORDER BY pa.id ASC`,
    )
    .all(p.id) as PaymentApplicationRow[];
  return { ...p, applications };
}

export function getPayment(db: Database, id: number): PaymentView | null {
  const row = db.query("SELECT * FROM payments WHERE id = ?").get(id) as PaymentRow | undefined;
  return row ? paymentView(db, row) : null;
}

export function listPayments(db: Database, opts: { customer_id?: number } = {}): PaymentView[] {
  const where: string[] = [];
  const params: number[] = [];
  if (opts.customer_id !== undefined) {
    where.push("customer_id = ?");
    params.push(opts.customer_id);
  }
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const rows = db.query(`SELECT * FROM payments ${clause} ORDER BY id DESC`).all(...params) as PaymentRow[];
  return rows.map((r) => paymentView(db, r));
}

/**
 * Create a payment: Dr Cash (1000) / Cr Accounts Receivable (1100) for the
 * full amount, then apply to invoices (each application ≤ open balance, and
 * the applications' sum ≤ payment amount; the remainder stays unapplied as
 * on-account credit). One atomic transaction.
 */
export function createPayment(db: Database, input: PaymentInput, actorId: number | null): PaymentView {
  const customerId = reqInt(input.customer_id, "customer_id", { min: 1 });
  const customer = getCustomer(db, customerId);
  if (!customer) throw new ArError("not_found", `customer ${customerId} not found`);
  if (typeof input.method !== "string" || !(PAYMENT_METHODS as readonly string[]).includes(input.method)) {
    throw new ArError("validation", `method must be one of ${PAYMENT_METHODS.join(", ")}`);
  }
  const amount = reqInt(input.amount_cents, "amount_cents", { min: 1 });
  const receivedOn = reqDate(input.received_on, "received_on");
  const applications: PaymentApplicationInput[] = [];
  if (input.applications !== undefined) {
    if (!Array.isArray(input.applications)) {
      throw new ArError("validation", "applications must be an array");
    }
    let sum = 0;
    for (const [i, a] of input.applications.entries()) {
      if (typeof a !== "object" || a === null) {
        throw new ArError("validation", `application ${i + 1}: must be an object`);
      }
      const invoiceId = reqInt(a.invoice_id, `application ${i + 1}: invoice_id`, { min: 1 });
      const appAmount = reqInt(a.amount_cents, `application ${i + 1}: amount_cents`, { min: 1 });
      sum += appAmount;
      applications.push({ invoice_id: invoiceId, amount_cents: appAmount });
    }
    if (sum > amount) {
      throw new ArError(
        "over_applied",
        `applications total ${sum} exceeds payment amount ${amount}`,
      );
    }
  }
  // Validate every application BEFORE writing anything.
  const targets = applications.map((a) => ({
    app: a,
    inv: assertApplicationFits(db, a.invoice_id, customerId, a.amount_cents),
  }));
  // Two applications to the same invoice must not jointly over-apply.
  const perInvoice = new Map<number, number>();
  for (const t of targets) {
    const running = (perInvoice.get(t.inv.id) ?? 0) + t.app.amount_cents;
    if (running > openBalance(t.inv)) {
      throw new ArError(
        "over_applied",
        `combined applications of ${running} exceed open balance ${openBalance(t.inv)} on ${t.inv.invoice_no}`,
      );
    }
    perInvoice.set(t.inv.id, running);
  }

  const now = nowIso();
  return db.transaction((): PaymentView => {
    const paymentNo = nextDocNo(db, "payment", "PMT");
    const unapplied = amount - targets.reduce((s, t) => s + t.app.amount_cents, 0);
    const info = db
      .query(
        `INSERT INTO payments
           (payment_no, customer_id, method, amount_cents, unapplied_cents,
            received_on, created_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(paymentNo, customerId, input.method, amount, unapplied, receivedOn, actorId, now);
    const paymentId = Number(info.lastInsertRowid);
    const insertApp = db.query(
      "INSERT INTO payment_applications (payment_id, invoice_id, amount_cents, applied_at) VALUES (?, ?, ?, ?)",
    );
    for (const t of targets) {
      insertApp.run(paymentId, t.inv.id, t.app.amount_cents, now);
    }
    // Apply to invoices: bump paid_cents, recompute status.
    for (const [invoiceId, appTotal] of perInvoice) {
      const inv = getInvoiceRow(db, invoiceId)!;
      const paid = inv.paid_cents + appTotal;
      const updated: InvoiceRow = { ...inv, paid_cents: paid };
      db.query("UPDATE invoices SET paid_cents = ?, status = ?, updated_at = ? WHERE id = ?").run(
        paid,
        deriveInvoiceStatus(updated),
        now,
        invoiceId,
      );
    }
    // GL: full payment amount hits Cash/AR (applications are AR allocation,
    // not separate postings — one entry, no double-count).
    const posted = postJournal(db, {
      memo: `Payment ${paymentNo}`,
      lines: [
        { account_code: "1000", debit_cents: amount },
        { account_code: "1100", credit_cents: amount },
      ],
      actor_id: actorId,
      posted_on: receivedOn,
      source_type: "ar",
      source_id: `payment:${paymentId}`,
    });
    db.query("UPDATE payments SET posted_entry_id = ? WHERE id = ?").run(posted.id, paymentId);
    appendAudit(db, {
      actor_id: actorId,
      action: "payment.create",
      entity_type: "payment",
      entity_id: paymentNo,
      after: {
        customer_id: customerId,
        amount_cents: amount,
        unapplied_cents: unapplied,
        entry_no: posted.entry_no,
        applications: targets.map((t) => ({ invoice_id: t.inv.id, amount_cents: t.app.amount_cents })),
      },
    });
    return getPayment(db, paymentId)!;
  })();
}

/**
 * Apply leftover on-account credit to an invoice. No new GL entry — the cash
 * was already recognized when the payment was created; this only reallocates
 * the AR side between the payment's unapplied balance and the invoice.
 */
export function applyPayment(
  db: Database,
  paymentId: number,
  invoiceId: number,
  amount: number,
  actorId: number | null,
): PaymentView {
  const payment = db.query("SELECT * FROM payments WHERE id = ?").get(paymentId) as
    | PaymentRow
    | undefined;
  if (!payment) throw new ArError("not_found", `payment ${paymentId} not found`);
  const appAmount = reqInt(amount, "amount_cents", { min: 1 });
  if (appAmount > payment.unapplied_cents) {
    throw new ArError(
      "over_applied",
      `application of ${appAmount} exceeds unapplied credit ${payment.unapplied_cents} on ${payment.payment_no}`,
    );
  }
  const inv = assertApplicationFits(db, invoiceId, payment.customer_id, appAmount);
  const now = nowIso();
  return db.transaction((): PaymentView => {
    db.query(
      "INSERT INTO payment_applications (payment_id, invoice_id, amount_cents, applied_at) VALUES (?, ?, ?, ?)",
    ).run(paymentId, invoiceId, appAmount, now);
    db.query("UPDATE payments SET unapplied_cents = ? WHERE id = ?").run(
      payment.unapplied_cents - appAmount,
      paymentId,
    );
    const paid = inv.paid_cents + appAmount;
    const updated: InvoiceRow = { ...inv, paid_cents: paid };
    db.query("UPDATE invoices SET paid_cents = ?, status = ?, updated_at = ? WHERE id = ?").run(
      paid,
      deriveInvoiceStatus(updated),
      now,
      invoiceId,
    );
    appendAudit(db, {
      actor_id: actorId,
      action: "payment.apply",
      entity_type: "payment",
      entity_id: payment.payment_no,
      after: { invoice_id: invoiceId, amount_cents: appAmount, unapplied_cents: payment.unapplied_cents - appAmount },
    });
    return getPayment(db, paymentId)!;
  })();
}

// --- credit memos -------------------------------------------------------------

export interface CreditMemoRow {
  id: number;
  memo_no: string;
  customer_id: number;
  invoice_id: number;
  status: string;
  amount_cents: number;
  reason: string;
  posted_entry_id: number | null;
  void_entry_id: number | null;
  created_by: number | null;
  created_at: string;
  updated_at: string;
}

export interface CreditMemoView extends CreditMemoRow {
  invoice_no: string;
}

export interface CreditMemoInput {
  customer_id: number;
  invoice_id: number;
  amount_cents: number;
  reason: string;
}

function creditMemoView(db: Database, m: CreditMemoRow): CreditMemoView {
  const inv = db.query("SELECT invoice_no FROM invoices WHERE id = ?").get(m.invoice_id) as
    | { invoice_no: string }
    | undefined;
  return { ...m, invoice_no: inv?.invoice_no ?? "" };
}

export function getCreditMemo(db: Database, id: number): CreditMemoView | null {
  const row = db.query("SELECT * FROM credit_memos WHERE id = ?").get(id) as
    | CreditMemoRow
    | undefined;
  return row ? creditMemoView(db, row) : null;
}

export function listCreditMemos(
  db: Database,
  opts: { customer_id?: number; invoice_id?: number } = {},
): CreditMemoView[] {
  const where: string[] = [];
  const params: number[] = [];
  if (opts.customer_id !== undefined) {
    where.push("customer_id = ?");
    params.push(opts.customer_id);
  }
  if (opts.invoice_id !== undefined) {
    where.push("invoice_id = ?");
    params.push(opts.invoice_id);
  }
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const rows = db.query(`SELECT * FROM credit_memos ${clause} ORDER BY id DESC`).all(...params) as CreditMemoRow[];
  return rows.map((r) => creditMemoView(db, r));
}

export function createCreditMemo(
  db: Database,
  input: CreditMemoInput,
  actorId: number | null,
): CreditMemoView {
  const customerId = reqInt(input.customer_id, "customer_id", { min: 1 });
  const customer = getCustomer(db, customerId);
  if (!customer) throw new ArError("not_found", `customer ${customerId} not found`);
  const invoiceId = reqInt(input.invoice_id, "invoice_id", { min: 1 });
  const amount = reqInt(input.amount_cents, "amount_cents", { min: 1 });
  const reason = typeof input.reason === "string" ? input.reason.trim() : "";
  if (!reason) throw new ArError("validation", "reason is required");
  if (reason.length > 2000) throw new ArError("validation", "reason is too long (max 2000 chars)");
  const inv = getInvoiceRow(db, invoiceId);
  if (!inv) throw new ArError("not_found", `invoice ${invoiceId} not found`);
  if (inv.customer_id !== customerId) {
    throw new ArError("validation", `invoice ${inv.invoice_no} belongs to a different customer`);
  }
  if (inv.status === "draft" || inv.status === "void") {
    throw new ArError("validation", `invoice ${inv.invoice_no} is ${inv.status} and cannot be credited`);
  }
  if (amount > openBalance(inv)) {
    throw new ArError(
      "over_applied",
      `credit of ${amount} exceeds open balance ${openBalance(inv)} on ${inv.invoice_no}`,
    );
  }
  const now = nowIso();
  return db.transaction((): CreditMemoView => {
    const memoNo = nextDocNo(db, "credit_memo", "CM");
    const info = db
      .query(
        `INSERT INTO credit_memos
           (memo_no, customer_id, invoice_id, status, amount_cents, reason, created_by, created_at, updated_at)
         VALUES (?, ?, ?, 'draft', ?, ?, ?, ?, ?)`,
      )
      .run(memoNo, customerId, invoiceId, amount, reason, actorId, now, now);
    const id = Number(info.lastInsertRowid);
    appendAudit(db, {
      actor_id: actorId,
      action: "credit_memo.create",
      entity_type: "credit_memo",
      entity_id: memoNo,
      after: { invoice_id: invoiceId, amount_cents: amount },
    });
    return getCreditMemo(db, id)!;
  })();
}

/**
 * Post a credit memo: Dr Sales Revenue (4000) / Cr Accounts Receivable
 * (1100), and reduce the invoice's open balance via credited_cents.
 * Draft memos are validated against the CURRENT open balance at post time —
 * a memo created against a balance since paid down is refused (over_applied),
 * never silently over-credited.
 */
export function postCreditMemo(db: Database, id: number, actorId: number | null): CreditMemoView {
  const memo = db.query("SELECT * FROM credit_memos WHERE id = ?").get(id) as
    | CreditMemoRow
    | undefined;
  if (!memo) throw new ArError("not_found", `credit memo ${id} not found`);
  if (memo.status !== "draft") {
    throw new ArError("already_posted", `credit memo ${memo.memo_no} is ${memo.status}, not draft`);
  }
  const inv = getInvoiceRow(db, memo.invoice_id);
  if (!inv) throw new ArError("not_found", `invoice ${memo.invoice_id} not found`);
  if (inv.status === "void") {
    throw new ArError("validation", `invoice ${inv.invoice_no} is void; the memo cannot post`);
  }
  if (memo.amount_cents > openBalance(inv)) {
    throw new ArError(
      "over_applied",
      `credit of ${memo.amount_cents} exceeds current open balance ${openBalance(inv)} on ${inv.invoice_no}`,
    );
  }
  return db.transaction((): CreditMemoView => {
    const posted = postJournal(db, {
      memo: `Credit memo ${memo.memo_no} against ${inv.invoice_no}`,
      lines: [
        { account_code: "4000", debit_cents: memo.amount_cents },
        { account_code: "1100", credit_cents: memo.amount_cents },
      ],
      actor_id: actorId,
      posted_on: todayDate(),
      source_type: "ar",
      source_id: `credit_memo:${memo.id}`,
    });
    const credited = inv.credited_cents + memo.amount_cents;
    const updated: InvoiceRow = { ...inv, credited_cents: credited };
    db.query("UPDATE invoices SET credited_cents = ?, status = ?, updated_at = ? WHERE id = ?").run(
      credited,
      deriveInvoiceStatus(updated),
      nowIso(),
      inv.id,
    );
    db.query("UPDATE credit_memos SET status = 'posted', posted_entry_id = ?, updated_at = ? WHERE id = ?").run(
      posted.id,
      nowIso(),
      memo.id,
    );
    appendAudit(db, {
      actor_id: actorId,
      action: "credit_memo.post",
      entity_type: "credit_memo",
      entity_id: memo.memo_no,
      after: { invoice_id: inv.id, amount_cents: memo.amount_cents, entry_no: posted.entry_no },
    });
    return getCreditMemo(db, memo.id)!;
  })();
}

/**
 * Void a posted credit memo: reversing entry restores the invoice's open
 * balance (credited_cents drops, status recomputed). Draft memos cannot be
 * voided — they were never posted, so there is nothing to reverse.
 */
export function voidCreditMemo(db: Database, id: number, actorId: number | null): CreditMemoView {
  const memo = db.query("SELECT * FROM credit_memos WHERE id = ?").get(id) as
    | CreditMemoRow
    | undefined;
  if (!memo) throw new ArError("not_found", `credit memo ${id} not found`);
  if (memo.status === "void") throw new ArError("already_void", `credit memo ${memo.memo_no} is already void`);
  if (memo.status !== "posted") {
    throw new ArError("not_posted", `credit memo ${memo.memo_no} is draft and cannot be voided`);
  }
  if (memo.posted_entry_id === null) {
    throw new ArError("validation", `credit memo ${memo.memo_no} has no posted entry to reverse`);
  }
  const inv = getInvoiceRow(db, memo.invoice_id);
  if (!inv) throw new ArError("not_found", `invoice ${memo.invoice_id} not found`);
  return db.transaction((): CreditMemoView => {
    const reversal = reverseJournal(db, memo.posted_entry_id!, {
      actor_id: actorId,
      memo: `Void of ${memo.memo_no}`,
    });
    const credited = inv.credited_cents - memo.amount_cents;
    const updated: InvoiceRow = { ...inv, credited_cents: credited };
    db.query("UPDATE invoices SET credited_cents = ?, status = ?, updated_at = ? WHERE id = ?").run(
      credited,
      deriveInvoiceStatus(updated),
      nowIso(),
      inv.id,
    );
    db.query("UPDATE credit_memos SET status = 'void', void_entry_id = ?, updated_at = ? WHERE id = ?").run(
      reversal.id,
      nowIso(),
      memo.id,
    );
    appendAudit(db, {
      actor_id: actorId,
      action: "credit_memo.void",
      entity_type: "credit_memo",
      entity_id: memo.memo_no,
      after: { reversal_entry_no: reversal.entry_no },
    });
    return getCreditMemo(db, memo.id)!;
  })();
}

// Re-exported so callers can distinguish ledger failures from AR failures.
export { LedgerError };
