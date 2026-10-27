// Tally ERP — reports.ts
// Phase 9 reporting: P&L, balance sheet, cash flow, AR/AP aging, and
// pinned report_runs (what/when/by whom + sha256 of the output).
//
// All figures come from posted journal lines only — reports never read
// module tables except aging, which reconciles its open balances back to
// the GL control accounts (1100/2000). Money in integer cents; dates
// are YYYY-MM-DD and compared as strings (ISO dates sort correctly).
//
// Conventions (v1, documented rather than hidden):
//  - P&L / cash flow take a fiscal period (period_id) or an explicit
//    from/to range; neither is defaulted, so a report always states its
//    window in its output.
//  - Cash accounts are the 10xx asset family (seeded 1000 Cash, 1010
//    Petty Cash). Cash-flow classification is by counterpart family:
//    equity counterparts -> financing, 15xx fixed-asset counterparts ->
//    investing, everything else -> operating.
//  - Aging buckets are by days past due at as_of: current (not yet due),
//    1-30, 31-60, 61-90, 90+.
//  - Aging reconciles as: total_open - total_unapplied == GL control
//    balance. A payment credits the control account for its FULL amount
//    while only the applied part reduces open invoices/bills, so the
//    unapplied remainder is the wedge — reported, not hidden.

import type { Database } from "bun:sqlite";
import { appendAudit, canonicalJson } from "./audit";
import { sha256HexSync } from "./crypto";
import { nowIso } from "./db";

export const REPORT_TYPES = [
  "profit_loss",
  "balance_sheet",
  "cash_flow",
  "ar_aging",
  "ap_aging",
] as const;
export type ReportType = (typeof REPORT_TYPES)[number];

export class ReportError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "ReportError";
    this.code = code;
  }
}

export interface ReportParams {
  period_id?: number;
  from?: string;
  to?: string;
  as_of?: string;
}

function isValidDate(d: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) return false;
  const dt = new Date(`${d}T00:00:00Z`);
  return !Number.isNaN(dt.getTime()) && dt.toISOString().slice(0, 10) === d;
}

function todayDate(): string {
  return new Date().toISOString().slice(0, 10);
}

/** Days from `earlier` to `later` (negative when later < earlier). */
function daysBetween(earlier: string, later: string): number {
  const ms = Date.parse(`${later}T00:00:00Z`) - Date.parse(`${earlier}T00:00:00Z`);
  return Math.floor(ms / 86400000);
}

interface PeriodRow {
  id: number;
  name: string;
  starts_on: string;
  ends_on: string;
}

/** Resolve a report window: explicit period, or from/to. Both must be sane. */
function resolveRange(
  db: Database,
  params: ReportParams,
): { period_id: number | null; from: string; to: string } {
  if (params.period_id !== undefined) {
    if (!Number.isInteger(params.period_id) || params.period_id <= 0) {
      throw new ReportError("validation", "period_id must be a positive integer");
    }
    const p = db
      .query("SELECT id, name, starts_on, ends_on FROM fiscal_periods WHERE id = ?")
      .get(params.period_id) as PeriodRow | undefined;
    if (!p) throw new ReportError("not_found", `fiscal period ${params.period_id} not found`);
    return { period_id: p.id, from: p.starts_on, to: p.ends_on };
  }
  const from = params.from;
  const to = params.to;
  if (!from || !to) {
    throw new ReportError("validation", "period_id or both from and to are required");
  }
  if (!isValidDate(from)) throw new ReportError("validation", `from must be YYYY-MM-DD, got '${from}'`);
  if (!isValidDate(to)) throw new ReportError("validation", `to must be YYYY-MM-DD, got '${to}'`);
  if (from > to) throw new ReportError("validation", "from must not be after to");
  return { period_id: null, from, to };
}

function resolveAsOf(params: ReportParams): string {
  const asOf = params.as_of ?? todayDate();
  if (!isValidDate(asOf)) {
    throw new ReportError("validation", `as_of must be YYYY-MM-DD, got '${params.as_of}'`);
  }
  return asOf;
}

interface AccountBalance {
  account_id: number;
  code: string;
  name: string;
  type: string;
  debits: number;
  credits: number;
  /** Signed amount in the account's normal-balance direction. */
  balance_cents: number;
}

/**
 * Per-account journal-line sums. `to` bounds posted_on above (inclusive);
 * `from` bounds below (inclusive) when given. Accounts with no lines in
 * range still appear with zero balances.
 */
function accountBalances(
  db: Database,
  opts: { from?: string; to: string },
): AccountBalance[] {
  // NOTE: the date window must filter LINES, not just entries. An earlier
  // draft put the window in a LEFT JOIN ... ON clause for journal_entries,
  // which nulls the entry but still sums the line — out-of-window activity
  // leaked into every report. The window therefore lives inside a derived
  // table of in-window lines, LEFT-joined so idle accounts still appear.
  const entryConds: string[] = [];
  const params: string[] = [];
  if (opts.from) {
    entryConds.push("e.posted_on >= ?");
    params.push(opts.from);
  }
  entryConds.push("e.posted_on <= ?");
  params.push(opts.to);
  const rows = db
    .query(
      `SELECT a.id AS account_id, a.code, a.name, a.type,
              COALESCE(SUM(l.debit_cents), 0) AS debits,
              COALESCE(SUM(l.credit_cents), 0) AS credits
       FROM accounts a
       LEFT JOIN (
         SELECT l.account_id, l.debit_cents, l.credit_cents
         FROM journal_lines l
         JOIN journal_entries e ON e.id = l.entry_id
         WHERE ${entryConds.join(" AND ")}
       ) l ON l.account_id = a.id
       WHERE a.deleted_at IS NULL
       GROUP BY a.id ORDER BY a.code ASC`,
    )
    .all(...params) as {
    account_id: number;
    code: string;
    name: string;
    type: string;
    debits: number;
    credits: number;
  }[];
  return rows.map((r) => {
    const debitNormal = r.type === "asset" || r.type === "expense";
    return {
      ...r,
      balance_cents: debitNormal ? r.debits - r.credits : r.credits - r.debits,
    };
  });
}

// --- profit & loss ------------------------------------------------------------

export interface ProfitLossRow {
  account_id: number;
  code: string;
  name: string;
  balance_cents: number;
}

export interface ProfitLoss {
  report_type: "profit_loss";
  period_id: number | null;
  from: string;
  to: string;
  revenue: ProfitLossRow[];
  expenses: ProfitLossRow[];
  total_revenue_cents: number;
  total_expenses_cents: number;
  net_income_cents: number;
}

/** Revenue (credit-normal) and expense (debit-normal) activity in the window. */
export function profitLoss(db: Database, params: ReportParams): ProfitLoss {
  const range = resolveRange(db, params);
  const balances = accountBalances(db, { from: range.from, to: range.to });
  const toRow = (b: AccountBalance): ProfitLossRow => ({
    account_id: b.account_id,
    code: b.code,
    name: b.name,
    balance_cents: b.balance_cents,
  });
  const revenue = balances.filter((b) => b.type === "revenue" && b.balance_cents !== 0).map(toRow);
  const expenses = balances.filter((b) => b.type === "expense" && b.balance_cents !== 0).map(toRow);
  const total_revenue_cents = revenue.reduce((s, r) => s + r.balance_cents, 0);
  const total_expenses_cents = expenses.reduce((s, r) => s + r.balance_cents, 0);
  return {
    report_type: "profit_loss",
    period_id: range.period_id,
    from: range.from,
    to: range.to,
    revenue,
    expenses,
    total_revenue_cents,
    total_expenses_cents,
    net_income_cents: total_revenue_cents - total_expenses_cents,
  };
}

// --- balance sheet ------------------------------------------------------------

export interface BalanceSheet {
  report_type: "balance_sheet";
  as_of: string;
  assets: ProfitLossRow[];
  liabilities: ProfitLossRow[];
  equity: ProfitLossRow[];
  net_income_cents: number;
  total_assets_cents: number;
  total_liabilities_cents: number;
  total_equity_cents: number;
  balanced: boolean;
}

/**
 * Balances as of a date. Equity here is the equity accounts PLUS net
 * income to date (revenue minus expenses), so the identity
 * assets == liabilities + equity is checkable directly.
 */
export function balanceSheet(db: Database, params: ReportParams): BalanceSheet {
  const asOf = resolveAsOf(params);
  const balances = accountBalances(db, { to: asOf });
  const toRow = (b: AccountBalance): ProfitLossRow => ({
    account_id: b.account_id,
    code: b.code,
    name: b.name,
    balance_cents: b.balance_cents,
  });
  const assets = balances.filter((b) => b.type === "asset" && b.balance_cents !== 0).map(toRow);
  const liabilities = balances
    .filter((b) => b.type === "liability" && b.balance_cents !== 0)
    .map(toRow);
  const equity = balances.filter((b) => b.type === "equity" && b.balance_cents !== 0).map(toRow);
  const rev = balances
    .filter((b) => b.type === "revenue")
    .reduce((s, b) => s + b.balance_cents, 0);
  const exp = balances
    .filter((b) => b.type === "expense")
    .reduce((s, b) => s + b.balance_cents, 0);
  const net_income_cents = rev - exp;
  const total_assets_cents = assets.reduce((s, r) => s + r.balance_cents, 0);
  const total_liabilities_cents = liabilities.reduce((s, r) => s + r.balance_cents, 0);
  const equityAccounts = equity.reduce((s, r) => s + r.balance_cents, 0);
  const total_equity_cents = equityAccounts + net_income_cents;
  return {
    report_type: "balance_sheet",
    as_of: asOf,
    assets,
    liabilities,
    equity,
    net_income_cents,
    total_assets_cents,
    total_liabilities_cents,
    total_equity_cents,
    balanced: total_assets_cents === total_liabilities_cents + total_equity_cents,
  };
}

// --- cash flow ----------------------------------------------------------------

export interface CashFlow {
  report_type: "cash_flow";
  period_id: number | null;
  from: string;
  to: string;
  cash_accounts: string[];
  operating_cents: number;
  investing_cents: number;
  financing_cents: number;
  net_change_cents: number;
  beginning_cash_cents: number;
  ending_cash_cents: number;
}

/** Cash accounts: the 10xx asset family (seeded 1000 Cash, 1010 Petty Cash). */
function cashAccountIds(db: Database): { ids: number[]; codes: string[] } {
  const rows = db
    .query(
      "SELECT id, code FROM accounts WHERE type = 'asset' AND code LIKE '10%' AND deleted_at IS NULL ORDER BY code ASC",
    )
    .all() as { id: number; code: string }[];
  return { ids: rows.map((r) => r.id), codes: rows.map((r) => r.code) };
}

/**
 * Indirect-by-entry cash flow: every entry touching a cash account moves
 * cash by (cash debits - cash credits), classified by its non-cash
 * counterparts — equity -> financing, 15xx fixed assets -> investing,
 * everything else -> operating.
 */
export function cashFlow(db: Database, params: ReportParams): CashFlow {
  const range = resolveRange(db, params);
  const cash = cashAccountIds(db);
  if (cash.ids.length === 0) {
    throw new ReportError("validation", "no cash accounts (10xx asset family) in the chart");
  }
  const placeholders = cash.ids.map(() => "?").join(",");
  const beginning = db
    .query(
      `SELECT COALESCE(SUM(l.debit_cents - l.credit_cents), 0) AS n
       FROM journal_lines l JOIN journal_entries e ON e.id = l.entry_id
       WHERE l.account_id IN (${placeholders}) AND e.posted_on < ?`,
    )
    .get(...cash.ids, range.from) as { n: number };
  const beginning_cash_cents = beginning.n;

  const entryIds = db
    .query(
      `SELECT DISTINCT e.id FROM journal_entries e
       JOIN journal_lines l ON l.entry_id = e.id
       WHERE l.account_id IN (${placeholders}) AND e.posted_on >= ? AND e.posted_on <= ?
       ORDER BY e.id ASC`,
    )
    .all(...cash.ids, range.from, range.to) as { id: number }[];

  let operating_cents = 0;
  let investing_cents = 0;
  let financing_cents = 0;
  for (const { id } of entryIds) {
    const lines = db
      .query(
        `SELECT l.account_id, a.code, a.type, l.debit_cents, l.credit_cents
         FROM journal_lines l JOIN accounts a ON a.id = l.account_id
         WHERE l.entry_id = ?`,
      )
      .all(id) as {
      account_id: number;
      code: string;
      type: string;
      debit_cents: number;
      credit_cents: number;
    }[];
    let cashDelta = 0;
    let section: "operating" | "investing" | "financing" = "operating";
    for (const ln of lines) {
      if (cash.ids.includes(ln.account_id)) {
        cashDelta += ln.debit_cents - ln.credit_cents;
      } else if (ln.type === "equity") {
        section = "financing";
      } else if (ln.type === "asset" && ln.code.startsWith("15")) {
        if (section !== "financing") section = "investing";
      }
    }
    if (section === "financing") financing_cents += cashDelta;
    else if (section === "investing") investing_cents += cashDelta;
    else operating_cents += cashDelta;
  }
  const net_change_cents = operating_cents + investing_cents + financing_cents;
  return {
    report_type: "cash_flow",
    period_id: range.period_id,
    from: range.from,
    to: range.to,
    cash_accounts: cash.codes,
    operating_cents,
    investing_cents,
    financing_cents,
    net_change_cents,
    beginning_cash_cents,
    ending_cash_cents: beginning_cash_cents + net_change_cents,
  };
}

// --- aging --------------------------------------------------------------------

export interface AgingBuckets {
  current_cents: number;
  days_1_30_cents: number;
  days_31_60_cents: number;
  days_61_90_cents: number;
  days_90_plus_cents: number;
}

export interface AgingCustomer {
  customer_id: number;
  customer_name: string;
  buckets: AgingBuckets;
  total_open_cents: number;
}

export interface Aging {
  report_type: "ar_aging" | "ap_aging";
  as_of: string;
  buckets: AgingBuckets;
  customers: AgingCustomer[];
  total_open_cents: number;
  total_unapplied_cents: number;
  gl_balance_cents: number | null;
  /** total_open - total_unapplied == gl_balance (null when the control account is missing). */
  reconciles: boolean | null;
}

function bucketFor(daysPastDue: number): keyof AgingBuckets {
  if (daysPastDue <= 0) return "current_cents";
  if (daysPastDue <= 30) return "days_1_30_cents";
  if (daysPastDue <= 60) return "days_31_60_cents";
  if (daysPastDue <= 90) return "days_61_90_cents";
  return "days_90_plus_cents";
}

function emptyBuckets(): AgingBuckets {
  return {
    current_cents: 0,
    days_1_30_cents: 0,
    days_31_60_cents: 0,
    days_61_90_cents: 0,
    days_90_plus_cents: 0,
  };
}

function buildAging(
  db: Database,
  reportType: "ar_aging" | "ap_aging",
  params: ReportParams,
): Aging {
  const asOf = resolveAsOf(params);
  const isAr = reportType === "ar_aging";
  const partyTable = isAr ? "customers" : "vendors";
  const docTable = isAr ? "invoices" : "bills";
  const openExpr = isAr ? "total_cents - paid_cents - credited_cents" : "total_cents - paid_cents";
  const payTable = isAr ? "payments" : "bill_payments";
  const controlCode = isAr ? "1100" : "2000";

  const docs = db
    .query(
      `SELECT d.id, d.${isAr ? "customer_id" : "vendor_id"} AS party_id,
              p.name AS party_name, d.due_date,
              (${openExpr}) AS open_cents
       FROM ${docTable} d JOIN ${partyTable} p ON p.id = d.${isAr ? "customer_id" : "vendor_id"}
       WHERE d.status IN ('posted', 'partially_paid') AND (${openExpr}) > 0
       ORDER BY d.due_date ASC, d.id ASC`,
    )
    .all() as { id: number; party_id: number; party_name: string; due_date: string; open_cents: number }[];

  const buckets = emptyBuckets();
  const byParty = new Map<number, AgingCustomer>();
  for (const d of docs) {
    const bucket = bucketFor(daysBetween(d.due_date, asOf));
    buckets[bucket] += d.open_cents;
    let row = byParty.get(d.party_id);
    if (!row) {
      row = {
        customer_id: d.party_id,
        customer_name: d.party_name,
        buckets: emptyBuckets(),
        total_open_cents: 0,
      };
      byParty.set(d.party_id, row);
    }
    row.buckets[bucket] += d.open_cents;
    row.total_open_cents += d.open_cents;
  }
  const total_open_cents = docs.reduce((s, d) => s + d.open_cents, 0);
  const unapplied = db
    .query(`SELECT COALESCE(SUM(unapplied_cents), 0) AS n FROM ${payTable}`)
    .get() as { n: number };
  const control = db
    .query("SELECT id FROM accounts WHERE code = ? AND deleted_at IS NULL")
    .get(controlCode) as { id: number } | undefined;
  let gl_balance_cents: number | null = null;
  if (control) {
    const bal = db
      .query(
        `SELECT COALESCE(SUM(l.debit_cents - l.credit_cents), 0) AS n
         FROM journal_lines l JOIN journal_entries e ON e.id = l.entry_id
         WHERE l.account_id = ? AND e.posted_on <= ?`,
      )
      .get(control.id, asOf) as { n: number };
    // 1100 is debit-normal, 2000 credit-normal: report the natural balance.
    gl_balance_cents = isAr ? bal.n : -bal.n;
  }
  const reconciles =
    gl_balance_cents === null ? null : total_open_cents - unapplied.n === gl_balance_cents;
  return {
    report_type: reportType,
    as_of: asOf,
    buckets,
    customers: [...byParty.values()].sort((a, b) => a.customer_name.localeCompare(b.customer_name)),
    total_open_cents,
    total_unapplied_cents: unapplied.n,
    gl_balance_cents,
    reconciles,
  };
}

// --- dispatcher + pinning -------------------------------------------------------

export type ReportOutput = ProfitLoss | BalanceSheet | CashFlow | Aging;

/** Compute any report from a validated (report_type, params) pair. */
export function computeReport(
  db: Database,
  reportType: string,
  params: ReportParams,
): ReportOutput {
  switch (reportType) {
    case "profit_loss":
      return profitLoss(db, params);
    case "balance_sheet":
      return balanceSheet(db, params);
    case "cash_flow":
      return cashFlow(db, params);
    case "ar_aging":
      return buildAging(db, "ar_aging", params);
    case "ap_aging":
      return buildAging(db, "ap_aging", params);
    default:
      throw new ReportError(
        "unknown_report",
        `unknown report type '${reportType}' (expected one of ${REPORT_TYPES.join(", ")})`,
      );
  }
}

export interface ReportRun {
  id: number;
  report_type: string;
  params: ReportParams;
  output: ReportOutput;
  output_sha256: string;
  generated_by: number | null;
  generated_at: string;
}

function rowToRun(row: {
  id: number;
  report_type: string;
  params_json: string;
  output_json: string;
  output_sha256: string;
  generated_by: number | null;
  generated_at: string;
}): ReportRun {
  return {
    id: row.id,
    report_type: row.report_type,
    params: JSON.parse(row.params_json) as ReportParams,
    output: JSON.parse(row.output_json) as ReportOutput,
    output_sha256: row.output_sha256,
    generated_by: row.generated_by,
    generated_at: row.generated_at,
  };
}

/**
 * Pin a report: compute it, hash the canonical output, store the run, and
 * audit the pin — all in one transaction, so the pin and its audit row are
 * atomic. The stored output_json IS the canonical JSON that was hashed.
 */
export function pinReport(
  db: Database,
  reportType: string,
  params: ReportParams,
  actorId: number | null,
): ReportRun {
  if (!(REPORT_TYPES as readonly string[]).includes(reportType)) {
    throw new ReportError(
      "unknown_report",
      `unknown report type '${reportType}' (expected one of ${REPORT_TYPES.join(", ")})`,
    );
  }
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new ReportError("validation", "params must be a JSON object");
  }
  const output = computeReport(db, reportType, params);
  const outputJson = canonicalJson(output);
  const outputSha256 = sha256HexSync(outputJson);
  const generatedAt = nowIso();
  return db.transaction((): ReportRun => {
    const info = db
      .query(
        `INSERT INTO report_runs
           (report_type, params_json, output_json, output_sha256, generated_by, generated_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        reportType,
        JSON.stringify(params),
        outputJson,
        outputSha256,
        actorId,
        generatedAt,
        generatedAt,
      );
    const id = Number(info.lastInsertRowid);
    appendAudit(db, {
      actor_id: actorId,
      action: "report.pin",
      entity_type: "report_run",
      entity_id: id,
      after: { report_type: reportType, params, output_sha256: outputSha256 },
    });
    return rowToRun({
      id,
      report_type: reportType,
      params_json: JSON.stringify(params),
      output_json: outputJson,
      output_sha256: outputSha256,
      generated_by: actorId,
      generated_at: generatedAt,
    });
  })();
}

export function getReportRun(db: Database, id: number): ReportRun | null {
  const row = db.query("SELECT * FROM report_runs WHERE id = ?").get(id) as
    | {
        id: number;
        report_type: string;
        params_json: string;
        output_json: string;
        output_sha256: string;
        generated_by: number | null;
        generated_at: string;
      }
    | undefined;
  return row ? rowToRun(row) : null;
}

export function listReportRuns(
  db: Database,
  opts: { report_type?: string; page?: number; per_page?: number } = {},
): { rows: ReportRun[]; total: number } {
  const where: string[] = [];
  const params: string[] = [];
  if (opts.report_type !== undefined) {
    if (!(REPORT_TYPES as readonly string[]).includes(opts.report_type)) {
      throw new ReportError(
        "unknown_report",
        `unknown report type '${opts.report_type}' (expected one of ${REPORT_TYPES.join(", ")})`,
      );
    }
    where.push("report_type = ?");
    params.push(opts.report_type);
  }
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const total = (
    db.query(`SELECT COUNT(*) AS n FROM report_runs ${clause}`).get(...params) as { n: number }
  ).n;
  const perPage = Math.min(Math.max(opts.per_page ?? 50, 1), 500);
  const page = Math.max(opts.page ?? 1, 1);
  const rows = db
    .query(
      `SELECT * FROM report_runs ${clause} ORDER BY id DESC LIMIT ? OFFSET ?`,
    )
    .all(...params, perPage, (page - 1) * perPage) as {
    id: number;
    report_type: string;
    params_json: string;
    output_json: string;
    output_sha256: string;
    generated_by: number | null;
    generated_at: string;
  }[];
  return { rows: rows.map(rowToRun), total };
}

export interface ReproduceResult {
  run_id: number;
  report_type: string;
  matches: boolean;
  stored_sha256: string;
  recomputed_sha256: string;
  generated_at: string;
}

/**
 * Re-run a pinned report with its stored params and compare hashes. A
 * mismatch is not an error — it is the honest signal that the underlying
 * books moved since the pin (the pin itself never changes: report_runs
 * are trigger-immutable).
 */
export function reproduceReportRun(db: Database, id: number): ReproduceResult {
  const run = getReportRun(db, id);
  if (!run) throw new ReportError("not_found", `report run ${id} not found`);
  const recomputed = computeReport(db, run.report_type, run.params);
  const recomputedSha256 = sha256HexSync(canonicalJson(recomputed));
  return {
    run_id: run.id,
    report_type: run.report_type,
    matches: recomputedSha256 === run.output_sha256,
    stored_sha256: run.output_sha256,
    recomputed_sha256: recomputedSha256,
    generated_at: run.generated_at,
  };
}
