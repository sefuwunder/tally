// Tally ERP — ledger.ts
// Ledger core: the ONLY path to GL writes. Every other module (AR, AP,
// inventory, payroll) must call postJournal() — never touch journal_entries
// directly. Posted entries are immutable at the DB level (migration 002
// triggers); corrections happen only through reverseJournal().
//
// Conventions from phase 0:
//  - Money in integer cents; rejects non-integers.
//  - All financial writes inside one SQLite transaction.
//  - Mutations append an audit row INSIDE the same transaction (sync
//    appendAudit), so audit + data are atomic.
//  - Errors are LedgerError with a stable machine .code the HTTP layer maps
//    to a status (validation 400, unbalanced 400, period_closed 409, ...).

import type { Database } from "bun:sqlite";
import { appendAudit } from "./audit";
import { nowIso } from "./db";

export const ACCOUNT_TYPES = ["asset", "liability", "equity", "revenue", "expense"] as const;
export type AccountType = (typeof ACCOUNT_TYPES)[number];

/** Debit-normal account types (assets, expenses). */
export const DEBIT_NORMAL: ReadonlySet<string> = new Set(["asset", "expense"]);

export class LedgerError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "LedgerError";
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

interface PeriodRow {
  id: number;
  name: string;
  starts_on: string;
  ends_on: string;
  closed_at: string | null;
}

/** Resolve the period for a posting: explicit id, or the open period containing posted_on. */
export function resolvePeriod(db: Database, periodId: number | undefined, postedOn: string): PeriodRow {
  let row: PeriodRow | null | undefined;
  if (periodId !== undefined) {
    row = db.query("SELECT * FROM fiscal_periods WHERE id = ?").get(periodId) as PeriodRow | undefined;
    if (!row) throw new LedgerError("validation", `fiscal period ${periodId} does not exist`);
  } else {
    row = db
      .query(
        "SELECT * FROM fiscal_periods WHERE closed_at IS NULL AND starts_on <= ? AND ends_on >= ? ORDER BY starts_on LIMIT 1",
      )
      .get(postedOn, postedOn) as PeriodRow | undefined;
    if (!row) throw new LedgerError("no_open_period", `no open fiscal period covers ${postedOn}`);
  }
  if (row.closed_at !== null) {
    throw new LedgerError("period_closed", `fiscal period '${row.name}' is closed`);
  }
  if (postedOn < row.starts_on || postedOn > row.ends_on) {
    throw new LedgerError("validation", `posted_on ${postedOn} is outside period '${row.name}'`);
  }
  return row;
}

export interface JournalLineInput {
  account_id?: number;
  account_code?: string;
  debit_cents?: number;
  credit_cents?: number;
}

export interface PostJournalInput {
  period_id?: number;
  memo: string;
  lines: JournalLineInput[];
  actor_id: number | null;
  posted_on?: string;
  source_type?: string | null;
  source_id?: string | null;
}

export interface PostedJournal {
  id: number;
  entry_no: string;
  period_id: number;
  posted_on: string;
}

interface ResolvedLine {
  account_id: number;
  account_code: string;
  debit_cents: number;
  credit_cents: number;
}

function resolveLines(db: Database, lines: JournalLineInput[]): ResolvedLine[] {
  if (!Array.isArray(lines) || lines.length < 2) {
    throw new LedgerError("validation", "a journal entry needs at least 2 lines");
  }
  const resolved: ResolvedLine[] = [];
  let i = 0;
  for (const ln of lines) {
    i++;
    if (typeof ln !== "object" || ln === null) {
      throw new LedgerError("validation", `line ${i}: must be an object`);
    }
    let account: { id: number; code: string } | undefined;
    if (ln.account_id !== undefined) {
      account = db
        .query("SELECT id, code FROM accounts WHERE id = ? AND deleted_at IS NULL")
        .get(ln.account_id) as { id: number; code: string } | undefined;
      if (!account) throw new LedgerError("validation", `line ${i}: account id ${ln.account_id} not found`);
    } else if (ln.account_code !== undefined) {
      account = db
        .query("SELECT id, code FROM accounts WHERE code = ? AND deleted_at IS NULL")
        .get(ln.account_code) as { id: number; code: string } | undefined;
      if (!account) throw new LedgerError("validation", `line ${i}: account code '${ln.account_code}' not found`);
    } else {
      throw new LedgerError("validation", `line ${i}: account_id or account_code required`);
    }
    const debit = ln.debit_cents ?? 0;
    const credit = ln.credit_cents ?? 0;
    for (const [label, v] of [["debit_cents", debit], ["credit_cents", credit]] as const) {
      if (typeof v !== "number" || !Number.isInteger(v) || v < 0) {
        throw new LedgerError("validation", `line ${i}: ${label} must be a non-negative integer`);
      }
    }
    // Exactly one side nonzero per line (mirrors the journal_lines CHECK).
    if (!((debit > 0 && credit === 0) || (credit > 0 && debit === 0))) {
      throw new LedgerError("validation", `line ${i}: exactly one of debit/credit must be positive`);
    }
    resolved.push({ account_id: account.id, account_code: account.code, debit_cents: debit, credit_cents: credit });
  }
  return resolved;
}

function nextEntryNo(db: Database): string {
  const row = db
    .query(
      `INSERT INTO sequences (name, next_val) VALUES ('journal_entry', 1)
       ON CONFLICT (name) DO UPDATE SET next_val = next_val + 1
       RETURNING next_val`,
    )
    .get() as { next_val: number };
  return `JE-${String(row.next_val).padStart(6, "0")}`;
}

/**
 * Post a balanced journal entry. Throws LedgerError (codes: validation,
 * unbalanced, period_closed, no_open_period). Returns the new entry's identity.
 */
export function postJournal(db: Database, input: PostJournalInput): PostedJournal {
  const memo = typeof input.memo === "string" ? input.memo.trim() : "";
  if (!memo) throw new LedgerError("validation", "memo is required");
  if (memo.length > 1000) throw new LedgerError("validation", "memo is too long (max 1000 chars)");
  const postedOn = input.posted_on ?? todayDate();
  if (!isValidDate(postedOn)) {
    throw new LedgerError("validation", `posted_on must be YYYY-MM-DD, got '${input.posted_on}'`);
  }
  const lines = resolveLines(db, input.lines);
  const totalDebit = lines.reduce((s, l) => s + l.debit_cents, 0);
  const totalCredit = lines.reduce((s, l) => s + l.credit_cents, 0);
  if (totalDebit !== totalCredit || totalDebit === 0) {
    throw new LedgerError(
      "unbalanced",
      `journal does not balance: debits ${totalDebit} != credits ${totalCredit}`,
    );
  }
  const period = resolvePeriod(db, input.period_id, postedOn);
  const postedAt = nowIso();

  return db.transaction((): PostedJournal => {
    const entryNo = nextEntryNo(db);
    const entry = db
      .query(
        `INSERT INTO journal_entries
           (entry_no, period_id, memo, source_type, source_id, posted_on, posted_at, posted_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        entryNo,
        period.id,
        memo,
        input.source_type ?? null,
        input.source_id ?? null,
        postedOn,
        postedAt,
        input.actor_id,
        postedAt,
      );
    const entryId = Number(entry.lastInsertRowid);
    const insertLine = db.query(
      "INSERT INTO journal_lines (entry_id, account_id, debit_cents, credit_cents) VALUES (?, ?, ?, ?)",
    );
    for (const l of lines) {
      insertLine.run(entryId, l.account_id, l.debit_cents, l.credit_cents);
    }
    appendAudit(db, {
      actor_id: input.actor_id,
      action: "journal.post",
      entity_type: "journal_entry",
      entity_id: entryNo,
      after: {
        entry_id: entryId,
        period_id: period.id,
        memo,
        posted_on: postedOn,
        total_cents: totalDebit,
        lines: lines.map((l) => ({
          account: l.account_code,
          debit_cents: l.debit_cents,
          credit_cents: l.credit_cents,
        })),
      },
    });
    return { id: entryId, entry_no: entryNo, period_id: period.id, posted_on: postedOn };
  })();
}

/**
 * Reverse a posted entry: posts a NEW entry with swapped debits/credits.
 * The original is never touched (immutable triggers would reject it anyway).
 */
export function reverseJournal(
  db: Database,
  entryId: number,
  opts: {
    actor_id: number | null;
    memo?: string;
    posted_on?: string;
    period_id?: number;
  },
): PostedJournal {
  const original = db
    .query("SELECT id, entry_no, memo, period_id FROM journal_entries WHERE id = ?")
    .get(entryId) as { id: number; entry_no: string; memo: string; period_id: number } | undefined;
  if (!original) throw new LedgerError("validation", `journal entry ${entryId} not found`);
  const existing = db
    .query("SELECT entry_no FROM journal_entries WHERE reversed_by = ?")
    .get(entryId) as { entry_no: string } | undefined;
  if (existing) {
    throw new LedgerError("already_reversed", `entry ${original.entry_no} was already reversed by ${existing.entry_no}`);
  }
  const lines = db
    .query("SELECT account_id, debit_cents, credit_cents FROM journal_lines WHERE entry_id = ?")
    .all(entryId) as { account_id: number; debit_cents: number; credit_cents: number }[];
  if (lines.length === 0) throw new LedgerError("validation", `entry ${original.entry_no} has no lines`);

  const swapped: JournalLineInput[] = lines.map((l) => ({
    account_id: l.account_id,
    debit_cents: l.credit_cents,
    credit_cents: l.debit_cents,
  }));

  // Post the reversal in its own transaction, then link it to the original.
  // (The original row is immutable — the link lives on the NEW entry's
  // reversed_by column, which is settable at INSERT time.)
  const postedOn = opts.posted_on ?? todayDate();
  if (!isValidDate(postedOn)) {
    throw new LedgerError("validation", `posted_on must be YYYY-MM-DD, got '${opts.posted_on}'`);
  }
  const resolvedLines = resolveLines(db, swapped);
  const totalDebit = resolvedLines.reduce((s, l) => s + l.debit_cents, 0);
  const totalCredit = resolvedLines.reduce((s, l) => s + l.credit_cents, 0);
  if (totalDebit !== totalCredit || totalDebit === 0) {
    // Cannot happen for a well-formed original, but refuse silently-corrupt reversals.
    throw new LedgerError("unbalanced", `reversal does not balance for ${original.entry_no}`);
  }
  const period = resolvePeriod(db, opts.period_id, postedOn);
  const memo =
    typeof opts.memo === "string" && opts.memo.trim()
      ? opts.memo.trim()
      : `Reversal of ${original.entry_no}`;
  const postedAt = nowIso();

  return db.transaction((): PostedJournal => {
    const entryNo = nextEntryNo(db);
    const entry = db
      .query(
        `INSERT INTO journal_entries
           (entry_no, period_id, memo, source_type, source_id, posted_on, posted_at, posted_by, reversed_by, created_at)
         VALUES (?, ?, ?, 'manual', ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        entryNo,
        period.id,
        memo,
        `reverses:${original.id}`,
        postedOn,
        postedAt,
        opts.actor_id,
        original.id,
        postedAt,
      );
    const newId = Number(entry.lastInsertRowid);
    const insertLine = db.query(
      "INSERT INTO journal_lines (entry_id, account_id, debit_cents, credit_cents) VALUES (?, ?, ?, ?)",
    );
    for (const l of resolvedLines) {
      insertLine.run(newId, l.account_id, l.debit_cents, l.credit_cents);
    }
    appendAudit(db, {
      actor_id: opts.actor_id,
      action: "journal.reverse",
      entity_type: "journal_entry",
      entity_id: entryNo,
      after: {
        reverses_entry_id: original.id,
        reverses_entry_no: original.entry_no,
        total_cents: totalDebit,
      },
    });
    return { id: newId, entry_no: entryNo, period_id: period.id, posted_on: postedOn };
  })();
}

// --- accounts -----------------------------------------------------------------

export interface AccountRow {
  id: number;
  code: string;
  name: string;
  type: string;
  parent_id: number | null;
  created_at: string;
  updated_at: string;
  deleted_at: string | null;
}

export function createAccount(
  db: Database,
  input: { code: string; name: string; type: string; parent_id?: number | null },
): AccountRow {
  const code = (input.code ?? "").trim();
  const name = (input.name ?? "").trim();
  if (!code) throw new LedgerError("validation", "account code is required");
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/.test(code)) {
    throw new LedgerError("validation", "account code must be 1-32 chars: letters, digits, . _ -");
  }
  if (!name) throw new LedgerError("validation", "account name is required");
  if (!(ACCOUNT_TYPES as readonly string[]).includes(input.type)) {
    throw new LedgerError("validation", `account type must be one of ${ACCOUNT_TYPES.join(", ")}`);
  }
  let parentId: number | null = input.parent_id ?? null;
  if (parentId !== null) {
    const parent = db
      .query("SELECT id, type FROM accounts WHERE id = ? AND deleted_at IS NULL")
      .get(parentId) as { id: number; type: string } | undefined;
    if (!parent) throw new LedgerError("validation", `parent account ${parentId} not found`);
    if (parent.type !== input.type) {
      throw new LedgerError("validation", "parent account must have the same type");
    }
  }
  const now = nowIso();
  try {
    const info = db
      .query(
        "INSERT INTO accounts (code, name, type, parent_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run(code, name, input.type, parentId, now, now);
    return getAccount(db, Number(info.lastInsertRowid))!;
  } catch (e) {
    if (e instanceof Error && /UNIQUE constraint failed: accounts.code/.test(e.message)) {
      throw new LedgerError("validation", `account code '${code}' already exists`);
    }
    throw e;
  }
}

export function getAccount(db: Database, id: number): AccountRow | null {
  const row = db.query("SELECT * FROM accounts WHERE id = ?").get(id) as AccountRow | undefined;
  return row ?? null;
}

/** Rename only — type/code changes are blocked once lines exist (would rewrite history). */
export function renameAccount(db: Database, id: number, name: string): AccountRow {
  const account = getAccount(db, id);
  if (!account || account.deleted_at !== null) {
    throw new LedgerError("validation", `account ${id} not found`);
  }
  const trimmed = (name ?? "").trim();
  if (!trimmed) throw new LedgerError("validation", "account name is required");
  db.query("UPDATE accounts SET name = ?, updated_at = ? WHERE id = ?").run(
    trimmed,
    nowIso(),
    id,
  );
  return getAccount(db, id)!;
}

/** Soft-delete. Blocked while any journal line references the account. */
export function deleteAccount(db: Database, id: number): void {
  const account = getAccount(db, id);
  if (!account || account.deleted_at !== null) {
    throw new LedgerError("validation", `account ${id} not found`);
  }
  const used = db
    .query("SELECT 1 FROM journal_lines WHERE account_id = ? LIMIT 1")
    .get(id);
  if (used) {
    throw new LedgerError("in_use", `account '${account.code}' has posted journal lines and cannot be deleted`);
  }
  const child = db
    .query("SELECT 1 FROM accounts WHERE parent_id = ? AND deleted_at IS NULL LIMIT 1")
    .get(id);
  if (child) {
    throw new LedgerError("in_use", `account '${account.code}' has child accounts and cannot be deleted`);
  }
  db.query("UPDATE accounts SET deleted_at = ?, updated_at = ? WHERE id = ?").run(
    nowIso(),
    nowIso(),
    id,
  );
}

export function listAccounts(db: Database, opts: { include_deleted?: boolean; type?: string } = {}): AccountRow[] {
  const where: string[] = [];
  const params: (string)[] = [];
  if (!opts.include_deleted) where.push("deleted_at IS NULL");
  if (opts.type) {
    if (!(ACCOUNT_TYPES as readonly string[]).includes(opts.type)) {
      throw new LedgerError("validation", `account type must be one of ${ACCOUNT_TYPES.join(", ")}`);
    }
    where.push("type = ?");
    params.push(opts.type);
  }
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
  return db.query(`SELECT * FROM accounts ${clause} ORDER BY code ASC`).all(...params) as AccountRow[];
}

// --- fiscal periods -------------------------------------------------------------

export function createPeriod(
  db: Database,
  input: { name: string; starts_on: string; ends_on: string },
): PeriodRow & { created_at: string } {
  const name = (input.name ?? "").trim();
  if (!name) throw new LedgerError("validation", "period name is required");
  if (!isValidDate(input.starts_on)) throw new LedgerError("validation", `starts_on must be YYYY-MM-DD`);
  if (!isValidDate(input.ends_on)) throw new LedgerError("validation", `ends_on must be YYYY-MM-DD`);
  if (input.starts_on > input.ends_on) {
    throw new LedgerError("validation", "starts_on must not be after ends_on");
  }
  const overlap = db
    .query("SELECT id FROM fiscal_periods WHERE starts_on <= ? AND ends_on >= ? LIMIT 1")
    .get(input.ends_on, input.starts_on);
  if (overlap) throw new LedgerError("overlap", "fiscal period overlaps an existing period");
  const now = nowIso();
  const info = db
    .query(
      "INSERT INTO fiscal_periods (name, starts_on, ends_on, created_at) VALUES (?, ?, ?, ?)",
    )
    .run(name, input.starts_on, input.ends_on, now);
  return db.query("SELECT * FROM fiscal_periods WHERE id = ?").get(
    Number(info.lastInsertRowid),
  ) as PeriodRow & { created_at: string };
}

export function listPeriods(db: Database): (PeriodRow & { created_at: string; created_by: number | null })[] {
  return db.query("SELECT * FROM fiscal_periods ORDER BY starts_on ASC").all() as (PeriodRow & {
    created_at: string;
    created_by: number | null;
  })[];
}

export function getPeriod(db: Database, id: number): (PeriodRow & { created_at: string }) | null {
  const row = db.query("SELECT * FROM fiscal_periods WHERE id = ?").get(id) as
    | (PeriodRow & { created_at: string })
    | undefined;
  return row ?? null;
}

/**
 * Close a period. Gate: the period's trial balance must balance (F-R1 gate).
 * Returns the closed row.
 */
export function closePeriod(
  db: Database,
  periodId: number,
  actorId: number | null,
): PeriodRow & { created_at: string } {
  const period = getPeriod(db, periodId);
  if (!period) throw new LedgerError("validation", `fiscal period ${periodId} not found`);
  if (period.closed_at !== null) throw new LedgerError("already_closed", `period '${period.name}' is already closed`);
  const tb = trialBalance(db, periodId);
  if (!tb.balanced) {
    throw new LedgerError(
      "unbalanced",
      `cannot close '${period.name}': trial balance does not balance (debits ${tb.total_debits} != credits ${tb.total_credits})`,
    );
  }
  const closedAt = nowIso();
  return db.transaction(() => {
    db.query("UPDATE fiscal_periods SET closed_at = ? WHERE id = ?").run(closedAt, periodId);
    appendAudit(db, {
      actor_id: actorId,
      action: "period.close",
      entity_type: "fiscal_period",
      entity_id: periodId,
      after: {
        name: period.name,
        closed_at: closedAt,
        total_debits: tb.total_debits,
        total_credits: tb.total_credits,
      },
    });
    return getPeriod(db, periodId)!;
  })();
}

/**
 * Reopen a closed period. Route-gated to ledger/admin; always audited —
 * reopening history is itself a compliance event (F-R3/F-R6).
 */
export function reopenPeriod(
  db: Database,
  periodId: number,
  actorId: number | null,
): PeriodRow & { created_at: string } {
  const period = getPeriod(db, periodId);
  if (!period) throw new LedgerError("validation", `fiscal period ${periodId} not found`);
  if (period.closed_at === null) throw new LedgerError("validation", `period '${period.name}' is not closed`);
  return db.transaction(() => {
    db.query("UPDATE fiscal_periods SET closed_at = NULL WHERE id = ?").run(periodId);
    appendAudit(db, {
      actor_id: actorId,
      action: "period.reopen",
      entity_type: "fiscal_period",
      entity_id: periodId,
      after: { name: period.name, was_closed_at: period.closed_at },
    });
    return getPeriod(db, periodId)!;
  })();
}

// --- trial balance + account ledger --------------------------------------------

export interface TrialBalanceRow {
  account_id: number;
  code: string;
  name: string;
  type: string;
  debits: number;
  credits: number;
}

export interface TrialBalance {
  period_id: number;
  rows: TrialBalanceRow[];
  total_debits: number;
  total_credits: number;
  balanced: boolean;
}

export function trialBalance(db: Database, periodId: number): TrialBalance {
  const period = getPeriod(db, periodId);
  if (!period) throw new LedgerError("validation", `fiscal period ${periodId} not found`);
  const rows = db
    .query(
      `SELECT a.id AS account_id, a.code, a.name, a.type,
              SUM(l.debit_cents) AS debits, SUM(l.credit_cents) AS credits
       FROM journal_lines l
       JOIN journal_entries e ON e.id = l.entry_id
       JOIN accounts a ON a.id = l.account_id
       WHERE e.period_id = ?
       GROUP BY a.id ORDER BY a.code ASC`,
    )
    .all(periodId) as TrialBalanceRow[];
  const total_debits = rows.reduce((s, r) => s + r.debits, 0);
  const total_credits = rows.reduce((s, r) => s + r.credits, 0);
  return { period_id: periodId, rows, total_debits, total_credits, balanced: total_debits === total_credits };
}

export interface AccountLedgerLine {
  entry_id: number;
  entry_no: string;
  posted_on: string;
  memo: string;
  debit_cents: number;
  credit_cents: number;
  /** Signed amount in the account's normal-balance direction. */
  balance_cents: number;
}

export interface AccountLedger {
  account: AccountRow;
  period_id: number | null;
  lines: AccountLedgerLine[];
  total_debits: number;
  total_credits: number;
  closing_balance_cents: number;
}

/** Account ledger with running balance. Filters: period and/or posted_on range. */
export function accountLedger(
  db: Database,
  accountId: number,
  opts: { period_id?: number; from?: string; to?: string } = {},
): AccountLedger {
  const account = getAccount(db, accountId);
  if (!account) throw new LedgerError("validation", `account ${accountId} not found`);
  if (opts.from && !isValidDate(opts.from)) throw new LedgerError("validation", "from must be YYYY-MM-DD");
  if (opts.to && !isValidDate(opts.to)) throw new LedgerError("validation", "to must be YYYY-MM-DD");
  if (opts.period_id !== undefined && !getPeriod(db, opts.period_id)) {
    throw new LedgerError("validation", `fiscal period ${opts.period_id} not found`);
  }
  const where: string[] = ["l.account_id = ?"];
  const params: (number | string)[] = [accountId];
  if (opts.period_id !== undefined) {
    where.push("e.period_id = ?");
    params.push(opts.period_id);
  }
  if (opts.from) {
    where.push("e.posted_on >= ?");
    params.push(opts.from);
  }
  if (opts.to) {
    where.push("e.posted_on <= ?");
    params.push(opts.to);
  }
  const rows = db
    .query(
      `SELECT e.id AS entry_id, e.entry_no, e.posted_on, e.memo,
              l.debit_cents, l.credit_cents
       FROM journal_lines l
       JOIN journal_entries e ON e.id = l.entry_id
       WHERE ${where.join(" AND ")}
       ORDER BY e.posted_on ASC, e.id ASC, l.id ASC`,
    )
    .all(...params) as {
    entry_id: number;
    entry_no: string;
    posted_on: string;
    memo: string;
    debit_cents: number;
    credit_cents: number;
  }[];

  const debitNormal = DEBIT_NORMAL.has(account.type);
  let running = 0;
  const lines: AccountLedgerLine[] = rows.map((r) => {
    running += debitNormal ? r.debit_cents - r.credit_cents : r.credit_cents - r.debit_cents;
    return {
      entry_id: r.entry_id,
      entry_no: r.entry_no,
      posted_on: r.posted_on,
      memo: r.memo,
      debit_cents: r.debit_cents,
      credit_cents: r.credit_cents,
      balance_cents: running,
    };
  });
  return {
    account,
    period_id: opts.period_id ?? null,
    lines,
    total_debits: rows.reduce((s, r) => s + r.debit_cents, 0),
    total_credits: rows.reduce((s, r) => s + r.credit_cents, 0),
    closing_balance_cents: running,
  };
}

// --- journal reads ---------------------------------------------------------------

export interface JournalEntryView {
  id: number;
  entry_no: string;
  period_id: number;
  memo: string;
  source_type: string | null;
  source_id: string | null;
  posted_on: string;
  posted_at: string;
  posted_by: number | null;
  reversed_by: number | null;
  reversed_entry_no: string | null;
  lines: { id: number; account_id: number; account_code: string; account_name: string; debit_cents: number; credit_cents: number }[];
}

export function getJournalEntry(db: Database, id: number): JournalEntryView | null {
  const e = db.query("SELECT * FROM journal_entries WHERE id = ?").get(id) as Record<string, unknown> | undefined;
  if (!e) return null;
  const lines = db
    .query(
      `SELECT l.id, l.account_id, a.code AS account_code, a.name AS account_name,
              l.debit_cents, l.credit_cents
       FROM journal_lines l JOIN accounts a ON a.id = l.account_id
       WHERE l.entry_id = ? ORDER BY l.id ASC`,
    )
    .all(id) as JournalEntryView["lines"];
  const rev = e.reversed_by
    ? (db.query("SELECT entry_no FROM journal_entries WHERE id = ?").get(e.reversed_by as number) as
      | { entry_no: string }
      | undefined)
    : undefined;
  return {
    id: e.id as number,
    entry_no: e.entry_no as string,
    period_id: e.period_id as number,
    memo: e.memo as string,
    source_type: e.source_type as string | null,
    source_id: e.source_id as string | null,
    posted_on: e.posted_on as string,
    posted_at: e.posted_at as string,
    posted_by: e.posted_by as number | null,
    reversed_by: e.reversed_by as number | null,
    reversed_entry_no: rev?.entry_no ?? null,
    lines,
  };
}

export function listJournalEntries(
  db: Database,
  opts: { period_id?: number; page?: number; per_page?: number } = {},
): { rows: JournalEntryView[]; total: number } {
  const where: string[] = [];
  const params: (number)[] = [];
  if (opts.period_id !== undefined) {
    where.push("e.period_id = ?");
    params.push(opts.period_id);
  }
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const total = (
    db.query(`SELECT COUNT(*) AS n FROM journal_entries e ${clause}`).get(...params) as { n: number }
  ).n;
  const perPage = Math.min(Math.max(opts.per_page ?? 50, 1), 500);
  const page = Math.max(opts.page ?? 1, 1);
  const ids = db
    .query(`SELECT e.id FROM journal_entries e ${clause} ORDER BY e.id DESC LIMIT ? OFFSET ?`)
    .all(...params, perPage, (page - 1) * perPage) as { id: number }[];
  const rows = ids
    .map((r) => getJournalEntry(db, r.id))
    .filter((r): r is JournalEntryView => r !== null);
  return { rows, total };
}

// --- idempotency ----------------------------------------------------------------

/**
 * Run produce() once per key; duplicate keys replay the original response.
 * The record is inserted inside the producer's own transaction — callers that
 * need the response bytes stored must include them in produce's return.
 */
export function withIdempotency<T>(
  db: Database,
  key: string,
  actorId: number | null,
  method: string,
  path: string,
  produce: () => { status: number; body: unknown },
): { replayed: boolean; status: number; body: unknown } {
  const existing = db
    .query("SELECT response_code, response_json FROM idempotency_records WHERE key = ?")
    .get(key) as { response_code: number; response_json: string } | undefined;
  if (existing) {
    return { replayed: true, status: existing.response_code, body: JSON.parse(existing.response_json) };
  }
  return db.transaction(() => {
    const check = db
      .query("SELECT response_code, response_json FROM idempotency_records WHERE key = ?")
      .get(key) as { response_code: number; response_json: string } | undefined;
    if (check) {
      return { replayed: true, status: check.response_code, body: JSON.parse(check.response_json) };
    }
    const result = produce();
    db.query(
      `INSERT INTO idempotency_records (key, actor_id, method, path, response_code, response_json, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).run(key, actorId, method, path, result.status, JSON.stringify(result.body), nowIso());
    return { replayed: false, status: result.status, body: result.body };
  })();
}
