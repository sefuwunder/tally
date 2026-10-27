// Tally ERP — retention.ts
// Retention engine: per-type retention schedules (F-R7, H-A5), retain-until
// computation, retention enforcement on the delete path (405 `retained`),
// and the per-type coverage report (F-R2, F-R4).
//
// v1 honesty note: "readily accessible" (17a-4's first-2-years rule) is the
// live DB itself — there is no archive tier. Everything retained lives in the
// primary store, so it is trivially retrievable.

import type { Database } from "bun:sqlite";

export class RetentionError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "RetentionError";
    this.code = code;
  }
}

/**
 * Retention years for a document type: per-type override first, then the
 * generic `document` policy, then a conservative 6-year default (never below
 * the F-R7 3-year floor).
 */
export function docRetentionYears(db: Database, doc_type: string): number {
  const row = db
    .query("SELECT years FROM doc_retention_years WHERE doc_type = ?")
    .get(doc_type) as { years: number } | null;
  if (row) return row.years;
  const policy = db
    .query("SELECT years FROM retention_policies WHERE entity_type = 'document'")
    .get() as { years: number } | null;
  return policy?.years ?? 6;
}

/** Add whole years to an ISO date (YYYY-MM-DD), clamping month overflow. */
export function addYearsIso(dateIso: string, years: number): string {
  const [y, m, d] = dateIso.split("-").map(Number);
  const dt = new Date(Date.UTC(y + years, m - 1, d));
  if (dt.getUTCMonth() !== m - 1) dt.setUTCDate(0); // e.g. Feb 29 -> Feb 28
  return dt.toISOString().slice(0, 10);
}

export function todayIsoDate(): string {
  return new Date().toISOString().slice(0, 10);
}

/** True while the record's retention period has not yet expired. */
export function isRetainedDate(retainUntilIsoDate: string): boolean {
  return retainUntilIsoDate > todayIsoDate();
}

/**
 * Throw RetentionError('retained') when a record dated `recordDate` of
 * `entity_type` is still inside its retention period. Delete paths call this
 * before touching the row; the WORM triggers are the backstop.
 */
export function assertRetentionExpired(
  db: Database,
  entity_type: string,
  recordDateIso: string,
): void {
  const policy = db
    .query("SELECT years FROM retention_policies WHERE entity_type = ?")
    .get(entity_type) as { years: number } | null;
  const years = policy?.years ?? 6;
  const retainUntil = addYearsIso(recordDateIso.slice(0, 10), years);
  if (isRetainedDate(retainUntil)) {
    throw new RetentionError(
      "retained",
      `${entity_type} record dated ${recordDateIso.slice(0, 10)} is retained until ${retainUntil} (${years}y policy)`,
    );
  }
}

export interface PolicyCoverage {
  entity_type: string;
  years: number;
  covered_table: string | null;
  record_count: number;
  retained_count: number;
  status: "covered" | "pending_module";
}

export interface DocTypeCoverage {
  doc_type: string;
  years: number;
  document_count: number;
  retained_count: number;
}

export interface RetentionReport {
  generated_at: string;
  policies: PolicyCoverage[];
  document_types: DocTypeCoverage[];
  notes: string;
}

// Entity types whose records already live in a queryable table.
const COVERED_TABLES: Record<string, string> = {
  journal: "journal_entries",
  document: "documents",
  audit: "audit_log",
  comms: "activities",
  crm: "companies",
  hr: "employees",
  report: "report_runs",
};

function countWhere(db: Database, table: string, where = "", ...params: string[]): number {
  return (
    db.query(`SELECT COUNT(*) AS n FROM ${table}${where ? ` WHERE ${where}` : ""}`).get(
      ...params,
    ) as { n: number }
  ).n;
}

/**
 * Per-type retention coverage (F-R4): every policy row lists its period, the
 * table it covers (or "pending_module" for phases not yet built), and how
 * many records are currently inside their retention window.
 */
export function retentionReport(db: Database): RetentionReport {
  const policies = (
    db
      .query("SELECT entity_type, years FROM retention_policies ORDER BY entity_type")
      .all() as { entity_type: string; years: number }[]
  ).map((p): PolicyCoverage => {
    const table = COVERED_TABLES[p.entity_type] ?? null;
    if (!table) {
      return {
        entity_type: p.entity_type,
        years: p.years,
        covered_table: null,
        record_count: 0,
        retained_count: 0,
        status: "pending_module",
      };
    }
    const record_count = countWhere(db, table);
    // journal/audit rows are immutable and retained indefinitely in v1;
    // documents carry their own retain_until.
    const retained_count =
      table === "documents"
        ? countWhere(db, table, "retain_until > date('now')")
        : record_count;
    return {
      entity_type: p.entity_type,
      years: p.years,
      covered_table: table,
      record_count,
      retained_count,
      status: "covered",
    };
  });

  const document_types = (
    db.query("SELECT doc_type, years FROM doc_retention_years ORDER BY doc_type").all() as {
      doc_type: string;
      years: number;
    }[]
  ).map(
    (t): DocTypeCoverage => ({
      doc_type: t.doc_type,
      years: t.years,
      document_count: countWhere(db, "documents", "doc_type = ?", t.doc_type),
      retained_count: countWhere(
        db,
        "documents",
        "doc_type = ? AND retain_until > date('now')",
        t.doc_type,
      ),
    }),
  );

  return {
    generated_at: new Date().toISOString(),
    policies,
    document_types,
    notes:
      "v1: retained records live in the primary DB (readily accessible; no archive tier). " +
      "pending_module rows are policies for roadmap phases not yet built.",
  };
}
