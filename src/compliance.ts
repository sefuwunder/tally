// Tally ERP — compliance.ts
// 17a-4(f)(2)(ii)-(iv) surfaces (F-R4): automatic verification of the storage
// processes (`tally verify`: audit chain + document hashes + retention
// coverage) and ready download/transfer of records + audit trail in
// human-readable AND reasonably usable electronic format
// (GET /api/v1/compliance/export as JSON or CSV).

import type { Database } from "bun:sqlite";
import { verifyChain, type ChainVerification } from "./audit";
import { decryptBytes, sha256HexSync } from "./crypto";
import { retentionReport, type RetentionReport } from "./retention";
import { getDocument, type DocumentMeta } from "./documents";
import { getJournalEntry } from "./ledger";

export class ComplianceError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "ComplianceError";
    this.code = code;
  }
}

// --- verification -----------------------------------------------------------

export interface DocumentCheck {
  checked: number;
  corrupt: number;
  corrupt_ids: number[];
}

/**
 * Re-verify every stored document: GCM-decrypt (authentication catches any
 * flipped byte) then recompute sha256(plaintext) against the content address.
 * Any failure lands in corrupt_ids — this is what flags the scratched-copy
 * tamper in the acceptance test.
 */
export async function verifyDocuments(db: Database): Promise<DocumentCheck> {
  const rows = db
    .query("SELECT id, content, content_sha256 FROM documents ORDER BY id ASC")
    .all() as { id: number; content: Uint8Array; content_sha256: string }[];
  const corrupt_ids: number[] = [];
  for (const r of rows) {
    try {
      const pt = await decryptBytes(new Uint8Array(r.content));
      if (sha256HexSync(pt) !== r.content_sha256) corrupt_ids.push(r.id);
    } catch {
      corrupt_ids.push(r.id);
    }
  }
  return { checked: rows.length, corrupt: corrupt_ids.length, corrupt_ids };
}

export interface VerifyReport {
  ok: boolean;
  generated_at: string;
  audit_chain: ChainVerification;
  documents: DocumentCheck;
  retention: RetentionReport;
}

/** Full storage-process verification: chain + document hashes + coverage. */
export async function verifyAll(db: Database): Promise<VerifyReport> {
  const audit_chain = verifyChain(db);
  const documents = await verifyDocuments(db);
  const retention = retentionReport(db);
  return {
    ok: audit_chain.ok && documents.corrupt === 0,
    generated_at: new Date().toISOString(),
    audit_chain,
    documents,
    retention,
  };
}

// --- export -----------------------------------------------------------------

export type ExportFormat = "json" | "csv";
export type ExportEntity = "audit_log" | "documents" | "journal_entries";

function csvEscape(v: unknown): string {
  const s = v === null || v === undefined ? "" : String(v);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function toCsv(columns: string[], rows: Record<string, unknown>[]): string {
  const lines = [columns.map(csvEscape).join(",")];
  for (const r of rows) lines.push(columns.map((c) => csvEscape(r[c])).join(","));
  return lines.join("\r\n") + "\r\n";
}

interface AuditRow {
  seq: number;
  ts: string;
  actor_id: number | null;
  action: string;
  entity_type: string;
  entity_id: string | null;
  before_json: string | null;
  after_json: string | null;
  prev_hash: string;
  hash: string;
}

function historyFor(db: Database, entity_type: string, entity_id: string | number): AuditRow[] {
  return db
    .query(
      `SELECT seq, ts, actor_id, action, entity_type, entity_id,
              before_json, after_json, prev_hash, hash
       FROM audit_log WHERE entity_type = ? AND entity_id = ?
       ORDER BY seq ASC`,
    )
    .all(entity_type, String(entity_id)) as AuditRow[];
}

const AUDIT_COLUMNS = [
  "seq",
  "ts",
  "actor_id",
  "action",
  "entity_type",
  "entity_id",
  "before_json",
  "after_json",
  "prev_hash",
  "hash",
];

const DOCUMENT_COLUMNS = [
  "id",
  "uuid",
  "title",
  "doc_type",
  "mime_type",
  "size_bytes",
  "content_sha256",
  "retain_until",
  "uploaded_by",
  "created_at",
];

/**
 * Export records + their full audit history (F-R4 "recreate the original
 * record" / "ready download"). entity_id narrows to one record and always
 * bundles its history; without it, the whole entity set exports.
 */
export function exportRecords(
  db: Database,
  entity: ExportEntity,
  entity_id: number | null,
  format: ExportFormat,
): { contentType: string; filename: string; body: string | Uint8Array } {
  let payload: { record?: unknown; records?: unknown[]; history: AuditRow[] };
  let columns: string[];
  let flat: Record<string, unknown>[];

  if (entity === "audit_log") {
    if (entity_id !== null) {
      throw new ComplianceError("validation", "entity_id is not supported for audit_log");
    }
    const rows = db
      .query(
        `SELECT seq, ts, actor_id, action, entity_type, entity_id,
                before_json, after_json, prev_hash, hash
         FROM audit_log ORDER BY seq ASC`,
      )
      .all() as AuditRow[];
    payload = { records: rows, history: [] };
    columns = AUDIT_COLUMNS;
    flat = rows as unknown as Record<string, unknown>[];
  } else if (entity === "documents") {
    if (entity_id !== null) {
      const meta: DocumentMeta | null = getDocument(db, entity_id);
      if (!meta) throw new ComplianceError("not_found", "document not found");
      payload = { record: meta, history: historyFor(db, "document", entity_id) };
      flat = [meta as unknown as Record<string, unknown>];
    } else {
      const rows = db.query("SELECT * FROM documents ORDER BY id ASC").all() as Record<
        string,
        unknown
      >[];
      const metas = rows.map((r) => {
        const { content: _c, ...meta } = r;
        void _c;
        return meta;
      });
      payload = { records: metas, history: [] };
      flat = metas;
    }
    columns = DOCUMENT_COLUMNS;
  } else {
    // journal_entries
    if (entity_id !== null) {
      const entry = getJournalEntry(db, entity_id);
      if (!entry) throw new ComplianceError("not_found", "journal entry not found");
      // Ledger audit rows key journal entries by entry_no, not numeric id.
      payload = { record: entry, history: historyFor(db, "journal_entry", entry.entry_no) };
      if (format === "csv") {
        // One row per line, entry fields repeated — the usable tabular form.
        const e = entry as unknown as Record<string, unknown>;
        flat = (entry.lines as unknown as Record<string, unknown>[]).map((l) => ({
          entry_id: e.id,
          entry_no: e.entry_no,
          posted_on: e.posted_on,
          memo: e.memo,
          reversed_by: e.reversed_by,
          ...l,
        }));
        columns = [
          "entry_id",
          "entry_no",
          "posted_on",
          "memo",
          "reversed_by",
          "id",
          "account_id",
          "account_code",
          "account_name",
          "debit_cents",
          "credit_cents",
        ];
      } else {
        flat = [{ ...(entry as unknown as Record<string, unknown>) }];
      }
    } else {
      const rows = db
        .query("SELECT id, entry_no, period_id, memo, source_type, source_id, posted_on, posted_by, created_at FROM journal_entries ORDER BY id ASC")
        .all() as Record<string, unknown>[];
      payload = { records: rows, history: [] };
      flat = rows;
    }
    if (!(entity === "journal_entries" && entity_id !== null && format === "csv")) {
      columns = [
        "id",
        "entry_no",
        "period_id",
        "memo",
        "source_type",
        "source_id",
        "posted_on",
        "posted_by",
        "created_at",
      ];
    }
  }

  const filename = `tally-${entity}${entity_id !== null ? `-${entity_id}` : ""}.${format}`;
  if (format === "csv") {
    return { contentType: "text/csv; charset=utf-8", filename, body: toCsv(columns, flat) };
  }
  return {
    contentType: "application/json; charset=utf-8",
    filename,
    body: JSON.stringify({ data: payload, meta: { entity, entity_id, format } }),
  };
}
