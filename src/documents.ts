// Tally ERP — documents.ts
// Content-addressed WORM document store (F-R2, F-R3 WORM path, F-R4).
//
// - Content address = sha256 of PLAINTEXT bytes; identical bytes dedupe to
//   one stored row (UNIQUE on content_sha256).
// - Content is AES-256-GCM ciphertext at rest (iv(12) || ct); the address is
//   over plaintext so dedupe and `tally verify` work on the real bytes.
// - retain_until is set at upload from the retention engine; the DB triggers
//   in 003_worm.sql reject UPDATE always and DELETE while retained.
// - Async crypto (encrypt/decrypt) runs BEFORE the caller's transaction;
//   inserts stay synchronous inside it (see server.ts upload route).

import type { Database } from "bun:sqlite";
import { randomUUID } from "node:crypto";
import { encryptBytes, decryptBytes, sha256HexSync } from "./crypto";
import { docRetentionYears, addYearsIso, todayIsoDate, RetentionError } from "./retention";
import { nowIso } from "./db";

export const MAX_DOCUMENT_BYTES = 64 * 1024 * 1024; // 64 MiB v1 cap

export class DocumentError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "DocumentError";
    this.code = code;
  }
}

export interface DocumentMeta {
  id: number;
  uuid: string;
  title: string;
  doc_type: string;
  mime_type: string;
  size_bytes: number;
  content_sha256: string;
  retain_until: string;
  uploaded_by: number | null;
  created_at: string;
}

export interface PreparedDocument {
  meta: Omit<DocumentMeta, "id" | "created_at"> & { created_at?: string };
  contentBlob: Uint8Array;
  deduped: boolean;
  existingId: number | null;
}

export interface StoreInput {
  title: string;
  doc_type: string;
  mime_type?: string;
  content: Uint8Array;
  actor_id: number | null;
}

function rowToMeta(r: Record<string, unknown>): DocumentMeta {
  return {
    id: r.id as number,
    uuid: r.uuid as string,
    title: r.title as string,
    doc_type: r.doc_type as string,
    mime_type: r.mime_type as string,
    size_bytes: r.size_bytes as number,
    content_sha256: r.content_sha256 as string,
    retain_until: r.retain_until as string,
    uploaded_by: r.uploaded_by as number | null,
    created_at: r.created_at as string,
  };
}

function validateInput(input: StoreInput): void {
  const title = (input.title ?? "").trim();
  if (!title || title.length > 255) {
    throw new DocumentError("validation", "title is required (1-255 chars)");
  }
  const doc_type = (input.doc_type ?? "").trim();
  if (!doc_type || doc_type.length > 64) {
    throw new DocumentError("validation", "doc_type is required (1-64 chars)");
  }
  const mime = (input.mime_type ?? "application/octet-stream").trim() || "application/octet-stream";
  if (mime.length > 127 || !mime.includes("/")) {
    throw new DocumentError("validation", "mime_type must look like type/subtype");
  }
  if (!(input.content instanceof Uint8Array) || input.content.length === 0) {
    throw new DocumentError("validation", "content must be non-empty bytes");
  }
  if (input.content.length > MAX_DOCUMENT_BYTES) {
    throw new DocumentError(
      "validation",
      `content exceeds the ${MAX_DOCUMENT_BYTES}-byte v1 cap`,
    );
  }
}

/**
 * Validate + hash + dedupe-check + encrypt. Async work happens here, OUTSIDE
 * any SQLite transaction; the caller inserts via insertDocument() inside its
 * own transaction with the audit row.
 */
export async function prepareDocument(db: Database, input: StoreInput): Promise<PreparedDocument> {
  validateInput(input);
  const title = input.title.trim();
  const doc_type = input.doc_type.trim();
  const mime_type = (input.mime_type ?? "application/octet-stream").trim() || "application/octet-stream";
  const content_sha256 = sha256HexSync(input.content);

  const existing = db
    .query("SELECT id FROM documents WHERE content_sha256 = ?")
    .get(content_sha256) as { id: number } | null;
  if (existing) {
    return {
      meta: {
        uuid: "",
        title,
        doc_type,
        mime_type,
        size_bytes: input.content.length,
        content_sha256,
        retain_until: "",
        uploaded_by: input.actor_id,
      },
      contentBlob: new Uint8Array(0),
      deduped: true,
      existingId: existing.id,
    };
  }

  const years = docRetentionYears(db, doc_type);
  const contentBlob = await encryptBytes(input.content);
  return {
    meta: {
      uuid: randomUUID(),
      title,
      doc_type,
      mime_type,
      size_bytes: input.content.length,
      content_sha256,
      retain_until: addYearsIso(todayIsoDate(), years),
      uploaded_by: input.actor_id,
    },
    contentBlob,
    deduped: false,
    existingId: null,
  };
}

/**
 * Insert a prepared (non-deduped) document. Synchronous — call inside the
 * caller's transaction next to its audit row. On a lost dedupe race the
 * UNIQUE constraint fires and we fall back to the winner.
 */
export function insertDocument(db: Database, prepared: PreparedDocument): DocumentMeta {
  if (prepared.deduped) {
    const row = db.query("SELECT * FROM documents WHERE id = ?").get(prepared.existingId) as Record<
      string,
      unknown
    > | null;
    if (!row) throw new DocumentError("not_found", "deduplicated document vanished");
    return rowToMeta(row);
  }
  const m = prepared.meta;
  const created_at = nowIso();
  try {
    const info = db
      .query(
        `INSERT INTO documents
           (uuid, title, doc_type, mime_type, size_bytes, content_sha256,
            content, retain_until, uploaded_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        m.uuid,
        m.title,
        m.doc_type,
        m.mime_type,
        m.size_bytes,
        m.content_sha256,
        prepared.contentBlob,
        m.retain_until,
        m.uploaded_by,
        created_at,
      );
    return { ...m, id: Number(info.lastInsertRowid), created_at };
  } catch (e) {
    // Lost a dedupe race: return the row that won.
    if (e instanceof Error && /UNIQUE constraint failed: documents\.content_sha256/.test(e.message)) {
      const row = db
        .query("SELECT * FROM documents WHERE content_sha256 = ?")
        .get(m.content_sha256) as Record<string, unknown> | null;
      if (row) return rowToMeta(row);
    }
    throw e;
  }
}

export function getDocument(db: Database, id: number): DocumentMeta | null {
  const row = db.query("SELECT * FROM documents WHERE id = ?").get(id) as Record<
    string,
    unknown
  > | null;
  return row ? rowToMeta(row) : null;
}

export function listDocuments(
  db: Database,
  opts: { doc_type?: string; page?: number; per_page?: number } = {},
): { rows: DocumentMeta[]; total: number } {
  const where: string[] = [];
  const params: (string | number)[] = [];
  if (opts.doc_type) {
    where.push("doc_type = ?");
    params.push(opts.doc_type);
  }
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const per_page = Math.min(Math.max(opts.per_page ?? 50, 1), 500);
  const page = Math.max(opts.page ?? 1, 1);
  const total = (
    db.query(`SELECT COUNT(*) AS n FROM documents ${clause}`).get(...params) as { n: number }
  ).n;
  const rows = db
    .query(`SELECT * FROM documents ${clause} ORDER BY id ASC LIMIT ? OFFSET ?`)
    .all(...params, per_page, (page - 1) * per_page) as Record<string, unknown>[];
  return { rows: rows.map(rowToMeta), total };
}

/** Decrypt and return the plaintext bytes. Throws DocumentError('corrupt') on auth failure. */
export async function getDocumentContent(
  db: Database,
  id: number,
): Promise<{ meta: DocumentMeta; bytes: Uint8Array }> {
  const meta = getDocument(db, id);
  if (!meta) throw new DocumentError("not_found", "document not found");
  const row = db.query("SELECT content FROM documents WHERE id = ?").get(id) as {
    content: Uint8Array;
  };
  let bytes: Uint8Array;
  try {
    bytes = await decryptBytes(new Uint8Array(row.content));
  } catch {
    throw new DocumentError("corrupt", "document content failed integrity check");
  }
  if (sha256HexSync(bytes) !== meta.content_sha256) {
    throw new DocumentError("corrupt", "document content hash mismatch");
  }
  return { meta, bytes };
}

/**
 * Delete a document. Throws RetentionError('retained') while retain_until is
 * in the future (the WORM trigger is the backstop). Synchronous — call inside
 * the caller's transaction next to its audit row.
 */
export function deleteDocument(db: Database, id: number): DocumentMeta {
  const meta = getDocument(db, id);
  if (!meta) throw new DocumentError("not_found", "document not found");
  if (meta.retain_until > todayIsoDate()) {
    throw new RetentionError(
      "retained",
      `document ${id} is retained until ${meta.retain_until} (WORM)`,
    );
  }
  db.query("DELETE FROM documents WHERE id = ?").run(id);
  return meta;
}
