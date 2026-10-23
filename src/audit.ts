// Tally ERP — audit.ts
// Hash-chained append-only audit log.
//
// hash = sha256(prev_hash || "|" || canonicalJson(payload))
// payload = { seq, ts, actor_id, action, entity_type, entity_id, before, after }
//
// Rules:
//  - appendAudit is fully synchronous: call it INSIDE the same transaction as
//    the mutation it records, so audit + data are atomic.
//  - Never pass raw passwords, bearer tokens, or encryption keys as
//    before/after — record the event, not the secret.
//  - The DB triggers in 001_core.sql reject UPDATE/DELETE on audit_log;
//    tampering with the file is detected by verifyChain (hash break at the
//    tampered seq).

import type { Database } from "bun:sqlite";
import { sha256HexSync } from "./crypto";

export const GENESIS_HASH = "GENESIS";

export interface AuditInput {
  actor_id: number | null;
  action: string;
  entity_type: string;
  entity_id?: string | number | null;
  before?: unknown;
  after?: unknown;
}

/** Deterministic JSON: object keys sorted recursively, so hashing is stable. */
export function canonicalJson(v: unknown): string {
  if (v === null || v === undefined) return "null";
  if (typeof v !== "object") return JSON.stringify(v) ?? "null";
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  const keys = Object.keys(v as Record<string, unknown>).sort();
  return `{${keys
    .map((k) => `${JSON.stringify(k)}:${canonicalJson((v as Record<string, unknown>)[k])}`)
    .join(",")}}`;
}

/** Append one audit row. MUST be called inside the caller's transaction. Returns seq. */
export function appendAudit(db: Database, input: AuditInput): number {
  const last = db
    .query("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1")
    .get() as { seq: number; hash: string } | null;
  const seq = (last?.seq ?? 0) + 1;
  const prev_hash = last?.hash ?? GENESIS_HASH;
  const ts = new Date().toISOString();
  const entity_id =
    input.entity_id === null || input.entity_id === undefined
      ? null
      : String(input.entity_id);
  const before = input.before === undefined ? null : input.before;
  const after = input.after === undefined ? null : input.after;
  const payload = canonicalJson({
    seq,
    ts,
    actor_id: input.actor_id,
    action: input.action,
    entity_type: input.entity_type,
    entity_id,
    before,
    after,
  });
  const hash = sha256HexSync(`${prev_hash}|${payload}`);
  db.query(
    `INSERT INTO audit_log
       (seq, ts, actor_id, action, entity_type, entity_id,
        before_json, after_json, prev_hash, hash)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    seq,
    ts,
    input.actor_id,
    input.action,
    input.entity_type,
    entity_id,
    before === null ? null : JSON.stringify(before),
    after === null ? null : JSON.stringify(after),
    prev_hash,
    hash,
  );
  return seq;
}

export interface ChainVerification {
  ok: boolean;
  break_at_seq: number | null;
  count: number;
}

/** Recompute the full hash chain. Any tamper breaks at the tampered seq. */
export function verifyChain(db: Database): ChainVerification {
  const rows = db
    .query(
      `SELECT seq, ts, actor_id, action, entity_type, entity_id,
              before_json, after_json, prev_hash, hash
       FROM audit_log ORDER BY seq ASC`,
    )
    .all() as {
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
  }[];

  let prev = GENESIS_HASH;
  for (const r of rows) {
    if (r.prev_hash !== prev) {
      return { ok: false, break_at_seq: r.seq, count: rows.length };
    }
    const payload = canonicalJson({
      seq: r.seq,
      ts: r.ts,
      actor_id: r.actor_id,
      action: r.action,
      entity_type: r.entity_type,
      entity_id: r.entity_id,
      before: r.before_json ? JSON.parse(r.before_json) : null,
      after: r.after_json ? JSON.parse(r.after_json) : null,
    });
    if (sha256HexSync(`${prev}|${payload}`) !== r.hash) {
      return { ok: false, break_at_seq: r.seq, count: rows.length };
    }
    prev = r.hash;
  }
  return { ok: true, break_at_seq: null, count: rows.length };
}
