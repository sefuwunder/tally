// Tally ERP — backup.ts
// Encrypted backup / restore / verify (Phase 10, F-R5).
//
// Format: magic "TALLYBK1" (8 bytes) + AES-256-GCM(iv(12) || ct) of the
// whole SQLite file, via the existing encryptBytes/decryptBytes +
// TALLY_DATA_KEY. The magic rejects garbage early; GCM authentication
// rejects any tampered byte. A backup is a VACUUM INTO snapshot taken
// after a WAL checkpoint, so the file is self-contained.
// Trial-balance comparison reuses ledger.trialBalance() on both the
// original and the restored DB — identical totals prove the restore.

import type { Database } from "bun:sqlite";
import { Database as SqliteDatabase } from "bun:sqlite";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { checkpoint, openDb } from "./db";
import { decryptBytes, encryptBytes } from "./crypto";
import { listPeriods, trialBalance, type TrialBalance } from "./ledger";
import { verifyAll, type VerifyReport } from "./compliance";

export const BACKUP_MAGIC = "TALLYBK1";

export class BackupError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "BackupError";
    this.code = code;
  }
}

function vacuumInto(db: Database, outPath: string): void {
  const escaped = outPath.replace(/'/g, "''");
  db.exec(`VACUUM INTO '${escaped}'`);
}

/**
 * Snapshot `db` (checkpoint + VACUUM INTO a temp file), encrypt the
 * snapshot, and write the backup file. The live DB is never copied
 * directly — WAL sidecars must not leak into a backup.
 */
export async function createBackup(db: Database, outPath: string): Promise<{ bytes: number }> {
  checkpoint(db);
  const dir = mkdtempSync(join(tmpdir(), "tally-backup-"));
  const snapPath = join(dir, "snapshot.db");
  try {
    vacuumInto(db, snapPath);
    const plain = readFileSync(snapPath);
    const enc = await encryptBytes(new Uint8Array(plain));
    const out = new Uint8Array(BACKUP_MAGIC.length + enc.length);
    out.set(new TextEncoder().encode(BACKUP_MAGIC), 0);
    out.set(enc, BACKUP_MAGIC.length);
    writeFileSync(outPath, out);
    return { bytes: out.length };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * Decrypt a backup file and write the DB to `targetPath`. Refuses to
 * overwrite a non-empty existing DB unless `force` is set; with force,
 * stale -wal/-shm sidecars of the target are removed first so a
 * restored file is never shadowed by an old WAL.
 */
export async function restoreBackup(
  backupPath: string,
  targetPath: string,
  opts: { force?: boolean } = {},
): Promise<{ bytes: number }> {
  if (!existsSync(backupPath)) {
    throw new BackupError("not_found", `backup file not found: ${backupPath}`);
  }
  if (existsSync(targetPath) && statSync(targetPath).size > 0 && !opts.force) {
    throw new BackupError(
      "refuse_overwrite",
      `target DB ${targetPath} already exists and is non-empty; pass --force to overwrite`,
    );
  }
  const raw = readFileSync(backupPath);
  const magic = new TextDecoder().decode(raw.subarray(0, BACKUP_MAGIC.length));
  if (magic !== BACKUP_MAGIC) {
    throw new BackupError("bad_format", "not a Tally backup file (bad magic header)");
  }
  let plain: Uint8Array;
  try {
    plain = await decryptBytes(new Uint8Array(raw.subarray(BACKUP_MAGIC.length)));
  } catch {
    throw new BackupError("corrupt", "backup file failed authentication (tampered or wrong TALLY_DATA_KEY)");
  }
  for (const suffix of ["-wal", "-shm", "-journal"]) {
    rmSync(targetPath + suffix, { force: true });
  }
  // Same fresh-install class as openDb: the target's parent may not exist yet.
  mkdirSync(dirname(targetPath), { recursive: true });
  writeFileSync(targetPath, plain);
  return { bytes: plain.length };
}

export interface TrialBalanceSummary {
  period_id: number;
  total_debits: number;
  total_credits: number;
  balanced: boolean;
  rows: TrialBalance["rows"];
}

export function trialBalanceSummaries(db: Database): TrialBalanceSummary[] {
  return listPeriods(db).map((p) => {
    const tb = trialBalance(db, p.id);
    return {
      period_id: p.id,
      total_debits: tb.total_debits,
      total_credits: tb.total_credits,
      balanced: tb.balanced,
      rows: tb.rows,
    };
  });
}

export interface BackupVerification {
  ok: boolean;
  original: { trial_balances: TrialBalanceSummary[]; verify: VerifyReport };
  restored: { trial_balances: TrialBalanceSummary[]; verify: VerifyReport };
  trial_balances_identical: boolean;
}

/**
 * Restore `backupPath` to a temp DB, run verifyAll + trialBalance on
 * both the original (already-open) DB and the restored DB, and report
 * whether trial-balance totals are identical. Temp files are cleaned
 * up; the restored DB is closed before returning.
 */
export async function verifyBackupAgainst(
  originalDb: Database,
  backupPath: string,
): Promise<BackupVerification> {
  const dir = mkdtempSync(join(tmpdir(), "tally-verify-"));
  const restoredPath = join(dir, "restored.db");
  let restoredDb: SqliteDatabase | null = null;
  try {
    await restoreBackup(backupPath, restoredPath, { force: true });
    restoredDb = openDb(restoredPath);
    const originalTbs = trialBalanceSummaries(originalDb);
    const restoredTbs = trialBalanceSummaries(restoredDb);
    const identical = JSON.stringify(originalTbs) === JSON.stringify(restoredTbs);
    const originalVerify = await verifyAll(originalDb);
    const restoredVerify = await verifyAll(restoredDb);
    return {
      ok: identical && restoredVerify.ok,
      original: { trial_balances: originalTbs, verify: originalVerify },
      restored: { trial_balances: restoredTbs, verify: restoredVerify },
      trial_balances_identical: identical,
    };
  } finally {
    restoredDb?.close();
    rmSync(dir, { recursive: true, force: true });
  }
}
