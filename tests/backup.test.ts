// Phase 10 acceptance: backup -> restore -> trial balance identical,
// tampered backup rejected, overwrite refused without --force, and the
// CLI backup --verify path end to end.

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { openDb, checkpoint } from "../src/db";
import { makeTestEnv, TEST_DATA_KEY, type TestEnv } from "./helpers";
import { postJournal } from "../src/ledger";
import {
  BACKUP_MAGIC, createBackup, restoreBackup, verifyBackupAgainst, trialBalanceSummaries,
} from "../src/backup";

let env: TestEnv;
beforeAll(async () => {
  env = await makeTestEnv();
});
afterAll(() => env.cleanup());

function seedLedgerActivity(): void {
  const period = env.db.query("SELECT id FROM fiscal_periods ORDER BY starts_on LIMIT 1").get() as { id: number };
  const cash = env.db.query("SELECT id FROM accounts WHERE code = '1000'").get() as { id: number };
  const revenue = env.db.query("SELECT id FROM accounts WHERE code = '4000'").get() as { id: number };
  postJournal(env.db, {
    period_id: period.id,
    memo: "backup acceptance sale",
    lines: [
      { account_id: cash.id, debit_cents: 12345 },
      { account_id: revenue.id, credit_cents: 12345 },
    ],
    actor_id: 1,
  });
  checkpoint(env.db);
}

describe("backup / restore", () => {
  test("backup -> restore -> trial balance identical (with seeded ledger activity)", async () => {
    seedLedgerActivity();
    const dir = mkdtempSync(join(tmpdir(), "tally-bk-"));
    const backupPath = join(dir, "tally.tallybk");
    const restoredPath = join(dir, "restored.db");
    const r = await createBackup(env.db, backupPath);
    expect(r.bytes).toBeGreaterThan(0);
    expect(readFileSync(backupPath).subarray(0, BACKUP_MAGIC.length).toString()).toBe(BACKUP_MAGIC);
    await restoreBackup(backupPath, restoredPath);
    const restored = openDb(restoredPath);
    try {
      expect(trialBalanceSummaries(restored)).toEqual(trialBalanceSummaries(env.db));
    } finally {
      restored.close();
    }
    const v = await verifyBackupAgainst(env.db, backupPath);
    expect(v.trial_balances_identical).toBe(true);
    expect(v.restored.verify.ok).toBe(true);
    expect(v.ok).toBe(true);
  });

  test("tampered backup file rejected (magic + GCM authentication)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tally-bk-"));
    const backupPath = join(dir, "tally.tallybk");
    await createBackup(env.db, backupPath);
    const bytes = readFileSync(backupPath);
    // Flip a byte deep in the ciphertext: magic stays valid, GCM must fail.
    bytes[bytes.length - 1] ^= 0xff;
    const tampered = join(dir, "tampered.tallybk");
    writeFileSync(tampered, bytes);
    await expect(restoreBackup(tampered, join(dir, "out.db"))).rejects.toThrow();

    const garbage = join(dir, "garbage.tallybk");
    writeFileSync(garbage, Buffer.from("this is not a tally backup at all........"));
    await expect(restoreBackup(garbage, join(dir, "out2.db"))).rejects.toThrow(/not a Tally backup/);
  });

  test("restore refuses to overwrite a non-empty DB without --force; --force succeeds", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tally-bk-"));
    const backupPath = join(dir, "tally.tallybk");
    await createBackup(env.db, backupPath);
    const target = join(dir, "existing.db");
    writeFileSync(target, Buffer.from("existing content, not empty"));
    await expect(restoreBackup(backupPath, target)).rejects.toThrow(/--force/);
    await restoreBackup(backupPath, target, { force: true });
    expect(existsSync(target)).toBe(true);
    const reopened = openDb(target);
    try {
      expect(trialBalanceSummaries(reopened)).toEqual(trialBalanceSummaries(env.db));
    } finally {
      reopened.close();
    }
  });

  test("CLI: tally backup --verify exits 0 and reports identical trial balances", async () => {
    seedLedgerActivity();
    checkpoint(env.db);
    const here = typeof import.meta.dir === "string"
      ? import.meta.dir
      : dirname(fileURLToPath(import.meta.url));
    const root = join(here, "..");
    const proc = Bun.spawn(
      ["bun", "src/cli.ts", "backup", "--verify", "--db", env.dbPath],
      {
        cwd: root,
        env: { ...process.env, TALLY_DATA_KEY: TEST_DATA_KEY },
        stdout: "pipe",
        stderr: "pipe",
      },
    );
    const [out, err, code] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
    ]);
    expect(err).not.toContain("FAILED");
    expect(out).toContain("trial balances identical: true");
    expect(out).toContain("backup verify — OK");
    expect(code).toBe(0);
  });
});
