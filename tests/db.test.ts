// Ship-readiness regression: a fresh clone has no data/ dir (it is
// gitignored), and bun:sqlite cannot create a DB file whose parent
// directory is missing. openDb must create the parent first.

import { describe, test, expect } from "bun:test";
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openDb } from "../src/db";

describe("openDb", () => {
  test("creates missing parent directories (fresh-clone install path)", () => {
    const dir = mkdtempSync(join(tmpdir(), "tally-db-test-"));
    const dbPath = join(dir, "nested", "deeper", "tally.db");
    const db = openDb(dbPath);
    try {
      expect(existsSync(dbPath)).toBe(true);
      // Migrations ran: the core tables exist.
      const row = db.query(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'",
      ).get();
      expect(row).toBeTruthy();
      const applied = db.query("SELECT COUNT(*) AS n FROM schema_migrations").get() as { n: number };
      expect(applied.n).toBeGreaterThan(0);
    } finally {
      db.close();
    }
  });
});
