// Tally ERP — db.ts
// SQLite open + ordered migrations from migrations/*.sql, tracked in schema_migrations.
// Zero npm deps (bun:sqlite is built in).

import { Database } from "bun:sqlite";
import { mkdirSync, readdirSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = typeof import.meta.dir === "string"
  ? import.meta.dir
  : dirname(fileURLToPath(import.meta.url));

export function migrationsDir(): string {
  return join(HERE, "..", "migrations");
}

export function runMigrations(db: Database): void {
  db.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
    name TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL
  )`);
  const files = readdirSync(migrationsDir())
    .filter((f) => f.endsWith(".sql"))
    .sort();
  const applied = new Set(
    (db.query("SELECT name FROM schema_migrations").all() as { name: string }[])
      .map((r) => r.name),
  );
  for (const f of files) {
    if (applied.has(f)) continue;
    const sql = readFileSync(join(migrationsDir(), f), "utf8");
    const apply = db.transaction(() => {
      db.exec(sql);
      db.query("INSERT INTO schema_migrations (name, applied_at) VALUES (?, ?)").run(
        f,
        new Date().toISOString(),
      );
    });
    apply();
  }
}

/** Open (creating) the SQLite file, enable WAL + FKs, run pending migrations. */
export function openDb(path: string): Database {
  // Fresh clones have no data/ dir (it is gitignored), and bun:sqlite
  // cannot create a file whose parent directory is missing — so create
  // the parent first. ":memory:" resolves to "." here, a no-op.
  mkdirSync(dirname(path), { recursive: true });
  const db = new Database(path, { create: true });
  db.exec("PRAGMA journal_mode = WAL;");
  db.exec("PRAGMA foreign_keys = ON;");
  db.exec("PRAGMA busy_timeout = 5000;");
  runMigrations(db);
  return db;
}

/** Force a WAL checkpoint so the main DB file is self-contained (used before file copies in tests/backups). */
export function checkpoint(db: Database): void {
  db.exec("PRAGMA wal_checkpoint(TRUNCATE);");
}

export function nowIso(): string {
  return new Date().toISOString();
}
