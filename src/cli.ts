// Tally ERP — CLI: `tally serve|seed|migrate|verify|backup|restore`
// Backup/restore/verify arrived in Phase 10 (F-R5).

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openDb } from "./db";
import { seed } from "./seed";
import { createServer, TALLY_VERSION } from "./server";
import { sessionConfigFromEnv } from "./auth";
import { verifyAll } from "./compliance";
import { createBackup, restoreBackup, verifyBackupAgainst, BackupError } from "./backup";

function usage(): never {
  console.error(`tally v${TALLY_VERSION}
usage:
  tally serve [--port N]     start the API server (default port 3041 / $TALLY_PORT)
  tally seed                 seed roles, permissions, admin user, retention policies
  tally migrate              run pending DB migrations only
  tally verify               verify storage processes: audit chain, document
                             hashes, retention coverage (17a-4(f)(2)(ii)); exit 1 on failure
  tally backup --out <file> [--verify] [--db <path>]
                             snapshot the DB (VACUUM INTO) + AES-256-GCM encrypt
                             with TALLY_DATA_KEY; --verify restores to a temp
                             DB and proves trial balances identical (exit 1
                             on mismatch). With --verify and no --out, the
                             backup lives only in a temp file.
  tally restore --in <file> --db <path> [--force]
                             decrypt + write the DB; refuses to overwrite a
                             non-empty existing DB unless --force`);
  process.exit(2);
}

function flagValue(rest: string[], name: string): string | null {
  const i = rest.indexOf(name);
  return i >= 0 ? (rest[i + 1] ?? null) : null;
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);
  if (!cmd) usage();

  const dbPath = process.env.TALLY_DB ?? "./data/tally.db";

  if (cmd === "migrate") {
    const db = openDb(dbPath);
    const rows = db.query("SELECT name FROM schema_migrations ORDER BY name").all() as { name: string }[];
    console.log(`migrations applied (${rows.length}): ${rows.map((r) => r.name).join(", ") || "(none)"}`);
    db.close();
    return;
  }

  if (cmd === "seed") {
    const db = openDb(dbPath);
    await seed(db);
    console.log(`seeded ${dbPath}`);
    db.close();
    return;
  }

  if (cmd === "verify") {
    const db = openDb(dbPath);
    const report = await verifyAll(db);
    const c = report.audit_chain;
    const d = report.documents;
    console.log(`tally verify — ${report.ok ? "OK" : "FAIL"} (${report.generated_at})`);
    console.log(
      `  audit chain: ${c.ok ? `ok (${c.count} rows)` : `BROKEN at seq ${c.break_at_seq} (${c.count} rows)`}`,
    );
    console.log(
      `  documents:   ${d.corrupt === 0 ? `ok (${d.checked} checked)` : `CORRUPT ${d.corrupt}/${d.checked} [ids: ${d.corrupt_ids.join(",")}]`}`,
    );
    console.log(
      `  retention:   ${report.retention.policies.length} policies, ` +
        `${report.retention.document_types.length} document types covered`,
    );
    db.close();
    process.exit(report.ok ? 0 : 1);
  }

  if (cmd === "backup") {
    const out = flagValue(rest, "--out");
    const dbOverride = flagValue(rest, "--db");
    const doVerify = rest.includes("--verify");
    let outPath = out;
    let tempDir: string | null = null;
    if (!outPath && !doVerify) {
      console.error("tally backup requires --out <file> (or --verify for a temp-only check)");
      process.exit(2);
    }
    if (!outPath) {
      tempDir = mkdtempSync(join(tmpdir(), "tally-backup-cli-"));
      outPath = join(tempDir, "tally.tallybk");
    }
    try {
      const db = openDb(dbOverride ?? dbPath);
      try {
        const r = await createBackup(db, outPath);
        console.log(`backup written: ${outPath} (${r.bytes} bytes, encrypted)`);
        if (doVerify) {
          const v = await verifyBackupAgainst(db, outPath);
          console.log(
            `backup verify — trial balances identical: ${v.trial_balances_identical}, ` +
              `restored storage verification: ${v.restored.verify.ok ? "OK" : "FAIL"}`,
          );
          for (const tb of v.original.trial_balances) {
            console.log(
              `  period ${tb.period_id}: debits ${tb.total_debits} credits ${tb.total_credits} balanced ${tb.balanced}`,
            );
          }
          if (!v.ok) {
            console.error("backup verification FAILED");
            process.exit(1);
          }
          console.log("backup verify — OK");
        }
      } finally {
        db.close();
      }
    } catch (e) {
      if (e instanceof BackupError) {
        console.error(`backup failed (${e.code}): ${e.message}`);
      } else {
        console.error(e);
      }
      process.exit(1);
    } finally {
      if (tempDir) rmSync(tempDir, { recursive: true, force: true });
    }
    return;
  }

  if (cmd === "restore") {
    const inFile = flagValue(rest, "--in");
    const dbOverride = flagValue(rest, "--db");
    const force = rest.includes("--force");
    if (!inFile || !dbOverride) {
      console.error("tally restore requires --in <file> --db <path> [--force]");
      process.exit(2);
    }
    try {
      const r = await restoreBackup(inFile, dbOverride, { force });
      console.log(`restored ${dbOverride} (${r.bytes} bytes)`);
    } catch (e) {
      if (e instanceof BackupError) {
        console.error(`restore failed (${e.code}): ${e.message}`);
      } else {
        console.error(e);
      }
      process.exit(1);
    }
    return;
  }

  if (cmd === "serve") {
    const portFlag = rest.indexOf("--port");
    const port =
      portFlag >= 0 ? parseInt(rest[portFlag + 1] ?? "", 10) : parseInt(process.env.TALLY_PORT ?? "3041", 10);
    if (!Number.isFinite(port)) {
      console.error("invalid port");
      process.exit(2);
    }
    // Reuse the server entry's TLS guard by delegating to server.ts main logic:
    // set env and import is overkill — duplicate the small guard here.
    const allowInsecure = process.env.TALLY_ALLOW_INSECURE === "1";
    const certPath = process.env.TALLY_TLS_CERT;
    const keyPath = process.env.TALLY_TLS_KEY;
    if (!certPath && !allowInsecure) {
      console.error(
        "refusing to serve Tally over plain HTTP (H-T8). Set TALLY_TLS_CERT/TALLY_TLS_KEY or TALLY_ALLOW_INSECURE=1.",
      );
      process.exit(1);
    }
    if (!process.env.TALLY_DATA_KEY) {
      console.warn("warning: TALLY_DATA_KEY is not set — field encryption is unavailable");
    }
    const db = openDb(dbPath);
    const server = createServer(db, sessionConfigFromEnv(), {
      port,
      tls: certPath && keyPath ? { cert: Bun.file(certPath), key: Bun.file(keyPath) } : undefined,
    });
    console.log(`tally v${TALLY_VERSION} listening on port ${server.port} (db: ${dbPath})`);
    return;
  }

  usage();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
