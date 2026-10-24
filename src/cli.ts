// Tally ERP — CLI: `tally serve|seed|migrate|verify`
// backup arrives in Phase 10 (roadmap).

import { openDb } from "./db";
import { seed } from "./seed";
import { createServer, TALLY_VERSION } from "./server";
import { sessionConfigFromEnv } from "./auth";
import { verifyAll } from "./compliance";

function usage(): never {
  console.error(`tally v${TALLY_VERSION}
usage:
  tally serve [--port N]     start the API server (default port 3041 / $TALLY_PORT)
  tally seed                 seed roles, permissions, admin user, retention policies
  tally migrate              run pending DB migrations only
  tally verify               verify storage processes: audit chain, document
                             hashes, retention coverage (17a-4(f)(2)(ii)); exit 1 on failure`);
  process.exit(2);
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
