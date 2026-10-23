// Tally ERP — CLI: `tally serve|seed|migrate`
// verify/backup arrive in later phases (roadmap).

import { openDb } from "./db";
import { seed } from "./seed";
import { createServer, TALLY_VERSION } from "./server";
import { sessionConfigFromEnv } from "./auth";

function usage(): never {
  console.error(`tally v${TALLY_VERSION}
usage:
  tally serve [--port N]     start the API server (default port 3041 / $TALLY_PORT)
  tally seed                 seed roles, permissions, admin user, retention policies
  tally migrate              run pending DB migrations only`);
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
