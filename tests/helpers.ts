// Shared test helpers: isolated temp DB per file, seeded; ephemeral server.

import { Database } from "bun:sqlite";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openDb, checkpoint } from "../src/db";
import { seed, ADMIN_EMAIL, ADMIN_PASSWORD } from "../src/seed";
export { ADMIN_EMAIL, ADMIN_PASSWORD };
import { createServer } from "../src/server";
import { sessionConfigFromEnv, type SessionConfig } from "../src/auth";
import { hashPassword } from "../src/auth";

export const TEST_DATA_KEY =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

export interface TestEnv {
  db: Database;
  dbPath: string;
  server: ReturnType<typeof createServer>;
  base: string;
  cfg: SessionConfig;
  cleanup: () => void;
}

export async function makeTestEnv(overrides: Partial<SessionConfig> = {}): Promise<TestEnv> {
  process.env.TALLY_DATA_KEY = TEST_DATA_KEY;
  const { resetKeyCache } = await import("../src/crypto");
  resetKeyCache();
  const dir = mkdtempSync(join(tmpdir(), "tally-test-"));
  const dbPath = join(dir, "test.db");
  const db = openDb(dbPath);
  await seed(db);
  const cfg: SessionConfig = { ...sessionConfigFromEnv(), ...overrides };
  const server = createServer(db, cfg, { port: 0 });
  const base = `http://127.0.0.1:${server.port}`;
  return {
    db,
    dbPath,
    server,
    base,
    cfg,
    cleanup: () => {
      server.stop(true);
      db.close();
    },
  };
}

export async function loginAs(
  base: string,
  email: string,
  password: string,
): Promise<{ token: string; expires_at: string; status: number; body: any }> {
  const res = await fetch(`${base}/api/v1/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  const body = await res.json().catch(() => ({}));
  return { token: body.token, expires_at: body.expires_at, status: res.status, body };
}

export function authHeaders(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}` };
}

/** Create an extra user directly (bypasses HTTP) for lockout/role tests. */
export async function createTestUser(
  db: Database,
  email: string,
  password: string,
  roleName: string,
): Promise<number> {
  const role = db.query("SELECT id FROM roles WHERE name = ?").get(roleName) as { id: number };
  const pwHash = await hashPassword(password);
  const now = new Date().toISOString();
  const info = db
    .query(
      "INSERT INTO users (email, pw_hash, role_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
    )
    .run(email, pwHash, role.id, now, now);
  return Number(info.lastInsertRowid);
}

export { checkpoint };
