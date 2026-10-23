// Tally ERP — server.ts
// Bun.serve HTTP API, REST /api/v1. Phase 0 surface: auth + compliance reads.
// Every mutating request is audited (see auth.ts login/logout, middleware.ts
// mutateWithAudit for future resource handlers).

import type { Database } from "bun:sqlite";
import { openDb } from "./db";
import {
  login,
  logout,
  authenticate,
  sessionConfigFromEnv,
  type SessionConfig,
} from "./auth";
import { verifyChain } from "./audit";
import { can } from "./rbac";
import {
  errorResponse,
  jsonResponse,
  getBearerToken,
  parseJsonBody,
} from "./middleware";

export const TALLY_VERSION = "0.1.0";

export interface ServeOptions {
  port?: number;
  tls?: { cert: Bun.BunFile; key: Bun.BunFile };
}

async function handleLogin(req: Request, db: Database, cfg: SessionConfig): Promise<Response> {
  const parsed = await parseJsonBody(req);
  if (!parsed.ok) return parsed.response;
  const { email, password } = parsed.body as { email?: unknown; password?: unknown };
  const result = await login(
    db,
    typeof email === "string" ? email : "",
    typeof password === "string" ? password : "",
    {
      ip: req.headers.get("x-forwarded-for") ?? null,
      userAgent: req.headers.get("user-agent")?.slice(0, 256) ?? null,
    },
    cfg,
  );
  if (!result.ok) {
    const status = result.code === "validation" ? 400 : 401;
    return errorResponse(result.code, result.message, status);
  }
  return Response.json({
    token: result.token,
    expires_at: result.expires_at,
    must_change_password: result.must_change_password,
  });
}

function handleLogout(req: Request, db: Database, cfg: SessionConfig): Response {
  const token = getBearerToken(req);
  if (!token) return errorResponse("unauthorized", "missing bearer token", 401);
  // authenticate first so a dead token can't be "logged out" silently; both
  // 401 codes are stable machine codes.
  const auth = authenticate(db, token, cfg);
  if (!auth.ok) return errorResponse(auth.code, auth.message, 401);
  logout(db, token);
  return jsonResponse({ logged_out: true });
}

function handleMe(req: Request, db: Database, cfg: SessionConfig): Response {
  const auth = authenticate(db, getBearerToken(req), cfg);
  if (!auth.ok) return errorResponse(auth.code, auth.message, 401);
  const { pw_hash: _pw, ...safe } = auth.user as Record<string, unknown>;
  void _pw;
  return jsonResponse({
    id: safe.id,
    email: safe.email,
    role: (auth.user as unknown as { role_name: string }).role_name,
    must_change_password: auth.user.must_change_pw === 1,
    session_expires_at: auth.session.expires_at,
  });
}

function handleAuditLog(req: Request, db: Database, cfg: SessionConfig, url: URL): Response {
  const auth = authenticate(db, getBearerToken(req), cfg);
  if (!auth.ok) return errorResponse(auth.code, auth.message, 401);
  if (!can(db, auth.user.role_name, "audit", "read")) {
    return errorResponse("forbidden", `role '${auth.user.role_name}' lacks read on audit`, 403);
  }

  const where: string[] = [];
  const params: (string | number)[] = [];
  const action = url.searchParams.get("action");
  const entityType = url.searchParams.get("entity_type");
  const actorId = url.searchParams.get("actor_id");
  const since = url.searchParams.get("since");
  const until = url.searchParams.get("until");
  if (action) { where.push("action = ?"); params.push(action); }
  if (entityType) { where.push("entity_type = ?"); params.push(entityType); }
  if (actorId) { where.push("actor_id = ?"); params.push(actorId); }
  if (since) { where.push("ts >= ?"); params.push(since); }
  if (until) { where.push("ts <= ?"); params.push(until); }
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";

  const perPage = Math.min(Math.max(parseInt(url.searchParams.get("per_page") ?? "50", 10) || 50, 1), 500);
  const page = Math.max(parseInt(url.searchParams.get("page") ?? "1", 10) || 1, 1);
  const total = (db.query(`SELECT COUNT(*) AS n FROM audit_log ${clause}`).get(...params) as { n: number }).n;
  const rows = db
    .query(
      `SELECT seq, ts, actor_id, action, entity_type, entity_id,
              before_json, after_json, prev_hash, hash
       FROM audit_log ${clause} ORDER BY seq ASC LIMIT ? OFFSET ?`,
    )
    .all(...params, perPage, (page - 1) * perPage) as Record<string, unknown>[];

  const data = rows.map((r) => ({
    ...r,
    before: r.before_json ? JSON.parse(r.before_json as string) : null,
    after: r.after_json ? JSON.parse(r.after_json as string) : null,
    before_json: undefined,
    after_json: undefined,
  }));

  const body: Record<string, unknown> = {
    data,
    meta: { page, per_page: perPage, total },
  };
  if (url.searchParams.get("verify") === "1") {
    body.verification = verifyChain(db);
  }
  return Response.json(body);
}

export function createServer(db: Database, cfg: SessionConfig, opts: ServeOptions = {}) {
  return Bun.serve({
    port: opts.port ?? 0,
    tls: opts.tls,
    fetch: async (req: Request) => {
      try {
        const url = new URL(req.url);
        const path = url.pathname;
        if (req.method === "GET" && path === "/health") {
          return jsonResponse({ status: "ok", name: "tally", version: TALLY_VERSION });
        }
        if (path === "/api/v1/auth/login" && req.method === "POST") {
          return handleLogin(req, db, cfg);
        }
        if (path === "/api/v1/auth/logout" && req.method === "POST") {
          return handleLogout(req, db, cfg);
        }
        if (path === "/api/v1/auth/me" && req.method === "GET") {
          return handleMe(req, db, cfg);
        }
        if (path === "/api/v1/compliance/audit-log" && req.method === "GET") {
          return handleAuditLog(req, db, cfg, url);
        }
        return errorResponse("not_found", "not found", 404);
      } catch (e) {
        console.error("unhandled request error:", e);
        return errorResponse("internal", "internal server error", 500);
      }
    },
  });
}

// --- standalone entry -------------------------------------------------------
if (import.meta.main) {
  const allowInsecure = process.env.TALLY_ALLOW_INSECURE === "1";
  const certPath = process.env.TALLY_TLS_CERT;
  const keyPath = process.env.TALLY_TLS_KEY;

  // H-T8: plain HTTP refuses to start unless the dev flag is set.
  if (!certPath && !allowInsecure) {
    console.error(
      "refusing to serve Tally over plain HTTP (H-T8 transmission security). " +
        "Set TALLY_TLS_CERT/TALLY_TLS_KEY, or TALLY_ALLOW_INSECURE=1 for local dev only.",
    );
    process.exit(1);
  }
  if (!process.env.TALLY_DATA_KEY) {
    console.warn("warning: TALLY_DATA_KEY is not set — field encryption is unavailable");
  }

  const dbPath = process.env.TALLY_DB ?? "./data/tally.db";
  const db = openDb(dbPath);
  const cfg = sessionConfigFromEnv();
  const port = parseInt(process.env.TALLY_PORT ?? "3041", 10);
  const server = createServer(db, cfg, {
    port,
    tls: certPath && keyPath ? { cert: Bun.file(certPath), key: Bun.file(keyPath) } : undefined,
  });
  console.log(
    `tally v${TALLY_VERSION} listening on ${certPath ? "https" : "http"}://127.0.0.1:${server.port} (db: ${dbPath})`,
  );
}
