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
  postJournal,
  reverseJournal,
  createAccount,
  getAccount,
  renameAccount,
  deleteAccount,
  listAccounts,
  createPeriod,
  listPeriods,
  closePeriod,
  reopenPeriod,
  trialBalance,
  accountLedger,
  getJournalEntry,
  listJournalEntries,
  withIdempotency,
  LedgerError,
  type AccountRow,
} from "./ledger";
import {
  errorResponse,
  jsonResponse,
  getBearerToken,
  parseJsonBody,
  parseJsonBodyLenient,
  mutateWithAudit,
  withPerm,
  type Ctx,
  type Handler,
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

/** Map a LedgerError to the stable error envelope; rethrow anything else. */
function ledgerError(e: unknown): Response {
  if (e instanceof LedgerError) {
    const status =
      {
        validation: 400,
        unbalanced: 400,
        no_open_period: 400,
        period_closed: 409,
        already_reversed: 409,
        already_closed: 409,
        in_use: 409,
        overlap: 409,
      }[e.code] ?? 400;
    return errorResponse(e.code, e.message, status);
  }
  throw e;
}

function parseIdParam(parts: string[], idx: number): number | null {
  const id = parseInt(parts[idx], 10);
  return Number.isInteger(id) && id > 0 ? id : null;
}

function parseQueryInt(url: URL, name: string, fallback: number): number {
  const v = url.searchParams.get(name);
  if (v === null) return fallback;
  const n = parseInt(v, 10);
  return Number.isInteger(n) && n > 0 ? n : fallback;
}

/** POST /api/v1/ledger/journal — post a balanced entry. Idempotency-Key honored. */
async function handlePostJournal(req: Request, db: Database, ctx: Ctx): Promise<Response> {
  const parsed = await parseJsonBodyLenient(req);
  if (!parsed.ok) return parsed.response;
  const b = parsed.body;
  const idemKey = req.headers.get("idempotency-key")?.trim().slice(0, 128);
  const produce = () => {
    let posted!: { id: number; entry_no: string };
    try {
      posted = postJournal(db, {
        period_id: typeof b.period_id === "number" ? b.period_id : undefined,
        memo: typeof b.memo === "string" ? b.memo : "",
        lines: Array.isArray(b.lines) ? b.lines : [],
        actor_id: ctx.user.id,
        posted_on: typeof b.posted_on === "string" ? b.posted_on : undefined,
        source_type: typeof b.source_type === "string" ? b.source_type : "manual",
        source_id: typeof b.source_id === "string" ? b.source_id : null,
      });
    } catch (e) {
      const r = ledgerError(e);
      throw { __ledgerHttp: r };
    }
    return { status: 201, body: { data: getJournalEntry(db, posted.id) } };
  };
  const run = (): { replayed: boolean; status: number; body: unknown } => {
    if (idemKey) {
      return withIdempotency(
        db,
        `journal:${ctx.user.id}:${idemKey}`,
        ctx.user.id,
        "POST",
        "/api/v1/ledger/journal",
        produce,
      );
    }
    return { replayed: false, ...produce() };
  };
  try {
    const r = run();
    return Response.json(r.body, { status: r.status });
  } catch (e) {
    if (e && typeof e === "object" && "__ledgerHttp" in e) {
      return (e as { __ledgerHttp: Response }).__ledgerHttp;
    }
    throw e;
  }
}

/** POST /api/v1/ledger/journal/:id/reverse — reversing entry. Idempotency-Key honored. */
async function handleReverseJournal(
  req: Request,
  db: Database,
  ctx: Ctx,
  entryId: number,
): Promise<Response> {
  const parsed = await parseJsonBodyLenient(req);
  if (!parsed.ok) return parsed.response;
  const b = parsed.body;
  const idemKey = req.headers.get("idempotency-key")?.trim().slice(0, 128);
  const produce = () => {
    let posted!: { id: number; entry_no: string };
    try {
      posted = reverseJournal(db, entryId, {
        actor_id: ctx.user.id,
        memo: typeof b.memo === "string" ? b.memo : undefined,
        posted_on: typeof b.posted_on === "string" ? b.posted_on : undefined,
        period_id: typeof b.period_id === "number" ? b.period_id : undefined,
      });
    } catch (e) {
      const r = ledgerError(e);
      throw { __ledgerHttp: r };
    }
    return { status: 201, body: { data: getJournalEntry(db, posted.id) } };
  };
  try {
    const r = idemKey
      ? withIdempotency(
          db,
          `reverse:${ctx.user.id}:${entryId}:${idemKey}`,
          ctx.user.id,
          "POST",
          `/api/v1/ledger/journal/${entryId}/reverse`,
          produce,
        )
      : { replayed: false, ...produce() };
    return Response.json(r.body, { status: r.status });
  } catch (e) {
    if (e && typeof e === "object" && "__ledgerHttp" in e) {
      return (e as { __ledgerHttp: Response }).__ledgerHttp;
    }
    throw e;
  }
}

/** All /api/v1/ledger/* routes. */
function handleLedger(req: Request, db: Database, cfg: SessionConfig, url: URL): Promise<Response> | Response {
  const perm = (
    action: string,
    handler: (req: Request, ctx: Ctx, url: URL) => Promise<Response> | Response,
  ): Handler =>
    withPerm(db, cfg, "ledger", action, (req2, ctx) => {
      if (!ctx) return errorResponse("unauthorized", "missing session", 401);
      return handler(req2, ctx, url);
    });

  const sub = url.pathname.slice("/api/v1/ledger/".length);
  const parts = sub.split("/");

  // --- accounts ---
  if (parts[0] === "accounts") {
    if (parts.length === 1) {
      if (req.method === "GET") {
        return perm("read", () => {
          try {
            const type = url.searchParams.get("type") ?? undefined;
            return jsonResponse(listAccounts(db, { type }));
          } catch (e) {
            return ledgerError(e);
          }
        })(req);
      }
      if (req.method === "POST") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            let created!: AccountRow;
            mutateWithAudit(
              db,
              {
                actor_id: ctx.user.id,
                action: "account.create",
                entity_type: "account",
                entity_id: String(b.code ?? ""),
              },
              () => {
                created = createAccount(db, {
                  code: String(b.code ?? ""),
                  name: String(b.name ?? ""),
                  type: String(b.type ?? ""),
                  parent_id: typeof b.parent_id === "number" ? b.parent_id : null,
                });
              },
            );
            return Response.json({ data: created }, { status: 201 });
          } catch (e) {
            return ledgerError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    const id = parseIdParam(parts, 1);
    if (id === null) return errorResponse("validation", "account id must be a positive integer", 400);
    if (parts.length === 2) {
      if (req.method === "GET") {
        return perm("read", () => {
          const a = getAccount(db, id);
          return a && a.deleted_at === null
            ? jsonResponse({ data: a })
            : errorResponse("not_found", "account not found", 404);
        })(req);
      }
      if (req.method === "PATCH") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          try {
            const before = getAccount(db, id);
            let renamed!: AccountRow;
            mutateWithAudit(
              db,
              {
                actor_id: ctx.user.id,
                action: "account.rename",
                entity_type: "account",
                entity_id: id,
                before: before ? { name: before.name } : null,
              },
              () => {
                renamed = renameAccount(db, id, String(parsed.body.name ?? ""));
              },
            );
            return jsonResponse(renamed);
          } catch (e) {
            return ledgerError(e);
          }
        })(req);
      }
      if (req.method === "DELETE") {
        return perm("write", (_req2, ctx) => {
          try {
            const before = getAccount(db, id);
            mutateWithAudit(
              db,
              {
                actor_id: ctx.user.id,
                action: "account.delete",
                entity_type: "account",
                entity_id: id,
                before: before ? { code: before.code, name: before.name } : null,
              },
              () => deleteAccount(db, id),
            );
            return jsonResponse({ deleted: true });
          } catch (e) {
            return ledgerError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    if (parts.length === 3 && parts[2] === "ledger" && req.method === "GET") {
      return perm("read", () => {
        try {
          const period_id = url.searchParams.get("period_id");
          const view = accountLedger(db, id, {
            period_id: period_id ? parseInt(period_id, 10) || undefined : undefined,
            from: url.searchParams.get("from") ?? undefined,
            to: url.searchParams.get("to") ?? undefined,
          });
          return jsonResponse(view);
        } catch (e) {
          return ledgerError(e);
        }
      })(req);
    }
    return errorResponse("not_found", "not found", 404);
  }

  // --- journal ---
  if (parts[0] === "journal") {
    if (parts.length === 1) {
      if (req.method === "POST") {
        return perm("post", (req2, ctx) => handlePostJournal(req2, db, ctx))(req);
      }
      if (req.method === "GET") {
        return perm("read", () => {
          const period_id = url.searchParams.get("period_id");
          const page = parseQueryInt(url, "page", 1);
          const per_page = parseQueryInt(url, "per_page", 50);
          const { rows, total } = listJournalEntries(db, {
            period_id: period_id ? parseInt(period_id, 10) || undefined : undefined,
            page,
            per_page,
          });
          return Response.json({ data: rows, meta: { page, per_page, total } });
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    const id = parseIdParam(parts, 1);
    if (id === null) return errorResponse("validation", "journal entry id must be a positive integer", 400);
    if (parts.length === 2 && req.method === "GET") {
      return perm("read", () => {
        const v = getJournalEntry(db, id);
        return v ? jsonResponse(v) : errorResponse("not_found", "journal entry not found", 404);
      })(req);
    }
    if (parts.length === 3 && parts[2] === "reverse" && req.method === "POST") {
      return perm("post", (req2, ctx) => handleReverseJournal(req2, db, ctx, id))(req);
    }
    return errorResponse("not_found", "not found", 404);
  }

  // --- periods ---
  if (parts[0] === "periods") {
    if (parts.length === 1) {
      if (req.method === "GET") {
        return perm("read", () => jsonResponse(listPeriods(db)))(req);
      }
      if (req.method === "POST") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            let created!: ReturnType<typeof createPeriod>;
            mutateWithAudit(
              db,
              {
                actor_id: ctx.user.id,
                action: "period.create",
                entity_type: "fiscal_period",
                entity_id: String(b.name ?? ""),
              },
              () => {
                created = createPeriod(db, {
                  name: String(b.name ?? ""),
                  starts_on: String(b.starts_on ?? ""),
                  ends_on: String(b.ends_on ?? ""),
                });
              },
            );
            return Response.json({ data: created }, { status: 201 });
          } catch (e) {
            return ledgerError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    const id = parseIdParam(parts, 1);
    if (id === null) return errorResponse("validation", "period id must be a positive integer", 400);
    if (parts.length === 3 && req.method === "POST") {
      if (parts[2] === "close") {
        return perm("approve", (_req2, ctx) => {
          try {
            return jsonResponse(closePeriod(db, id, ctx.user.id));
          } catch (e) {
            return ledgerError(e);
          }
        })(req);
      }
      if (parts[2] === "reopen") {
        return perm("admin", (_req2, ctx) => {
          try {
            return jsonResponse(reopenPeriod(db, id, ctx.user.id));
          } catch (e) {
            return ledgerError(e);
          }
        })(req);
      }
    }
    return errorResponse("not_found", "not found", 404);
  }

  // --- trial balance ---
  if (parts[0] === "trial-balance" && req.method === "GET") {
    return perm("read", () => {
      const period_id = url.searchParams.get("period_id");
      if (!period_id) return errorResponse("validation", "period_id is required", 400);
      try {
        return jsonResponse(trialBalance(db, parseInt(period_id, 10)));
      } catch (e) {
        return ledgerError(e);
      }
    })(req);
  }

  return errorResponse("not_found", "not found", 404);
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
        if (path.startsWith("/api/v1/ledger/")) {
          return handleLedger(req, db, cfg, url);
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
