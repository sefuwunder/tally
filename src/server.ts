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
  prepareDocument,
  insertDocument,
  getDocument,
  listDocuments,
  getDocumentContent,
  deleteDocument,
  DocumentError,
  type DocumentMeta,
} from "./documents";
import { RetentionError, retentionReport } from "./retention";
import { verifyAll, exportRecords, ComplianceError } from "./compliance";
import {
  createCustomer,
  getCustomer,
  listCustomers,
  updateCustomer,
  createInvoice,
  getInvoice,
  listInvoices,
  updateInvoiceDraft,
  postInvoice,
  voidInvoice,
  createPayment,
  getPayment,
  listPayments,
  applyPayment,
  createCreditMemo,
  getCreditMemo,
  listCreditMemos,
  postCreditMemo,
  voidCreditMemo,
  ArError,
} from "./ar";
import {
  createVendor,
  getVendor,
  listVendors,
  updateVendor,
  createBill,
  getBill,
  listBills,
  updateBillDraft,
  approveBill,
  postBill,
  voidBill,
  createBillPayment,
  getBillPayment,
  listBillPayments,
  applyBillPayment,
  ApError,
} from "./ap";
import {
  createItem,
  getItem,
  listItems,
  updateItem,
  createWarehouse,
  getWarehouse,
  listWarehouses,
  updateWarehouse,
  receiveStock,
  issueStock,
  adjustStock,
  transferStock,
  listStockLevels,
  listMovements,
  InventoryError,
} from "./inventory";
import {
  createPurchaseOrder,
  getPurchaseOrder,
  listPurchaseOrders,
  updatePurchaseOrderDraft,
  submitPurchaseOrder,
  closePurchaseOrder,
  cancelPurchaseOrder,
  receivePurchaseOrder,
  getReceiving,
  listReceivings,
  ProcurementError,
} from "./procurement";
import {
  createCompany,
  getCompany,
  listCompanies,
  updateCompany,
  createContact,
  getContact,
  listContacts,
  updateContact,
  createDeal,
  getDeal,
  listDeals,
  updateDeal,
  createActivity,
  getActivity,
  listActivities,
  reviewQueue,
  getCommsReview,
  reviewActivity,
  listPrincipals,
  designatePrincipal,
  revokePrincipal,
  createComplaint,
  getComplaint,
  listComplaints,
  acknowledgeComplaint,
  respondComplaint,
  CrmError,
} from "./crm";
import {
  createEmployee,
  getEmployee,
  listEmployees,
  updateEmployee,
  createDeductionType,
  getDeductionType,
  listDeductionTypes,
  createPayRun,
  getPayRun,
  listPayRuns,
  addPayLine,
  updatePayLineDraft,
  removePayLine,
  approvePayRun,
  payPayRun,
  HrError,
} from "./hr";
import { appendAudit } from "./audit";
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

/** Map an ArError to the stable error envelope; LedgerError delegates to ledgerError. */
function arError(e: unknown): Response {
  if (e instanceof LedgerError) return ledgerError(e);
  if (e instanceof ArError) {
    const status =
      {
        validation: 400,
        over_applied: 400,
        not_found: 404,
        not_draft: 409,
        not_posted: 409,
        already_posted: 409,
        already_void: 409,
        void_blocked: 409,
      }[e.code] ?? 400;
    return errorResponse(e.code, e.message, status);
  }
  throw e;
}

/**
 * Run produce() for an AR mutation, honoring Idempotency-Key like the ledger
 * routes: errors are NOT recorded (the retry can succeed), successes replay.
 * produce() must return { status, body }; ArError/LedgerError inside it are
 * mapped to the error envelope and returned, not recorded.
 */
function runArMutation(
  req: Request,
  db: Database,
  ctx: Ctx,
  scope: string,
  path: string,
  produce: () => { status: number; body: unknown },
): Response {
  const idemKey = req.headers.get("idempotency-key")?.trim().slice(0, 128);
  const run = (): { status: number; body: unknown } => {
    try {
      return produce();
    } catch (e) {
      throw { __arHttp: arError(e) };
    }
  };
  try {
    const r = idemKey
      ? withIdempotency(db, `${scope}:${ctx.user.id}:${idemKey}`, ctx.user.id, "POST", path, run)
      : { replayed: false, ...run() };
    return Response.json(r.body, { status: r.status });
  } catch (e) {
    if (e && typeof e === "object" && "__arHttp" in e) {
      return (e as { __arHttp: Response }).__arHttp;
    }
    throw e;
  }
}

/** Map an ApError to the stable error envelope; LedgerError delegates to ledgerError. */
function apError(e: unknown): Response {
  if (e instanceof LedgerError) return ledgerError(e);
  if (e instanceof ApError) {
    const status =
      {
        validation: 400,
        over_applied: 400,
        not_found: 404,
        self_approval: 403,
        not_draft: 409,
        not_approved: 409,
        not_posted: 409,
        already_posted: 409,
        already_approved: 409,
        already_void: 409,
        void_blocked: 409,
      }[e.code] ?? 400;
    return errorResponse(e.code, e.message, status);
  }
  throw e;
}

/**
 * Run produce() for an AP mutation, honoring Idempotency-Key like the AR
 * routes: errors are NOT recorded (the retry can succeed), successes replay.
 * produce() must return { status, body }; ApError/LedgerError inside it are
 * mapped to the error envelope and returned, not recorded.
 */
function runApMutation(
  req: Request,
  db: Database,
  ctx: Ctx,
  scope: string,
  path: string,
  produce: () => { status: number; body: unknown },
): Response {
  const idemKey = req.headers.get("idempotency-key")?.trim().slice(0, 128);
  const run = (): { status: number; body: unknown } => {
    try {
      return produce();
    } catch (e) {
      throw { __apHttp: apError(e) };
    }
  };
  try {
    const r = idemKey
      ? withIdempotency(db, `${scope}:${ctx.user.id}:${idemKey}`, ctx.user.id, "POST", path, run)
      : { replayed: false, ...run() };
    return Response.json(r.body, { status: r.status });
  } catch (e) {
    if (e && typeof e === "object" && "__apHttp" in e) {
      return (e as { __apHttp: Response }).__apHttp;
    }
    throw e;
  }
}

/** Map an InventoryError to the stable error envelope; LedgerError delegates. */
function inventoryError(e: unknown): Response {
  if (e instanceof LedgerError) return ledgerError(e);
  if (e instanceof InventoryError) {
    const status =
      {
        validation: 400,
        no_cost_basis: 400,
        not_found: 404,
        negative_stock: 409,
      }[e.code] ?? 400;
    return errorResponse(e.code, e.message, status);
  }
  throw e;
}

/**
 * Run produce() for an inventory movement, honoring Idempotency-Key like
 * the AR/AP routes: errors are NOT recorded, successes replay.
 * produce() must return { status, body }.
 */
function runInventoryMutation(
  req: Request,
  db: Database,
  ctx: Ctx,
  scope: string,
  path: string,
  produce: () => { status: number; body: unknown },
): Response {
  const idemKey = req.headers.get("idempotency-key")?.trim().slice(0, 128);
  const run = (): { status: number; body: unknown } => {
    try {
      return produce();
    } catch (e) {
      throw { __invHttp: inventoryError(e) };
    }
  };
  try {
    const r = idemKey
      ? withIdempotency(db, `${scope}:${ctx.user.id}:${idemKey}`, ctx.user.id, "POST", path, run)
      : { replayed: false, ...run() };
    return Response.json(r.body, { status: r.status });
  } catch (e) {
    if (e && typeof e === "object" && "__invHttp" in e) {
      return (e as { __invHttp: Response }).__invHttp;
    }
    throw e;
  }
}

/** Map a ProcurementError to the stable error envelope; LedgerError delegates.
 *  Receiving calls inventory receiveStock, so InventoryError (e.g. an
 *  inactive item) must map here too — otherwise it would surface as a 500. */
function procurementError(e: unknown): Response {
  if (e instanceof LedgerError) return ledgerError(e);
  if (e instanceof InventoryError) return inventoryError(e);
  if (e instanceof ProcurementError) {
    const status =
      {
        validation: 400,
        over_received: 400,
        line_mismatch: 400,
        not_found: 404,
        not_draft: 409,
        not_submitted: 409,
        not_receivable: 409,
        not_cancellable: 409,
        already_closed: 409,
        already_cancelled: 409,
      }[e.code] ?? 400;
    return errorResponse(e.code, e.message, status);
  }
  throw e;
}

/**
 * Run produce() for a procurement posting (receiving), honoring
 * Idempotency-Key like the AR/AP/inventory routes: errors are NOT
 * recorded, successes replay.
 */
function runProcurementMutation(
  req: Request,
  db: Database,
  ctx: Ctx,
  scope: string,
  path: string,
  produce: () => { status: number; body: unknown },
): Response {
  const idemKey = req.headers.get("idempotency-key")?.trim().slice(0, 128);
  const run = (): { status: number; body: unknown } => {
    try {
      return produce();
    } catch (e) {
      throw { __procHttp: procurementError(e) };
    }
  };
  try {
    const r = idemKey
      ? withIdempotency(db, `${scope}:${ctx.user.id}:${idemKey}`, ctx.user.id, "POST", path, run)
      : { replayed: false, ...run() };
    return Response.json(r.body, { status: r.status });
  } catch (e) {
    if (e && typeof e === "object" && "__procHttp" in e) {
      return (e as { __procHttp: Response }).__procHttp;
    }
    throw e;
  }
}

/** Map document/retention/compliance errors to the envelope; rethrow others. */
function documentError(e: unknown): Response {
  if (e instanceof RetentionError) {
    return errorResponse("retained", e.message, 405);
  }
  if (e instanceof DocumentError) {
    const status = { validation: 400, not_found: 404, corrupt: 500 }[e.code] ?? 400;
    return errorResponse(e.code, e.message, status);
  }
  if (e instanceof ComplianceError) {
    const status = { validation: 400, not_found: 404 }[e.code] ?? 400;
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

/** Sanitize a title for Content-Disposition (no quotes/CR/LF). */
function safeFilename(title: string): string {
  return title.replace(/["\r\n]/g, "_").slice(0, 200) || "document";
}

/** Extract upload fields from JSON (base64) or multipart form bodies. */
async function parseUploadBody(
  req: Request,
): Promise<
  | { ok: true; title: string; doc_type: string; mime_type: string; content: Uint8Array }
  | { ok: false; response: Response }
> {
  const ct = req.headers.get("content-type") ?? "";
  try {
    if (ct.includes("multipart/form-data")) {
      const form = await req.formData();
      const file = form.get("file");
      if (!(file instanceof File)) {
        return {
          ok: false,
          response: errorResponse("validation", "multipart upload requires a 'file' field", 400),
        };
      }
      const title = String(form.get("title") ?? file.name ?? "").trim();
      return {
        ok: true,
        title: title || "untitled",
        doc_type: String(form.get("doc_type") ?? "other"),
        mime_type: file.type || "application/octet-stream",
        content: new Uint8Array(await file.arrayBuffer()),
      };
    }
    const parsed = await parseJsonBody(req);
    if (!parsed.ok) return parsed;
    const b = parsed.body;
    if (typeof b.content_base64 !== "string" || !b.content_base64) {
      return {
        ok: false,
        response: errorResponse("validation", "content_base64 is required", 400),
      };
    }
    let content: Uint8Array;
    try {
      content = new Uint8Array(Buffer.from(b.content_base64, "base64"));
    } catch {
      return {
        ok: false,
        response: errorResponse("validation", "content_base64 is not valid base64", 400),
      };
    }
    return {
      ok: true,
      title: String(b.title ?? "untitled"),
      doc_type: String(b.doc_type ?? "other"),
      mime_type: typeof b.mime_type === "string" ? b.mime_type : "application/octet-stream",
      content,
    };
  } catch {
    return {
      ok: false,
      response: errorResponse("validation", "could not parse upload body", 400),
    };
  }
}

/** All /api/v1/documents/* routes (WORM store, F-R2/F-R3/F-R4). */
function handleDocuments(
  req: Request,
  db: Database,
  cfg: SessionConfig,
  url: URL,
): Promise<Response> | Response {
  const perm = (
    action: string,
    handler: (req: Request, ctx: Ctx, url: URL) => Promise<Response> | Response,
  ): Handler =>
    withPerm(db, cfg, "documents", action, (req2, ctx) => {
      if (!ctx) return errorResponse("unauthorized", "missing session", 401);
      return handler(req2, ctx, url);
    });

  const sub = url.pathname.slice("/api/v1/documents/".length);
  const parts = sub.split("/").filter((p) => p !== "");

  // --- collection ---
  if (parts.length === 0) {
    if (req.method === "GET") {
      return perm("read", () => {
        const page = parseQueryInt(url, "page", 1);
        const per_page = parseQueryInt(url, "per_page", 50);
        const { rows, total } = listDocuments(db, {
          doc_type: url.searchParams.get("doc_type") ?? undefined,
          page,
          per_page,
        });
        return Response.json({ data: rows, meta: { page, per_page, total } });
      })(req);
    }
    if (req.method === "POST") {
      return perm("write", async (req2, ctx) => {
        const up = await parseUploadBody(req2);
        if (!up.ok) return up.response;
        try {
          // Async crypto happens BEFORE the transaction (bun:sqlite txns are sync).
          const prepared = await prepareDocument(db, {
            title: up.title,
            doc_type: up.doc_type,
            mime_type: up.mime_type,
            content: up.content,
            actor_id: ctx.user.id,
          });
          if (prepared.deduped) {
            const meta = getDocument(db, prepared.existingId!);
            return jsonResponse({ ...meta, deduped: true });
          }
          let meta!: DocumentMeta;
          // Direct transaction (not mutateWithAudit): the audit row needs the
          // inserted id as entity_id, known only after insertDocument runs.
          db.transaction(() => {
            meta = insertDocument(db, prepared);
            appendAudit(db, {
              actor_id: ctx.user.id,
              action: "document.upload",
              entity_type: "document",
              entity_id: String(meta.id),
              before: null,
              after: {
                title: prepared.meta.title,
                doc_type: prepared.meta.doc_type,
                size_bytes: prepared.meta.size_bytes,
                content_sha256: prepared.meta.content_sha256,
                retain_until: prepared.meta.retain_until,
              },
            });
          })();
          return Response.json({ data: meta }, { status: 201 });
        } catch (e) {
          return documentError(e);
        }
      })(req);
    }
    return errorResponse("not_found", "not found", 404);
  }

  const id = parseIdParam(parts, 0);
  if (id === null) return errorResponse("validation", "document id must be a positive integer", 400);

  // --- download ---
  if (parts.length === 2 && parts[1] === "content" && req.method === "GET") {
    return perm("read", async () => {
      try {
        const { meta, bytes } = await getDocumentContent(db, id);
        return new Response(bytes as BodyInit, {
          headers: {
            "content-type": meta.mime_type,
            "content-length": String(bytes.length),
            etag: `"${meta.content_sha256}"`,
            "content-disposition": `attachment; filename="${safeFilename(meta.title)}"`,
          },
        });
      } catch (e) {
        return documentError(e);
      }
    })(req);
  }

  // --- item ---
  if (parts.length === 1) {
    if (req.method === "GET") {
      return perm("read", () => {
        const meta = getDocument(db, id);
        return meta ? jsonResponse(meta) : errorResponse("not_found", "document not found", 404);
      })(req);
    }
    if (req.method === "DELETE") {
      return perm("write", (_req2, ctx) => {
        try {
          const before = getDocument(db, id);
          if (!before) return errorResponse("not_found", "document not found", 404);
          mutateWithAudit(
            db,
            {
              actor_id: ctx.user.id,
              action: "document.delete",
              entity_type: "document",
              entity_id: id,
              before: { title: before.title, content_sha256: before.content_sha256 },
            },
            () => deleteDocument(db, id),
          );
          return jsonResponse({ deleted: true });
        } catch (e) {
          if (e instanceof RetentionError) {
            // Denied deletions are security-relevant: audit the attempt.
            appendAudit(db, {
              actor_id: ctx.user.id,
              action: "document.delete_denied",
              entity_type: "document",
              entity_id: id,
              after: { reason: "retained" },
            });
          }
          return documentError(e);
        }
      })(req);
    }
    return errorResponse("not_found", "not found", 404);
  }

  return errorResponse("not_found", "not found", 404);
}

/** All /api/v1/compliance/* routes beyond audit-log (F-R4). */
function handleCompliance(
  req: Request,
  db: Database,
  cfg: SessionConfig,
  url: URL,
): Promise<Response> | Response {
  const perm = (
    action: string,
    handler: (req: Request, ctx: Ctx, url: URL) => Promise<Response> | Response,
  ): Handler =>
    withPerm(db, cfg, "audit", action, (req2, ctx) => {
      if (!ctx) return errorResponse("unauthorized", "missing session", 401);
      return handler(req2, ctx, url);
    });

  const sub = url.pathname.slice("/api/v1/compliance/".length);

  if (sub === "retention-report" && req.method === "GET") {
    return perm("read", () => jsonResponse(retentionReport(db)))(req);
  }

  if (sub === "verify" && req.method === "GET") {
    return perm("read", async () => jsonResponse(await verifyAll(db)))(req);
  }

  if (sub === "export" && req.method === "GET") {
    return perm("read", () => {
      const entity = url.searchParams.get("entity_type") ?? "audit_log";
      if (entity !== "audit_log" && entity !== "documents" && entity !== "journal_entries") {
        return errorResponse(
          "validation",
          "entity_type must be audit_log, documents, or journal_entries",
          400,
        );
      }
      const format = url.searchParams.get("format") ?? "json";
      if (format !== "json" && format !== "csv") {
        return errorResponse("validation", "format must be json or csv", 400);
      }
      const idParam = url.searchParams.get("entity_id");
      const entity_id = idParam === null ? null : parseInt(idParam, 10);
      if (idParam !== null && (!Number.isInteger(entity_id) || (entity_id as number) <= 0)) {
        return errorResponse("validation", "entity_id must be a positive integer", 400);
      }
      try {
        const out = exportRecords(db, entity, entity_id, format);
        return new Response(out.body as BodyInit, {
          headers: {
            "content-type": out.contentType,
            "content-disposition": `attachment; filename="${out.filename}"`,
          },
        });
      } catch (e) {
        return documentError(e);
      }
    })(req);
  }

  return errorResponse("not_found", "not found", 404);
}

/** All /api/v1/ar/* routes (Phase 3: customers, invoices, payments, credit memos). */
function handleAr(
  req: Request,
  db: Database,
  cfg: SessionConfig,
  url: URL,
): Promise<Response> | Response {
  const perm = (
    action: string,
    handler: (req: Request, ctx: Ctx, url: URL) => Promise<Response> | Response,
  ): Handler =>
    withPerm(db, cfg, "ar", action, (req2, ctx) => {
      if (!ctx) return errorResponse("unauthorized", "missing session", 401);
      return handler(req2, ctx, url);
    });

  const sub = url.pathname.slice("/api/v1/ar/".length);
  const parts = sub.split("/").filter((p) => p !== "");
  const num = (v: unknown): number | undefined => (typeof v === "number" ? v : undefined);
  const str = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);

  // --- customers ---
  if (parts[0] === "customers") {
    if (parts.length === 1) {
      if (req.method === "GET") {
        return perm("read", () => {
          try {
            return jsonResponse(listCustomers(db, { status: url.searchParams.get("status") ?? undefined }));
          } catch (e) {
            return arError(e);
          }
        })(req);
      }
      if (req.method === "POST") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            const created = createCustomer(
              db,
              {
                name: str(b.name) ?? "",
                email: (b.email ?? null) as string | null,
                phone: (b.phone ?? null) as string | null,
                billing_address: (b.billing_address ?? null) as string | null,
                credit_limit_cents: num(b.credit_limit_cents),
                status: str(b.status),
              },
              ctx.user.id,
            );
            return Response.json({ data: created }, { status: 201 });
          } catch (e) {
            return arError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    const id = parseIdParam(parts, 1);
    if (id === null) return errorResponse("validation", "customer id must be a positive integer", 400);
    if (parts.length === 2) {
      if (req.method === "GET") {
        return perm("read", () => {
          const c = getCustomer(db, id);
          return c ? jsonResponse(c) : errorResponse("not_found", "customer not found", 404);
        })(req);
      }
      if (req.method === "PATCH") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            const updated = updateCustomer(
              db,
              id,
              {
                name: str(b.name),
                email: b.email === undefined ? undefined : (b.email as string | null),
                phone: b.phone === undefined ? undefined : (b.phone as string | null),
                billing_address:
                  b.billing_address === undefined ? undefined : (b.billing_address as string | null),
                credit_limit_cents: num(b.credit_limit_cents),
                status: str(b.status),
              },
              ctx.user.id,
            );
            return jsonResponse(updated);
          } catch (e) {
            return arError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    return errorResponse("not_found", "not found", 404);
  }

  // --- invoices ---
  if (parts[0] === "invoices") {
    if (parts.length === 1) {
      if (req.method === "GET") {
        return perm("read", () => {
          try {
            const customer_id = url.searchParams.get("customer_id");
            return jsonResponse(
              listInvoices(db, {
                customer_id: customer_id ? parseInt(customer_id, 10) || undefined : undefined,
                status: url.searchParams.get("status") ?? undefined,
              }),
            );
          } catch (e) {
            return arError(e);
          }
        })(req);
      }
      if (req.method === "POST") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            const created = createInvoice(
              db,
              {
                customer_id: num(b.customer_id) ?? 0,
                issue_date: str(b.issue_date) ?? "",
                due_date: str(b.due_date) ?? "",
                tax_cents: num(b.tax_cents),
                lines: Array.isArray(b.lines) ? b.lines : [],
              },
              ctx.user.id,
            );
            return Response.json({ data: created }, { status: 201 });
          } catch (e) {
            return arError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    const id = parseIdParam(parts, 1);
    if (id === null) return errorResponse("validation", "invoice id must be a positive integer", 400);
    if (parts.length === 2) {
      if (req.method === "GET") {
        return perm("read", () => {
          const v = getInvoice(db, id);
          return v ? jsonResponse(v) : errorResponse("not_found", "invoice not found", 404);
        })(req);
      }
      if (req.method === "PATCH") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            const updated = updateInvoiceDraft(
              db,
              id,
              {
                due_date: str(b.due_date),
                tax_cents: num(b.tax_cents),
                lines: Array.isArray(b.lines) ? b.lines : undefined,
              },
              ctx.user.id,
            );
            return jsonResponse(updated);
          } catch (e) {
            return arError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    if (parts.length === 3 && req.method === "POST") {
      if (parts[2] === "post") {
        return perm("post", async (req2, ctx) => {
          const parsed = await parseJsonBodyLenient(req2);
          if (!parsed.ok) return parsed.response;
          return runArMutation(req2, db, ctx, `invoice-post:${id}`, `/api/v1/ar/invoices/${id}/post`, () => ({
            status: 200,
            body: { data: postInvoice(db, id, ctx.user.id) },
          }));
        })(req);
      }
      if (parts[2] === "void") {
        return perm("approve", async (req2, ctx) => {
          const parsed = await parseJsonBodyLenient(req2);
          if (!parsed.ok) return parsed.response;
          return runArMutation(req2, db, ctx, `invoice-void:${id}`, `/api/v1/ar/invoices/${id}/void`, () => ({
            status: 200,
            body: { data: voidInvoice(db, id, ctx.user.id) },
          }));
        })(req);
      }
    }
    return errorResponse("not_found", "not found", 404);
  }

  // --- payments ---
  if (parts[0] === "payments") {
    if (parts.length === 1) {
      if (req.method === "GET") {
        return perm("read", () => {
          const customer_id = url.searchParams.get("customer_id");
          return jsonResponse(
            listPayments(db, {
              customer_id: customer_id ? parseInt(customer_id, 10) || undefined : undefined,
            }),
          );
        })(req);
      }
      if (req.method === "POST") {
        return perm("post", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          return runArMutation(req2, db, ctx, "payment-create", "/api/v1/ar/payments", () => ({
            status: 201,
            body: {
              data: createPayment(
                db,
                {
                  customer_id: num(b.customer_id) ?? 0,
                  method: str(b.method) ?? "",
                  amount_cents: num(b.amount_cents) ?? 0,
                  received_on: str(b.received_on) ?? "",
                  applications: Array.isArray(b.applications) ? b.applications : undefined,
                },
                ctx.user.id,
              ),
            },
          }));
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    const id = parseIdParam(parts, 1);
    if (id === null) return errorResponse("validation", "payment id must be a positive integer", 400);
    if (parts.length === 2 && req.method === "GET") {
      return perm("read", () => {
        const v = getPayment(db, id);
        return v ? jsonResponse(v) : errorResponse("not_found", "payment not found", 404);
      })(req);
    }
    if (parts.length === 3 && parts[2] === "apply" && req.method === "POST") {
      return perm("post", async (req2, ctx) => {
        const parsed = await parseJsonBody(req2);
        if (!parsed.ok) return parsed.response;
        const b = parsed.body;
        return runArMutation(req2, db, ctx, `payment-apply:${id}`, `/api/v1/ar/payments/${id}/apply`, () => ({
          status: 200,
          body: {
            data: applyPayment(db, id, num(b.invoice_id) ?? 0, num(b.amount_cents) ?? 0, ctx.user.id),
          },
        }));
      })(req);
    }
    return errorResponse("not_found", "not found", 404);
  }

  // --- credit memos ---
  if (parts[0] === "credit-memos") {
    if (parts.length === 1) {
      if (req.method === "GET") {
        return perm("read", () => {
          const customer_id = url.searchParams.get("customer_id");
          const invoice_id = url.searchParams.get("invoice_id");
          return jsonResponse(
            listCreditMemos(db, {
              customer_id: customer_id ? parseInt(customer_id, 10) || undefined : undefined,
              invoice_id: invoice_id ? parseInt(invoice_id, 10) || undefined : undefined,
            }),
          );
        })(req);
      }
      if (req.method === "POST") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            const created = createCreditMemo(
              db,
              {
                customer_id: num(b.customer_id) ?? 0,
                invoice_id: num(b.invoice_id) ?? 0,
                amount_cents: num(b.amount_cents) ?? 0,
                reason: str(b.reason) ?? "",
              },
              ctx.user.id,
            );
            return Response.json({ data: created }, { status: 201 });
          } catch (e) {
            return arError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    const id = parseIdParam(parts, 1);
    if (id === null) return errorResponse("validation", "credit memo id must be a positive integer", 400);
    if (parts.length === 2 && req.method === "GET") {
      return perm("read", () => {
        const v = getCreditMemo(db, id);
        return v ? jsonResponse(v) : errorResponse("not_found", "credit memo not found", 404);
      })(req);
    }
    if (parts.length === 3 && req.method === "POST") {
      if (parts[2] === "post") {
        return perm("post", async (req2, ctx) => {
          const parsed = await parseJsonBodyLenient(req2);
          if (!parsed.ok) return parsed.response;
          return runArMutation(req2, db, ctx, `cm-post:${id}`, `/api/v1/ar/credit-memos/${id}/post`, () => ({
            status: 200,
            body: { data: postCreditMemo(db, id, ctx.user.id) },
          }));
        })(req);
      }
      if (parts[2] === "void") {
        return perm("approve", async (req2, ctx) => {
          const parsed = await parseJsonBodyLenient(req2);
          if (!parsed.ok) return parsed.response;
          return runArMutation(req2, db, ctx, `cm-void:${id}`, `/api/v1/ar/credit-memos/${id}/void`, () => ({
            status: 200,
            body: { data: voidCreditMemo(db, id, ctx.user.id) },
          }));
        })(req);
      }
    }
    return errorResponse("not_found", "not found", 404);
  }

  return errorResponse("not_found", "not found", 404);
}

/** All /api/v1/ap/* routes (Phase 4: vendors, bills with maker-checker approval, bill payments). */
function handleAp(
  req: Request,
  db: Database,
  cfg: SessionConfig,
  url: URL,
): Promise<Response> | Response {
  const perm = (
    action: string,
    handler: (req: Request, ctx: Ctx, url: URL) => Promise<Response> | Response,
  ): Handler =>
    withPerm(db, cfg, "ap", action, (req2, ctx) => {
      if (!ctx) return errorResponse("unauthorized", "missing session", 401);
      return handler(req2, ctx, url);
    });

  const sub = url.pathname.slice("/api/v1/ap/".length);
  const parts = sub.split("/").filter((p) => p !== "");
  const num = (v: unknown): number | undefined => (typeof v === "number" ? v : undefined);
  const str = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);

  // --- vendors ---
  if (parts[0] === "vendors") {
    if (parts.length === 1) {
      if (req.method === "GET") {
        return perm("read", () => {
          try {
            return jsonResponse(listVendors(db, { status: url.searchParams.get("status") ?? undefined }));
          } catch (e) {
            return apError(e);
          }
        })(req);
      }
      if (req.method === "POST") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            const created = createVendor(
              db,
              {
                name: str(b.name) ?? "",
                email: (b.email ?? null) as string | null,
                phone: (b.phone ?? null) as string | null,
                remittance_address: (b.remittance_address ?? null) as string | null,
                status: str(b.status),
              },
              ctx.user.id,
            );
            return Response.json({ data: created }, { status: 201 });
          } catch (e) {
            return apError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    const id = parseIdParam(parts, 1);
    if (id === null) return errorResponse("validation", "vendor id must be a positive integer", 400);
    if (parts.length === 2) {
      if (req.method === "GET") {
        return perm("read", () => {
          const v = getVendor(db, id);
          return v ? jsonResponse(v) : errorResponse("not_found", "vendor not found", 404);
        })(req);
      }
      if (req.method === "PATCH") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            const updated = updateVendor(
              db,
              id,
              {
                name: str(b.name),
                email: b.email === undefined ? undefined : (b.email as string | null),
                phone: b.phone === undefined ? undefined : (b.phone as string | null),
                remittance_address:
                  b.remittance_address === undefined ? undefined : (b.remittance_address as string | null),
                status: str(b.status),
              },
              ctx.user.id,
            );
            return jsonResponse(updated);
          } catch (e) {
            return apError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    return errorResponse("not_found", "not found", 404);
  }

  // --- bills ---
  if (parts[0] === "bills") {
    if (parts.length === 1) {
      if (req.method === "GET") {
        return perm("read", () => {
          try {
            const vendor_id = url.searchParams.get("vendor_id");
            return jsonResponse(
              listBills(db, {
                vendor_id: vendor_id ? parseInt(vendor_id, 10) || undefined : undefined,
                status: url.searchParams.get("status") ?? undefined,
              }),
            );
          } catch (e) {
            return apError(e);
          }
        })(req);
      }
      if (req.method === "POST") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            const created = createBill(
              db,
              {
                vendor_id: num(b.vendor_id) ?? 0,
                bill_date: str(b.bill_date) ?? "",
                due_date: str(b.due_date) ?? "",
                tax_cents: num(b.tax_cents),
                lines: Array.isArray(b.lines) ? b.lines : [],
              },
              ctx.user.id,
            );
            return Response.json({ data: created }, { status: 201 });
          } catch (e) {
            return apError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    const id = parseIdParam(parts, 1);
    if (id === null) return errorResponse("validation", "bill id must be a positive integer", 400);
    if (parts.length === 2) {
      if (req.method === "GET") {
        return perm("read", () => {
          const v = getBill(db, id);
          return v ? jsonResponse(v) : errorResponse("not_found", "bill not found", 404);
        })(req);
      }
      if (req.method === "PATCH") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            const updated = updateBillDraft(
              db,
              id,
              {
                due_date: str(b.due_date),
                tax_cents: num(b.tax_cents),
                lines: Array.isArray(b.lines) ? b.lines : undefined,
              },
              ctx.user.id,
            );
            return jsonResponse(updated);
          } catch (e) {
            return apError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    if (parts.length === 3 && req.method === "POST") {
      if (parts[2] === "approve") {
        return perm("approve", async (req2, ctx) => {
          const parsed = await parseJsonBodyLenient(req2);
          if (!parsed.ok) return parsed.response;
          try {
            return jsonResponse(approveBill(db, id, ctx.user.id));
          } catch (e) {
            return apError(e);
          }
        })(req);
      }
      if (parts[2] === "post") {
        return perm("post", async (req2, ctx) => {
          const parsed = await parseJsonBodyLenient(req2);
          if (!parsed.ok) return parsed.response;
          return runApMutation(req2, db, ctx, `bill-post:${id}`, `/api/v1/ap/bills/${id}/post`, () => ({
            status: 200,
            body: { data: postBill(db, id, ctx.user.id) },
          }));
        })(req);
      }
      if (parts[2] === "void") {
        return perm("approve", async (req2, ctx) => {
          const parsed = await parseJsonBodyLenient(req2);
          if (!parsed.ok) return parsed.response;
          return runApMutation(req2, db, ctx, `bill-void:${id}`, `/api/v1/ap/bills/${id}/void`, () => ({
            status: 200,
            body: { data: voidBill(db, id, ctx.user.id) },
          }));
        })(req);
      }
    }
    return errorResponse("not_found", "not found", 404);
  }

  // --- bill payments ---
  if (parts[0] === "bill-payments") {
    if (parts.length === 1) {
      if (req.method === "GET") {
        return perm("read", () => {
          const vendor_id = url.searchParams.get("vendor_id");
          return jsonResponse(
            listBillPayments(db, {
              vendor_id: vendor_id ? parseInt(vendor_id, 10) || undefined : undefined,
            }),
          );
        })(req);
      }
      if (req.method === "POST") {
        return perm("post", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          return runApMutation(req2, db, ctx, "bill-payment-create", "/api/v1/ap/bill-payments", () => ({
            status: 201,
            body: {
              data: createBillPayment(
                db,
                {
                  vendor_id: num(b.vendor_id) ?? 0,
                  method: str(b.method) ?? "",
                  amount_cents: num(b.amount_cents) ?? 0,
                  paid_on: str(b.paid_on) ?? "",
                  applications: Array.isArray(b.applications) ? b.applications : undefined,
                },
                ctx.user.id,
              ),
            },
          }));
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    const id = parseIdParam(parts, 1);
    if (id === null) return errorResponse("validation", "bill payment id must be a positive integer", 400);
    if (parts.length === 2 && req.method === "GET") {
      return perm("read", () => {
        const v = getBillPayment(db, id);
        return v ? jsonResponse(v) : errorResponse("not_found", "bill payment not found", 404);
      })(req);
    }
    if (parts.length === 3 && parts[2] === "apply" && req.method === "POST") {
      return perm("post", async (req2, ctx) => {
        const parsed = await parseJsonBody(req2);
        if (!parsed.ok) return parsed.response;
        const b = parsed.body;
        return runApMutation(req2, db, ctx, `bill-payment-apply:${id}`, `/api/v1/ap/bill-payments/${id}/apply`, () => ({
          status: 200,
          body: {
            data: applyBillPayment(db, id, num(b.bill_id) ?? 0, num(b.amount_cents) ?? 0, ctx.user.id),
          },
        }));
      })(req);
    }
    return errorResponse("not_found", "not found", 404);
  }

  return errorResponse("not_found", "not found", 404);
}

/** All /api/v1/inventory/* routes (Phase 5: items, warehouses, movements, levels). */
function handleInventory(
  req: Request,
  db: Database,
  cfg: SessionConfig,
  url: URL,
): Promise<Response> | Response {
  const perm = (
    action: string,
    handler: (req: Request, ctx: Ctx, url: URL) => Promise<Response> | Response,
  ): Handler =>
    withPerm(db, cfg, "inventory", action, (req2, ctx) => {
      if (!ctx) return errorResponse("unauthorized", "missing session", 401);
      return handler(req2, ctx, url);
    });

  const sub = url.pathname.slice("/api/v1/inventory/".length);
  const parts = sub.split("/").filter((p) => p !== "");
  const num = (v: unknown): number | undefined => (typeof v === "number" ? v : undefined);
  const str = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);

  // --- items ---
  if (parts[0] === "items") {
    if (parts.length === 1) {
      if (req.method === "GET") {
        return perm("read", () => {
          try {
            return jsonResponse(listItems(db, { status: url.searchParams.get("status") ?? undefined }));
          } catch (e) {
            return inventoryError(e);
          }
        })(req);
      }
      if (req.method === "POST") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            const created = createItem(
              db,
              {
                sku: str(b.sku) ?? "",
                name: str(b.name) ?? "",
                description: (b.description ?? null) as string | null,
                unit: str(b.unit),
                allow_negative_stock: typeof b.allow_negative_stock === "boolean" ? b.allow_negative_stock : undefined,
                inventory_account_code: str(b.inventory_account_code),
                cogs_account_code: str(b.cogs_account_code),
                status: str(b.status),
              },
              ctx.user.id,
            );
            return Response.json({ data: created }, { status: 201 });
          } catch (e) {
            return inventoryError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    const id = parseIdParam(parts, 1);
    if (id === null) return errorResponse("validation", "item id must be a positive integer", 400);
    if (parts.length === 2) {
      if (req.method === "GET") {
        return perm("read", () => {
          const v = getItem(db, id);
          return v ? jsonResponse(v) : errorResponse("not_found", "item not found", 404);
        })(req);
      }
      if (req.method === "PATCH") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            const updated = updateItem(
              db,
              id,
              {
                sku: str(b.sku),
                name: str(b.name),
                description: b.description === undefined ? undefined : (b.description as string | null),
                unit: str(b.unit),
                allow_negative_stock: typeof b.allow_negative_stock === "boolean" ? b.allow_negative_stock : undefined,
                inventory_account_code: str(b.inventory_account_code),
                cogs_account_code: str(b.cogs_account_code),
                status: str(b.status),
              },
              ctx.user.id,
            );
            return jsonResponse(updated);
          } catch (e) {
            return inventoryError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    return errorResponse("not_found", "not found", 404);
  }

  // --- warehouses ---
  if (parts[0] === "warehouses") {
    if (parts.length === 1) {
      if (req.method === "GET") {
        return perm("read", () => jsonResponse(listWarehouses(db)))(req);
      }
      if (req.method === "POST") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            const created = createWarehouse(
              db,
              {
                code: str(b.code) ?? "",
                name: str(b.name) ?? "",
                location: (b.location ?? null) as string | null,
              },
              ctx.user.id,
            );
            return Response.json({ data: created }, { status: 201 });
          } catch (e) {
            return inventoryError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    const id = parseIdParam(parts, 1);
    if (id === null) return errorResponse("validation", "warehouse id must be a positive integer", 400);
    if (parts.length === 2) {
      if (req.method === "GET") {
        return perm("read", () => {
          const v = getWarehouse(db, id);
          return v ? jsonResponse(v) : errorResponse("not_found", "warehouse not found", 404);
        })(req);
      }
      if (req.method === "PATCH") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            const updated = updateWarehouse(
              db,
              id,
              {
                code: str(b.code),
                name: str(b.name),
                location: b.location === undefined ? undefined : (b.location as string | null),
              },
              ctx.user.id,
            );
            return jsonResponse(updated);
          } catch (e) {
            return inventoryError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    return errorResponse("not_found", "not found", 404);
  }

  // --- movements ---
  if (parts[0] === "movements") {
    if (parts.length === 1 && req.method === "GET") {
      return perm("read", () => {
        try {
          const item_id = url.searchParams.get("item_id");
          const warehouse_id = url.searchParams.get("warehouse_id");
          return jsonResponse(
            listMovements(db, {
              item_id: item_id ? parseInt(item_id, 10) || undefined : undefined,
              warehouse_id: warehouse_id ? parseInt(warehouse_id, 10) || undefined : undefined,
              movement_type: url.searchParams.get("movement_type") ?? undefined,
            }),
          );
        } catch (e) {
          return inventoryError(e);
        }
      })(req);
    }
    if (parts.length === 2 && req.method === "POST") {
      if (parts[1] === "receipt") {
        return perm("post", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          return runInventoryMutation(req2, db, ctx, "stock-receipt", "/api/v1/inventory/movements/receipt", () => ({
            status: 201,
            body: {
              data: receiveStock(
                db,
                {
                  item_id: num(b.item_id) ?? 0,
                  warehouse_id: num(b.warehouse_id) ?? 0,
                  quantity: num(b.quantity) ?? 0,
                  unit_cost_cents: num(b.unit_cost_cents) ?? 0,
                  movement_date: str(b.movement_date),
                  reason: (b.reason ?? null) as string | null,
                  source_type: str(b.source_type),
                  source_id: str(b.source_id),
                },
                ctx.user.id,
              ),
            },
          }));
        })(req);
      }
      if (parts[1] === "issue") {
        return perm("post", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          return runInventoryMutation(req2, db, ctx, "stock-issue", "/api/v1/inventory/movements/issue", () => ({
            status: 201,
            body: {
              data: issueStock(
                db,
                {
                  item_id: num(b.item_id) ?? 0,
                  warehouse_id: num(b.warehouse_id) ?? 0,
                  quantity: num(b.quantity) ?? 0,
                  movement_date: str(b.movement_date),
                  reason: (b.reason ?? null) as string | null,
                  source_type: str(b.source_type),
                  source_id: str(b.source_id),
                },
                ctx.user.id,
              ),
            },
          }));
        })(req);
      }
      if (parts[1] === "adjust") {
        return perm("post", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          return runInventoryMutation(req2, db, ctx, "stock-adjust", "/api/v1/inventory/movements/adjust", () => ({
            status: 201,
            body: {
              data: adjustStock(
                db,
                {
                  item_id: num(b.item_id) ?? 0,
                  warehouse_id: num(b.warehouse_id) ?? 0,
                  quantity: num(b.quantity) ?? 0,
                  unit_cost_cents: num(b.unit_cost_cents),
                  movement_date: str(b.movement_date),
                  reason: str(b.reason) ?? "",
                  source_type: str(b.source_type),
                  source_id: str(b.source_id),
                },
                ctx.user.id,
              ),
            },
          }));
        })(req);
      }
      if (parts[1] === "transfer") {
        return perm("post", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          return runInventoryMutation(req2, db, ctx, "stock-transfer", "/api/v1/inventory/movements/transfer", () => ({
            status: 201,
            body: {
              data: transferStock(
                db,
                {
                  item_id: num(b.item_id) ?? 0,
                  from_warehouse_id: num(b.from_warehouse_id) ?? 0,
                  to_warehouse_id: num(b.to_warehouse_id) ?? 0,
                  quantity: num(b.quantity) ?? 0,
                  movement_date: str(b.movement_date),
                  reason: (b.reason ?? null) as string | null,
                },
                ctx.user.id,
              ),
            },
          }));
        })(req);
      }
    }
    return errorResponse("not_found", "not found", 404);
  }

  // --- levels ---
  if (parts[0] === "levels" && parts.length === 1 && req.method === "GET") {
    return perm("read", () => {
      const item_id = url.searchParams.get("item_id");
      const warehouse_id = url.searchParams.get("warehouse_id");
      return jsonResponse(
        listStockLevels(db, {
          item_id: item_id ? parseInt(item_id, 10) || undefined : undefined,
          warehouse_id: warehouse_id ? parseInt(warehouse_id, 10) || undefined : undefined,
        }),
      );
    })(req);
  }

  return errorResponse("not_found", "not found", 404);
}

/** All /api/v1/procurement/* routes (Phase 6: purchase orders, receivings). */
function handleProcurement(
  req: Request,
  db: Database,
  cfg: SessionConfig,
  url: URL,
): Promise<Response> | Response {
  const perm = (
    action: string,
    handler: (req: Request, ctx: Ctx, url: URL) => Promise<Response> | Response,
  ): Handler =>
    withPerm(db, cfg, "procurement", action, (req2, ctx) => {
      if (!ctx) return errorResponse("unauthorized", "missing session", 401);
      return handler(req2, ctx, url);
    });

  const sub = url.pathname.slice("/api/v1/procurement/".length);
  const parts = sub.split("/").filter((p) => p !== "");
  const num = (v: unknown): number | undefined => (typeof v === "number" ? v : undefined);
  const str = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);

  // --- purchase orders ---
  if (parts[0] === "purchase-orders") {
    if (parts.length === 1) {
      if (req.method === "GET") {
        return perm("read", () => {
          try {
            const vendor_id = url.searchParams.get("vendor_id");
            return jsonResponse(
              listPurchaseOrders(db, {
                vendor_id: vendor_id ? parseInt(vendor_id, 10) || undefined : undefined,
                status: url.searchParams.get("status") ?? undefined,
              }),
            );
          } catch (e) {
            return procurementError(e);
          }
        })(req);
      }
      if (req.method === "POST") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            const created = createPurchaseOrder(
              db,
              {
                vendor_id: num(b.vendor_id) ?? 0,
                order_date: str(b.order_date) ?? "",
                expected_date: (b.expected_date ?? null) as string | null,
                notes: (b.notes ?? null) as string | null,
                lines: (Array.isArray(b.lines) ? b.lines : []) as {
                  item_id: number;
                  quantity_ordered: number;
                  unit_cost_cents: number;
                }[],
              },
              ctx.user.id,
            );
            return Response.json({ data: created }, { status: 201 });
          } catch (e) {
            return procurementError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    const id = parseIdParam(parts, 1);
    if (id === null) return errorResponse("validation", "purchase order id must be a positive integer", 400);
    if (parts.length === 2) {
      if (req.method === "GET") {
        return perm("read", () => {
          const v = getPurchaseOrder(db, id);
          return v ? jsonResponse(v) : errorResponse("not_found", "purchase order not found", 404);
        })(req);
      }
      if (req.method === "PATCH") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            const updated = updatePurchaseOrderDraft(
              db,
              id,
              {
                vendor_id: num(b.vendor_id),
                order_date: str(b.order_date),
                expected_date: b.expected_date === undefined ? undefined : (b.expected_date as string | null),
                notes: b.notes === undefined ? undefined : (b.notes as string | null),
                lines: Array.isArray(b.lines)
                  ? (b.lines as { item_id: number; quantity_ordered: number; unit_cost_cents: number }[])
                  : undefined,
              },
              ctx.user.id,
            );
            return jsonResponse(updated);
          } catch (e) {
            return procurementError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    if (parts.length === 3 && req.method === "POST") {
      const action = parts[2];
      if (action === "submit" || action === "close" || action === "cancel") {
        return perm("write", async (_req2, ctx) => {
          try {
            const fn =
              action === "submit"
                ? submitPurchaseOrder
                : action === "close"
                  ? closePurchaseOrder
                  : cancelPurchaseOrder;
            return jsonResponse(fn(db, id, ctx.user.id));
          } catch (e) {
            return procurementError(e);
          }
        })(req);
      }
      if (action === "receive") {
        return perm("post", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          return runProcurementMutation(req2, db, ctx, `po-receive:${id}`, `/api/v1/procurement/purchase-orders/${id}/receive`, () => ({
            status: 201,
            body: {
              data: receivePurchaseOrder(
                db,
                id,
                {
                  warehouse_id: num(b.warehouse_id) ?? 0,
                  receiving_date: str(b.receiving_date),
                  lines: (Array.isArray(b.lines) ? b.lines : []) as {
                    po_line_id: number;
                    quantity: number;
                  }[],
                },
                ctx.user.id,
              ),
            },
          }));
        })(req);
      }
    }
    return errorResponse("not_found", "not found", 404);
  }

  // --- receivings (read-only surface; created via PO receive) ---
  if (parts[0] === "receivings") {
    if (parts.length === 1 && req.method === "GET") {
      return perm("read", () => {
        const po_id = url.searchParams.get("po_id");
        const warehouse_id = url.searchParams.get("warehouse_id");
        return jsonResponse(
          listReceivings(db, {
            po_id: po_id ? parseInt(po_id, 10) || undefined : undefined,
            warehouse_id: warehouse_id ? parseInt(warehouse_id, 10) || undefined : undefined,
          }),
        );
      })(req);
    }
    const id = parseIdParam(parts, 1);
    if (id === null) return errorResponse("validation", "receiving id must be a positive integer", 400);
    if (parts.length === 2 && req.method === "GET") {
      return perm("read", () => {
        const v = getReceiving(db, id);
        return v ? jsonResponse(v) : errorResponse("not_found", "receiving not found", 404);
      })(req);
    }
    return errorResponse("not_found", "not found", 404);
  }

  return errorResponse("not_found", "not found", 404);
}

/** Map a CrmError to the stable error envelope; rethrow anything else. */
function crmError(e: unknown): Response {
  if (e instanceof CrmError) {
    const status =
      {
        validation: 400,
        not_found: 404,
        self_review: 403,
        not_principal: 403,
        not_flagged: 409,
        already_reviewed: 409,
        already_principal: 409,
        state_regression: 409,
        terminal_stage: 409,
      }[e.code] ?? 400;
    return errorResponse(e.code, e.message, status);
  }
  throw e;
}

/** All /api/v1/crm/* routes (Phase 7: companies, contacts, deals, activities,
 *  principal review queue, supervisory personnel, complaints). */
function handleCrm(
  req: Request,
  db: Database,
  cfg: SessionConfig,
  url: URL,
): Promise<Response> | Response {
  const perm = (
    action: string,
    handler: (req: Request, ctx: Ctx, url: URL) => Promise<Response> | Response,
  ): Handler =>
    withPerm(db, cfg, "crm", action, (req2, ctx) => {
      if (!ctx) return errorResponse("unauthorized", "missing session", 401);
      return handler(req2, ctx, url);
    });

  const sub = url.pathname.slice("/api/v1/crm/".length);
  const parts = sub.split("/").filter((p) => p !== "");
  const num = (v: unknown): number | undefined => (typeof v === "number" ? v : undefined);
  const str = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);
  const nul = (v: unknown): string | null =>
    v === undefined ? null : typeof v === "string" ? v : null;
  const qint = (name: string): number | undefined => {
    const v = url.searchParams.get(name);
    return v ? parseInt(v, 10) || undefined : undefined;
  };

  // --- companies ---
  if (parts[0] === "companies") {
    if (parts.length === 1) {
      if (req.method === "GET") {
        return perm("read", () => {
          try {
            return jsonResponse(listCompanies(db, { status: url.searchParams.get("status") ?? undefined }));
          } catch (e) {
            return crmError(e);
          }
        })(req);
      }
      if (req.method === "POST") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            const created = createCompany(
              db,
              {
                name: b.name,
                legal_name: b.legal_name,
                address: b.address,
                tax_id: b.tax_id,
                investment_objectives: b.investment_objectives,
                authorized_parties: b.authorized_parties,
                status: b.status,
              },
              ctx.user.id,
            );
            return Response.json({ data: created }, { status: 201 });
          } catch (e) {
            return crmError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    const id = parseIdParam(parts, 1);
    if (id === null) return errorResponse("validation", "company id must be a positive integer", 400);
    if (parts.length === 2) {
      if (req.method === "GET") {
        return perm("read", () => {
          const v = getCompany(db, id);
          return v ? jsonResponse(v) : errorResponse("not_found", "company not found", 404);
        })(req);
      }
      if (req.method === "PATCH") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            return jsonResponse(
              updateCompany(
                db,
                id,
                {
                  name: b.name,
                  legal_name: b.legal_name,
                  address: b.address,
                  tax_id: b.tax_id,
                  investment_objectives: b.investment_objectives,
                  authorized_parties: b.authorized_parties,
                  status: b.status,
                },
                ctx.user.id,
              ),
            );
          } catch (e) {
            return crmError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    return errorResponse("not_found", "not found", 404);
  }

  // --- contacts ---
  if (parts[0] === "contacts") {
    if (parts.length === 1) {
      if (req.method === "GET") {
        return perm("read", () => {
          try {
            return jsonResponse(
              listContacts(db, { company_id: qint("company_id"), status: url.searchParams.get("status") ?? undefined }),
            );
          } catch (e) {
            return crmError(e);
          }
        })(req);
      }
      if (req.method === "POST") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            const created = createContact(
              db,
              {
                company_id: b.company_id,
                name: b.name,
                email: b.email,
                phone: b.phone,
                address: b.address,
                status: b.status,
              },
              ctx.user.id,
            );
            return Response.json({ data: created }, { status: 201 });
          } catch (e) {
            return crmError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    const id = parseIdParam(parts, 1);
    if (id === null) return errorResponse("validation", "contact id must be a positive integer", 400);
    if (parts.length === 2) {
      if (req.method === "GET") {
        return perm("read", () => {
          const v = getContact(db, id);
          return v ? jsonResponse(v) : errorResponse("not_found", "contact not found", 404);
        })(req);
      }
      if (req.method === "PATCH") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            return jsonResponse(
              updateContact(
                db,
                id,
                {
                  company_id: b.company_id,
                  name: b.name,
                  email: b.email,
                  phone: b.phone,
                  address: b.address,
                  status: b.status,
                },
                ctx.user.id,
              ),
            );
          } catch (e) {
            return crmError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    return errorResponse("not_found", "not found", 404);
  }

  // --- deals ---
  if (parts[0] === "deals") {
    if (parts.length === 1) {
      if (req.method === "GET") {
        return perm("read", () => {
          try {
            return jsonResponse(
              listDeals(db, {
                company_id: qint("company_id"),
                contact_id: qint("contact_id"),
                stage: url.searchParams.get("stage") ?? undefined,
              }),
            );
          } catch (e) {
            return crmError(e);
          }
        })(req);
      }
      if (req.method === "POST") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            const created = createDeal(
              db,
              {
                title: b.title,
                company_id: b.company_id,
                contact_id: b.contact_id,
                stage: b.stage,
                amount_cents: b.amount_cents,
                expected_close_date: b.expected_close_date,
                owner_id: b.owner_id,
              },
              ctx.user.id,
            );
            return Response.json({ data: created }, { status: 201 });
          } catch (e) {
            return crmError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    const id = parseIdParam(parts, 1);
    if (id === null) return errorResponse("validation", "deal id must be a positive integer", 400);
    if (parts.length === 2) {
      if (req.method === "GET") {
        return perm("read", () => {
          const v = getDeal(db, id);
          return v ? jsonResponse(v) : errorResponse("not_found", "deal not found", 404);
        })(req);
      }
      if (req.method === "PATCH") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            return jsonResponse(
              updateDeal(
                db,
                id,
                {
                  title: b.title,
                  company_id: b.company_id,
                  contact_id: b.contact_id,
                  stage: b.stage,
                  amount_cents: b.amount_cents,
                  expected_close_date: b.expected_close_date,
                  owner_id: b.owner_id,
                },
                ctx.user.id,
              ),
            );
          } catch (e) {
            return crmError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    return errorResponse("not_found", "not found", 404);
  }

  // --- activities (comms log, read + create only: append-only) ---
  if (parts[0] === "activities") {
    if (parts.length === 1) {
      if (req.method === "GET") {
        return perm("read", () => {
          try {
            const flagged = url.searchParams.get("flagged_for_review");
            return jsonResponse(
              listActivities(db, {
                company_id: qint("company_id"),
                contact_id: qint("contact_id"),
                deal_id: qint("deal_id"),
                flagged_for_review: flagged === null ? undefined : flagged === "1",
                origin: url.searchParams.get("origin") ?? undefined,
                direction: url.searchParams.get("direction") ?? undefined,
              }),
            );
          } catch (e) {
            return crmError(e);
          }
        })(req);
      }
      if (req.method === "POST") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            const created = createActivity(
              db,
              {
                direction: b.direction,
                channel: b.channel,
                origin: b.origin,
                subject: b.subject,
                body: b.body,
                company_id: b.company_id,
                contact_id: b.contact_id,
                deal_id: b.deal_id,
                flagged_for_review: b.flagged_for_review,
              },
              ctx.user.id,
            );
            return Response.json({ data: created }, { status: 201 });
          } catch (e) {
            return crmError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    const id = parseIdParam(parts, 1);
    if (id === null) return errorResponse("validation", "activity id must be a positive integer", 400);
    if (parts.length === 2 && req.method === "GET") {
      return perm("read", () => {
        const v = getActivity(db, id);
        return v ? jsonResponse(v) : errorResponse("not_found", "activity not found", 404);
      })(req);
    }
    return errorResponse("not_found", "not found", 404);
  }

  // --- comms reviews (principal queue + review) ---
  if (parts[0] === "comms-reviews") {
    if (parts.length === 2 && parts[1] === "queue" && req.method === "GET") {
      return perm("read", () => jsonResponse(reviewQueue(db)))(req);
    }
    const id = parseIdParam(parts, 1);
    if (id === null) return errorResponse("validation", "activity id must be a positive integer", 400);
    if (parts.length === 2 && req.method === "GET") {
      return perm("read", () => {
        const v = getCommsReview(db, id);
        return v ? jsonResponse(v) : errorResponse("not_found", "no review for activity", 404);
      })(req);
    }
    if (parts.length === 3 && parts[2] === "review" && req.method === "POST") {
      // crm:approve is the RBAC gate; is_principal + no-self-review are
      // enforced inside reviewActivity (F-S3) and surface as 403s.
      return perm("approve", async (req2, ctx) => {
        const parsed = await parseJsonBody(req2);
        if (!parsed.ok) return parsed.response;
        const b = parsed.body;
        try {
          return jsonResponse(
            reviewActivity(db, id, ctx.user.id, str(b.disposition) ?? "", nul(b.notes)),
          );
        } catch (e) {
          return crmError(e);
        }
      })(req);
    }
    return errorResponse("not_found", "not found", 404);
  }

  // --- supervisory personnel (F-S3) ---
  if (parts[0] === "principals") {
    if (parts.length === 1) {
      if (req.method === "GET") {
        return perm("read", () => jsonResponse(listPrincipals(db)))(req);
      }
      if (req.method === "POST") {
        return perm("admin", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            const created = designatePrincipal(
              db,
              num(b.user_id) ?? 0,
              nul(b.title),
              nul(b.location),
              ctx.user.id,
            );
            return Response.json({ data: created }, { status: 201 });
          } catch (e) {
            return crmError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    const id = parseIdParam(parts, 1);
    if (id === null) return errorResponse("validation", "user id must be a positive integer", 400);
    if (parts.length === 2 && req.method === "DELETE") {
      return perm("admin", (_req2, ctx) => {
        try {
          return jsonResponse(revokePrincipal(db, id, ctx.user.id));
        } catch (e) {
          return crmError(e);
        }
      })(req);
    }
    return errorResponse("not_found", "not found", 404);
  }

  // --- complaints ---
  if (parts[0] === "complaints") {
    if (parts.length === 1) {
      if (req.method === "GET") {
        return perm("read", () => {
          try {
            const overdue = url.searchParams.get("overdue_ack");
            return jsonResponse(
              listComplaints(db, {
                status: url.searchParams.get("status") ?? undefined,
                overdue_ack: overdue === "1",
              }),
            );
          } catch (e) {
            return crmError(e);
          }
        })(req);
      }
      if (req.method === "POST") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            const created = createComplaint(
              db,
              {
                company_id: b.company_id,
                contact_id: b.contact_id,
                subject: b.subject,
                description: b.description,
                ack_sla_days: b.ack_sla_days,
              },
              ctx.user.id,
            );
            return Response.json({ data: created }, { status: 201 });
          } catch (e) {
            return crmError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    const id = parseIdParam(parts, 1);
    if (id === null) return errorResponse("validation", "complaint id must be a positive integer", 400);
    if (parts.length === 2 && req.method === "GET") {
      return perm("read", () => {
        const v = getComplaint(db, id);
        return v ? jsonResponse(v) : errorResponse("not_found", "complaint not found", 404);
      })(req);
    }
    if (parts.length === 3 && req.method === "POST") {
      if (parts[2] === "acknowledge") {
        return perm("write", async (_req2, ctx) => {
          try {
            return jsonResponse(acknowledgeComplaint(db, id, ctx.user.id));
          } catch (e) {
            return crmError(e);
          }
        })(req);
      }
      if (parts[2] === "respond") {
        return perm("write", async (_req2, ctx) => {
          try {
            return jsonResponse(respondComplaint(db, id, ctx.user.id));
          } catch (e) {
            return crmError(e);
          }
        })(req);
      }
    }
    return errorResponse("not_found", "not found", 404);
  }

  return errorResponse("not_found", "not found", 404);
}

/** Map an HrError to the stable error envelope; LedgerError delegates to ledgerError. */
function hrError(e: unknown): Response {
  if (e instanceof LedgerError) return ledgerError(e);
  if (e instanceof HrError) {
    const status =
      {
        validation: 400,
        deductions_exceed_gross: 400,
        not_found: 404,
        self_approval: 403,
        not_draft: 409,
        not_approved: 409,
        already_approved: 409,
        already_paid: 409,
        empty_run: 409,
        duplicate_line: 409,
        employee_inactive: 409,
      }[e.code] ?? 400;
    return errorResponse(e.code, e.message, status);
  }
  throw e;
}

/**
 * Run produce() for an HR posting (pay), honoring Idempotency-Key like the
 * AR/AP/inventory/procurement routes: errors are NOT recorded, successes
 * replay. Approve is a state transition, not a posting, so it is NOT
 * idempotency-wrapped (same rule as bill approve / PO submit).
 */
function runHrMutation(
  req: Request,
  db: Database,
  ctx: Ctx,
  scope: string,
  path: string,
  produce: () => { status: number; body: unknown },
): Response {
  const idemKey = req.headers.get("idempotency-key")?.trim().slice(0, 128);
  const run = (): { status: number; body: unknown } => {
    try {
      return produce();
    } catch (e) {
      throw { __hrHttp: hrError(e) };
    }
  };
  try {
    const r = idemKey
      ? withIdempotency(db, `${scope}:${ctx.user.id}:${idemKey}`, ctx.user.id, "POST", path, run)
      : { replayed: false, ...run() };
    return Response.json(r.body, { status: r.status });
  } catch (e) {
    if (e && typeof e === "object" && "__hrHttp" in e) {
      return (e as { __hrHttp: Response }).__hrHttp;
    }
    throw e;
  }
}

/** All /api/v1/hr/* routes (Phase 8: employees with encrypted PII,
 *  deduction types, pay runs with maker-checker approval + summary posting). */
function handleHr(
  req: Request,
  db: Database,
  cfg: SessionConfig,
  url: URL,
): Promise<Response> | Response {
  const perm = (
    action: string,
    handler: (req: Request, ctx: Ctx, url: URL) => Promise<Response> | Response,
  ): Handler =>
    withPerm(db, cfg, "hr", action, (req2, ctx) => {
      if (!ctx) return errorResponse("unauthorized", "missing session", 401);
      return handler(req2, ctx, url);
    });

  const sub = url.pathname.slice("/api/v1/hr/".length);
  const parts = sub.split("/").filter((p) => p !== "");
  const qint = (name: string): number | undefined => {
    const v = url.searchParams.get(name);
    return v ? parseInt(v, 10) || undefined : undefined;
  };

  // --- employees (PII encrypted at rest; HTTP view shows ssn_last4 only) ---
  if (parts[0] === "employees") {
    if (parts.length === 1) {
      if (req.method === "GET") {
        return perm("read", () => {
          try {
            return jsonResponse(listEmployees(db, { status: url.searchParams.get("status") ?? undefined }));
          } catch (e) {
            return hrError(e);
          }
        })(req);
      }
      if (req.method === "POST") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            const created = await createEmployee(
              db,
              {
                first_name: b.first_name,
                last_name: b.last_name,
                email: b.email,
                status: b.status,
                hire_date: b.hire_date,
                pay_type: b.pay_type,
                base_pay_cents: b.base_pay_cents,
                ssn: b.ssn,
                date_of_birth: b.date_of_birth,
                bank_account: b.bank_account,
              },
              ctx.user.id,
            );
            return Response.json({ data: created }, { status: 201 });
          } catch (e) {
            return hrError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    const id = parseIdParam(parts, 1);
    if (id === null) return errorResponse("validation", "employee id must be a positive integer", 400);
    if (parts.length === 2) {
      if (req.method === "GET") {
        return perm("read", () => {
          const v = getEmployee(db, id);
          return v ? jsonResponse(v) : errorResponse("not_found", "employee not found", 404);
        })(req);
      }
      if (req.method === "PATCH") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            return jsonResponse(
              await updateEmployee(
                db,
                id,
                {
                  first_name: b.first_name,
                  last_name: b.last_name,
                  email: b.email,
                  status: b.status,
                  hire_date: b.hire_date,
                  pay_type: b.pay_type,
                  base_pay_cents: b.base_pay_cents,
                  ssn: b.ssn,
                  date_of_birth: b.date_of_birth,
                  bank_account: b.bank_account,
                },
                ctx.user.id,
              ),
            );
          } catch (e) {
            return hrError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    return errorResponse("not_found", "not found", 404);
  }

  // --- deduction types ---
  if (parts[0] === "deduction-types") {
    if (parts.length === 1) {
      if (req.method === "GET") {
        return perm("read", () => {
          const active = url.searchParams.get("active");
          return jsonResponse(
            listDeductionTypes(db, { active: active === null ? undefined : active === "1" }),
          );
        })(req);
      }
      if (req.method === "POST") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            const created = createDeductionType(
              db,
              {
                code: b.code,
                name: b.name,
                kind: b.kind,
                percent_bps: b.percent_bps,
                amount_cents: b.amount_cents,
                active: b.active,
              },
              ctx.user.id,
            );
            return Response.json({ data: created }, { status: 201 });
          } catch (e) {
            return hrError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    const id = parseIdParam(parts, 1);
    if (id === null) return errorResponse("validation", "deduction type id must be a positive integer", 400);
    if (parts.length === 2 && req.method === "GET") {
      return perm("read", () => {
        const v = getDeductionType(db, id);
        return v ? jsonResponse(v) : errorResponse("not_found", "deduction type not found", 404);
      })(req);
    }
    return errorResponse("not_found", "not found", 404);
  }

  // --- pay runs ---
  if (parts[0] === "pay-runs") {
    if (parts.length === 1) {
      if (req.method === "GET") {
        return perm("read", () => {
          try {
            return jsonResponse(listPayRuns(db, { status: url.searchParams.get("status") ?? undefined }));
          } catch (e) {
            return hrError(e);
          }
        })(req);
      }
      if (req.method === "POST") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            const created = createPayRun(
              db,
              { period_start: b.period_start, period_end: b.period_end, pay_date: b.pay_date },
              ctx.user.id,
            );
            return Response.json({ data: created }, { status: 201 });
          } catch (e) {
            return hrError(e);
          }
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    const id = parseIdParam(parts, 1);
    if (id === null) return errorResponse("validation", "pay run id must be a positive integer", 400);
    if (parts.length === 2) {
      if (req.method === "GET") {
        return perm("read", () => {
          const v = getPayRun(db, id);
          return v ? jsonResponse(v) : errorResponse("not_found", "pay run not found", 404);
        })(req);
      }
      return errorResponse("not_found", "not found", 404);
    }
    if (parts.length === 3 && req.method === "POST") {
      if (parts[2] === "lines") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            const line = addPayLine(
              db,
              id,
              { employee_id: b.employee_id, gross_cents: b.gross_cents, deduction_codes: b.deduction_codes },
              ctx.user.id,
            );
            return Response.json({ data: line }, { status: 201 });
          } catch (e) {
            return hrError(e);
          }
        })(req);
      }
      if (parts[2] === "approve") {
        return perm("approve", async (req2, ctx) => {
          await parseJsonBodyLenient(req2);
          try {
            return jsonResponse(approvePayRun(db, id, ctx.user.id));
          } catch (e) {
            return hrError(e);
          }
        })(req);
      }
      if (parts[2] === "pay") {
        return perm("post", async (req2, ctx) => {
          await parseJsonBodyLenient(req2);
          return runHrMutation(req2, db, ctx, "hr-pay", `/api/v1/hr/pay-runs/${id}/pay`, () => {
            const paid = payPayRun(db, id, ctx.user.id);
            return { status: 200, body: { data: paid } };
          });
        })(req);
      }
    }
    if (parts.length === 4 && parts[2] === "lines") {
      const lineId = parseIdParam(parts, 3);
      if (lineId === null) return errorResponse("validation", "pay line id must be a positive integer", 400);
      if (req.method === "PATCH") {
        return perm("write", async (req2, ctx) => {
          const parsed = await parseJsonBody(req2);
          if (!parsed.ok) return parsed.response;
          const b = parsed.body;
          try {
            return jsonResponse(
              updatePayLineDraft(
                db,
                id,
                lineId,
                { employee_id: b.employee_id, gross_cents: b.gross_cents, deduction_codes: b.deduction_codes },
                ctx.user.id,
              ),
            );
          } catch (e) {
            return hrError(e);
          }
        })(req);
      }
      if (req.method === "DELETE") {
        return perm("write", (_req2, ctx) => {
          try {
            removePayLine(db, id, lineId, ctx.user.id);
            return jsonResponse({ removed: true });
          } catch (e) {
            return hrError(e);
          }
        })(req);
      }
    }
    return errorResponse("not_found", "not found", 404);
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
        if (path.startsWith("/api/v1/compliance/")) {
          return handleCompliance(req, db, cfg, url);
        }
        if (path.startsWith("/api/v1/documents/") || path === "/api/v1/documents") {
          return handleDocuments(req, db, cfg, url);
        }
        if (path.startsWith("/api/v1/ledger/")) {
          return handleLedger(req, db, cfg, url);
        }
        if (path.startsWith("/api/v1/ar/")) {
          return handleAr(req, db, cfg, url);
        }
        if (path.startsWith("/api/v1/ap/")) {
          return handleAp(req, db, cfg, url);
        }
        if (path.startsWith("/api/v1/inventory/")) {
          return handleInventory(req, db, cfg, url);
        }
        if (path.startsWith("/api/v1/procurement/")) {
          return handleProcurement(req, db, cfg, url);
        }
        if (path.startsWith("/api/v1/crm/")) {
          return handleCrm(req, db, cfg, url);
        }
        if (path.startsWith("/api/v1/hr/")) {
          return handleHr(req, db, cfg, url);
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
