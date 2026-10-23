// Tally ERP — middleware.ts
// HTTP plumbing shared by server.ts: JSON bodies, the error envelope,
// auth/RBAC request wrappers, and the audited-mutation helper every future
// resource handler must use (mutating endpoints are always audited).

import type { Database } from "bun:sqlite";
import { authenticate, type SessionConfig, type UserRow, type SessionRow } from "./auth";
import { appendAudit, type AuditInput } from "./audit";
import { can } from "./rbac";

export interface Ctx {
  user: UserRow;
  session: SessionRow;
}

export type Handler = (req: Request, ctx: Ctx | null) => Promise<Response> | Response;

/** Stable error envelope: { error: { code, message } }. */
export function errorResponse(code: string, message: string, status: number): Response {
  return Response.json({ error: { code, message } }, { status });
}

export function jsonResponse(data: unknown, status = 200): Response {
  return Response.json({ data }, { status });
}

export function getBearerToken(req: Request): string | null {
  const h = req.headers.get("authorization");
  if (!h) return null;
  const m = /^Bearer\s+(\S+)$/i.exec(h.trim());
  return m ? m[1] : null;
}

export async function parseJsonBody(req: Request): Promise<
  | { ok: true; body: Record<string, unknown> }
  | { ok: false; response: Response }
> {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return { ok: false, response: errorResponse("validation", "request body must be valid JSON", 400) };
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return { ok: false, response: errorResponse("validation", "request body must be a JSON object", 400) };
  }
  return { ok: true, body: body as Record<string, unknown> };
}

/** Lenient variant: an empty body parses as {} (for POSTs with no payload). */
export async function parseJsonBodyLenient(req: Request): Promise<
  | { ok: true; body: Record<string, unknown> }
  | { ok: false; response: Response }
> {
  const text = await req.text();
  if (!text.trim()) return { ok: true, body: {} };
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return { ok: false, response: errorResponse("validation", "request body must be valid JSON", 400) };
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return { ok: false, response: errorResponse("validation", "request body must be a JSON object", 400) };
  }
  return { ok: true, body: body as Record<string, unknown> };
}
export function withAuth(db: Database, cfg: SessionConfig, handler: Handler): Handler {
  return (req) => {
    const auth = authenticate(db, getBearerToken(req), cfg);
    if (!auth.ok) {
      const status = auth.code === "session_expired" ? 401 : 401;
      return errorResponse(auth.code, auth.message, status);
    }
    return handler(req, { user: auth.user, session: auth.session });
  };
}

/** Wrap a handler: require session + (resource, action) permission (403 forbidden). */
export function withPerm(
  db: Database,
  cfg: SessionConfig,
  resource: string,
  action: string,
  handler: Handler,
): Handler {
  return withAuth(db, cfg, (req, ctx) => {
    if (!ctx) return errorResponse("unauthorized", "missing session", 401);
    if (!can(db, ctx.user.role_name, resource, action)) {
      return errorResponse("forbidden", `role '${ctx.user.role_name}' lacks ${action} on ${resource}`, 403);
    }
    return handler(req, ctx);
  });
}

/**
 * Run fn() inside a transaction and append exactly one audit row for the
 * mutation. All mutating resource endpoints must go through this (or an
 * equivalent explicit appendAudit inside their transaction) — H-T5 / F-R6.
 */
export function mutateWithAudit<T>(
  db: Database,
  audit: Omit<AuditInput, "before" | "after"> & { before?: unknown; after?: unknown },
  fn: () => T,
): T {
  return db.transaction(() => {
    const result = fn();
    appendAudit(db, audit);
    return result;
  })();
}
