// Tally ERP — crm.ts
// Phase 7: CRM + supervision surfaces (FINRA 4512/4513, 3110(b)(4)–(6)).
//
// - companies carry the 4512 field set: name, address, tax_id, investment
//   objectives (free-form profile field — the [verify] flag in the matrix
//   stands: the exact 4512 element list is still unconfirmed against
//   primary rule text, so completeness validation covers the fields the
//   matrix names and reports the missing ones by name instead of
//   silently accepting an incomplete account record), authorized parties.
//   Tax ID is stored in clear in v1, like AR/AP contact details; the
//   field-level encryption designated in H-T4 lands with Phase 8 HR
//   PII work, which is the phase that introduces encrypted columns.
// - contacts are people, optionally attached to a company.
// - deals move through lead → qualified → proposal → negotiation →
//   won/lost; won/lost are terminal (a won deal is history, not a
//   pipeline stage to re-enter).
// - activities are the communications log: append-only by trigger (F-R3),
//   never edited, never deleted. Flagged activities (manual flag, or any
//   ai_agent origin — F-S4) sit in the principal review queue until a
//   principal writes a comms_reviews row. The review row is itself
//   append-only: review evidence, not a mutable status.
// - complaints run received → acknowledged → responded (F-S2). Content
//   is trigger-immutable; only status + its timestamps move. An
//   unacknowledged complaint past its ack SLA (default 7 calendar days,
//   firm policy, per-complaint override) reports acknowledged_overdue.
//
// Conventions from phases 0–6: money in integer cents; all writes in
// transactions; audit row inside the same transaction; CrmError with a
// stable .code the HTTP layer maps to a status.

import type { Database } from "bun:sqlite";
import { appendAudit } from "./audit";
import { nowIso } from "./db";

export class CrmError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "CrmError";
    this.code = code;
  }
}

function isValidDate(d: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) return false;
  const dt = new Date(`${d}T00:00:00Z`);
  return !Number.isNaN(dt.getTime()) && dt.toISOString().slice(0, 10) === d;
}

function reqStr(v: unknown, label: string, max = 2000): string {
  if (typeof v !== "string" || !v.trim()) {
    throw new CrmError("validation", `${label} is required`);
  }
  return v.trim().slice(0, max);
}

function optStr(v: unknown, max = 2000): string | null {
  return typeof v === "string" && v.trim() ? v.trim().slice(0, max) : null;
}

function reqInt(v: unknown, label: string, opts: { min?: number } = {}): number {
  if (typeof v !== "number" || !Number.isInteger(v)) {
    throw new CrmError("validation", `${label} must be an integer`);
  }
  if (opts.min !== undefined && v < opts.min) {
    throw new CrmError("validation", `${label} must be >= ${opts.min}`);
  }
  return v;
}

function emailScreen(email: string | null): void {
  if (email !== null && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new CrmError("validation", `email '${email}' is not a valid email address`);
  }
}

function mustExist(db: Database, table: string, id: number, label: string): void {
  const row = db.query(`SELECT id FROM ${table} WHERE id = ?`).get(id) as
    | { id: number }
    | undefined;
  if (!row) throw new CrmError("not_found", `${label} ${id} not found`);
}

// --- companies (F-R8) -----------------------------------------------------------

export interface CompanyRow {
  id: number;
  name: string;
  legal_name: string | null;
  address: string | null;
  tax_id: string | null;
  investment_objectives: string | null;
  authorized_parties: string | null;
  status: string;
  created_by: number | null;
  created_at: string;
  updated_at: string;
}

export interface CompanyInput {
  name?: unknown;
  legal_name?: unknown;
  address?: unknown;
  tax_id?: unknown;
  investment_objectives?: unknown;
  authorized_parties?: unknown;
  status?: unknown;
}

/** The 4512 completeness set: every missing field is named in the error. */
export const COMPANY_REQUIRED_4512 = ["name", "address", "tax_id"] as const;

function companyRow(db: Database, id: number): CompanyRow | null {
  const row = db.query("SELECT * FROM companies WHERE id = ?").get(id) as CompanyRow | undefined;
  return row ?? null;
}

export function getCompany(db: Database, id: number): CompanyRow | null {
  return companyRow(db, id);
}

export function listCompanies(db: Database, opts: { status?: string } = {}): CompanyRow[] {
  if (opts.status !== undefined && !["active", "inactive"].includes(opts.status)) {
    throw new CrmError("validation", `unknown company status '${opts.status}'`);
  }
  const clause = opts.status !== undefined ? "WHERE status = ?" : "";
  const params = opts.status !== undefined ? [opts.status] : [];
  return db.query(`SELECT * FROM companies ${clause} ORDER BY id DESC`).all(...params) as CompanyRow[];
}

export function createCompany(
  db: Database,
  input: CompanyInput,
  actorId: number | null,
): CompanyRow {
  const missing: string[] = [];
  if (typeof input.name !== "string" || !input.name.trim()) missing.push("name");
  if (typeof input.address !== "string" || !input.address.trim()) missing.push("address");
  if (typeof input.tax_id !== "string" || !input.tax_id.trim()) missing.push("tax_id");
  if (missing.length) {
    throw new CrmError(
      "validation",
      `missing required 4512 fields: ${missing.join(", ")}`,
    );
  }
  const status =
    input.status === undefined ? "active" : reqStr(input.status, "status");
  if (!["active", "inactive"].includes(status)) {
    throw new CrmError("validation", `unknown company status '${status}'`);
  }
  const now = nowIso();
  return db.transaction((): CompanyRow => {
    const info = db
      .query(
        `INSERT INTO companies
           (name, legal_name, address, tax_id, investment_objectives,
            authorized_parties, status, created_by, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        reqStr(input.name, "name", 500),
        optStr(input.legal_name, 500),
        optStr(input.address),
        optStr(input.tax_id, 200),
        optStr(input.investment_objectives),
        optStr(input.authorized_parties),
        status,
        actorId,
        now,
        now,
      );
    const id = Number(info.lastInsertRowid);
    appendAudit(db, {
      actor_id: actorId,
      action: "company.create",
      entity_type: "company",
      entity_id: id,
      after: { name: reqStr(input.name, "name", 500), status },
    });
    return companyRow(db, id)!;
  })();
}

export function updateCompany(
  db: Database,
  id: number,
  input: CompanyInput,
  actorId: number | null,
): CompanyRow {
  const before = companyRow(db, id);
  if (!before) throw new CrmError("not_found", `company ${id} not found`);
  let status = before.status;
  if (input.status !== undefined) {
    status = reqStr(input.status, "status");
    if (!["active", "inactive"].includes(status)) {
      throw new CrmError("validation", `unknown company status '${status}'`);
    }
  }
  const name = input.name === undefined ? before.name : reqStr(input.name, "name", 500);
  const address = input.address === undefined ? before.address : optStr(input.address);
  const taxId = input.tax_id === undefined ? before.tax_id : optStr(input.tax_id, 200);
  // Updates must not silently gut the 4512 set: clearing a required field
  // is a validation error, not a quiet downgrade to an incomplete record.
  const missing: string[] = [];
  if (!name.trim()) missing.push("name");
  if (!address?.trim()) missing.push("address");
  if (!taxId?.trim()) missing.push("tax_id");
  if (missing.length) {
    throw new CrmError(
      "validation",
      `update would remove required 4512 fields: ${missing.join(", ")}`,
    );
  }
  return db.transaction((): CompanyRow => {
    db.query(
      `UPDATE companies SET name = ?, legal_name = ?, address = ?, tax_id = ?,
         investment_objectives = ?, authorized_parties = ?, status = ?,
         updated_at = ? WHERE id = ?`,
    ).run(
      name,
      input.legal_name === undefined ? before.legal_name : optStr(input.legal_name, 500),
      address,
      taxId,
      input.investment_objectives === undefined
        ? before.investment_objectives
        : optStr(input.investment_objectives),
      input.authorized_parties === undefined
        ? before.authorized_parties
        : optStr(input.authorized_parties),
      status,
      nowIso(),
      id,
    );
    appendAudit(db, {
      actor_id: actorId,
      action: "company.update",
      entity_type: "company",
      entity_id: id,
      before: { name: before.name, status: before.status },
      after: { name, status },
    });
    return companyRow(db, id)!;
  })();
}

// --- contacts -------------------------------------------------------------------

export interface ContactRow {
  id: number;
  company_id: number | null;
  name: string;
  email: string | null;
  phone: string | null;
  address: string | null;
  status: string;
  created_by: number | null;
  created_at: string;
  updated_at: string;
}

export interface ContactInput {
  company_id?: unknown;
  name?: unknown;
  email?: unknown;
  phone?: unknown;
  address?: unknown;
  status?: unknown;
}

function contactRow(db: Database, id: number): ContactRow | null {
  const row = db.query("SELECT * FROM contacts WHERE id = ?").get(id) as ContactRow | undefined;
  return row ?? null;
}

export function getContact(db: Database, id: number): ContactRow | null {
  return contactRow(db, id);
}

export function listContacts(
  db: Database,
  opts: { company_id?: number; status?: string } = {},
): ContactRow[] {
  const where: string[] = [];
  const params: (number | string)[] = [];
  if (opts.company_id !== undefined) {
    where.push("company_id = ?");
    params.push(opts.company_id);
  }
  if (opts.status !== undefined) {
    if (!["active", "inactive"].includes(opts.status)) {
      throw new CrmError("validation", `unknown contact status '${opts.status}'`);
    }
    where.push("status = ?");
    params.push(opts.status);
  }
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
  return db.query(`SELECT * FROM contacts ${clause} ORDER BY id DESC`).all(...params) as ContactRow[];
}

export function createContact(
  db: Database,
  input: ContactInput,
  actorId: number | null,
): ContactRow {
  const name = reqStr(input.name, "name", 500);
  const email = optStr(input.email, 500);
  emailScreen(email);
  let companyId: number | null = null;
  if (input.company_id !== undefined && input.company_id !== null) {
    companyId = reqInt(input.company_id, "company_id", { min: 1 });
    mustExist(db, "companies", companyId, "company");
  }
  const status = input.status === undefined ? "active" : reqStr(input.status, "status");
  if (!["active", "inactive"].includes(status)) {
    throw new CrmError("validation", `unknown contact status '${status}'`);
  }
  const now = nowIso();
  return db.transaction((): ContactRow => {
    const info = db
      .query(
        `INSERT INTO contacts
           (company_id, name, email, phone, address, status, created_by, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        companyId,
        name,
        email,
        optStr(input.phone, 200),
        optStr(input.address),
        status,
        actorId,
        now,
        now,
      );
    const id = Number(info.lastInsertRowid);
    appendAudit(db, {
      actor_id: actorId,
      action: "contact.create",
      entity_type: "contact",
      entity_id: id,
      after: { name, company_id: companyId },
    });
    return contactRow(db, id)!;
  })();
}

export function updateContact(
  db: Database,
  id: number,
  input: ContactInput,
  actorId: number | null,
): ContactRow {
  const before = contactRow(db, id);
  if (!before) throw new CrmError("not_found", `contact ${id} not found`);
  const name = input.name === undefined ? before.name : reqStr(input.name, "name", 500);
  const email = input.email === undefined ? before.email : optStr(input.email, 500);
  emailScreen(email);
  let companyId = before.company_id;
  if (input.company_id !== undefined) {
    companyId =
      input.company_id === null ? null : reqInt(input.company_id, "company_id", { min: 1 });
    if (companyId !== null) mustExist(db, "companies", companyId, "company");
  }
  let status = before.status;
  if (input.status !== undefined) {
    status = reqStr(input.status, "status");
    if (!["active", "inactive"].includes(status)) {
      throw new CrmError("validation", `unknown contact status '${status}'`);
    }
  }
  return db.transaction((): ContactRow => {
    db.query(
      `UPDATE contacts SET company_id = ?, name = ?, email = ?, phone = ?,
         address = ?, status = ?, updated_at = ? WHERE id = ?`,
    ).run(
      companyId,
      name,
      email,
      input.phone === undefined ? before.phone : optStr(input.phone, 200),
      input.address === undefined ? before.address : optStr(input.address),
      status,
      nowIso(),
      id,
    );
    appendAudit(db, {
      actor_id: actorId,
      action: "contact.update",
      entity_type: "contact",
      entity_id: id,
      before: { name: before.name, company_id: before.company_id },
      after: { name, company_id: companyId },
    });
    return contactRow(db, id)!;
  })();
}

// --- deals ----------------------------------------------------------------------

export const DEAL_STAGES = [
  "lead",
  "qualified",
  "proposal",
  "negotiation",
  "won",
  "lost",
] as const;

export interface DealRow {
  id: number;
  title: string;
  company_id: number | null;
  contact_id: number | null;
  stage: string;
  amount_cents: number;
  expected_close_date: string | null;
  owner_id: number | null;
  created_by: number | null;
  created_at: string;
  updated_at: string;
}

export interface DealInput {
  title?: unknown;
  company_id?: unknown;
  contact_id?: unknown;
  stage?: unknown;
  amount_cents?: unknown;
  expected_close_date?: unknown;
  owner_id?: unknown;
}

function dealRow(db: Database, id: number): DealRow | null {
  const row = db.query("SELECT * FROM deals WHERE id = ?").get(id) as DealRow | undefined;
  return row ?? null;
}

export function getDeal(db: Database, id: number): DealRow | null {
  return dealRow(db, id);
}

export function listDeals(
  db: Database,
  opts: { company_id?: number; contact_id?: number; stage?: string } = {},
): DealRow[] {
  const where: string[] = [];
  const params: (number | string)[] = [];
  if (opts.company_id !== undefined) {
    where.push("company_id = ?");
    params.push(opts.company_id);
  }
  if (opts.contact_id !== undefined) {
    where.push("contact_id = ?");
    params.push(opts.contact_id);
  }
  if (opts.stage !== undefined) {
    if (!(DEAL_STAGES as readonly string[]).includes(opts.stage)) {
      throw new CrmError("validation", `unknown deal stage '${opts.stage}'`);
    }
    where.push("stage = ?");
    params.push(opts.stage);
  }
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
  return db.query(`SELECT * FROM deals ${clause} ORDER BY id DESC`).all(...params) as DealRow[];
}

export function createDeal(
  db: Database,
  input: DealInput,
  actorId: number | null,
): DealRow {
  const title = reqStr(input.title, "title", 500);
  let companyId: number | null = null;
  let contactId: number | null = null;
  if (input.company_id !== undefined && input.company_id !== null) {
    companyId = reqInt(input.company_id, "company_id", { min: 1 });
    mustExist(db, "companies", companyId, "company");
  }
  if (input.contact_id !== undefined && input.contact_id !== null) {
    contactId = reqInt(input.contact_id, "contact_id", { min: 1 });
    mustExist(db, "contacts", contactId, "contact");
  }
  if (companyId === null && contactId === null) {
    throw new CrmError("validation", "a deal needs a company_id or a contact_id");
  }
  const stage = input.stage === undefined ? "lead" : reqStr(input.stage, "stage");
  if (!(DEAL_STAGES as readonly string[]).includes(stage)) {
    throw new CrmError("validation", `unknown deal stage '${stage}'`);
  }
  const amount = input.amount_cents === undefined ? 0 : reqInt(input.amount_cents, "amount_cents", { min: 0 });
  let expected: string | null = null;
  if (input.expected_close_date !== undefined && input.expected_close_date !== null) {
    if (!isValidDate(String(input.expected_close_date))) {
      throw new CrmError("validation", "expected_close_date must be YYYY-MM-DD");
    }
    expected = String(input.expected_close_date);
  }
  let ownerId: number | null = null;
  if (input.owner_id !== undefined && input.owner_id !== null) {
    ownerId = reqInt(input.owner_id, "owner_id", { min: 1 });
    mustExist(db, "users", ownerId, "user");
  }
  const now = nowIso();
  return db.transaction((): DealRow => {
    const info = db
      .query(
        `INSERT INTO deals
           (title, company_id, contact_id, stage, amount_cents,
            expected_close_date, owner_id, created_by, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(title, companyId, contactId, stage, amount, expected, ownerId, actorId, now, now);
    const id = Number(info.lastInsertRowid);
    appendAudit(db, {
      actor_id: actorId,
      action: "deal.create",
      entity_type: "deal",
      entity_id: id,
      after: { title, stage, amount_cents: amount },
    });
    return dealRow(db, id)!;
  })();
}

export function updateDeal(
  db: Database,
  id: number,
  input: DealInput,
  actorId: number | null,
): DealRow {
  const before = dealRow(db, id);
  if (!before) throw new CrmError("not_found", `deal ${id} not found`);
  let stage = before.stage;
  if (input.stage !== undefined) {
    if (before.stage === "won" || before.stage === "lost") {
      throw new CrmError(
        "terminal_stage",
        `deal ${id} is ${before.stage} (terminal) and cannot move to another stage`,
      );
    }
    stage = reqStr(input.stage, "stage");
    if (!(DEAL_STAGES as readonly string[]).includes(stage)) {
      throw new CrmError("validation", `unknown deal stage '${stage}'`);
    }
  }
  const title = input.title === undefined ? before.title : reqStr(input.title, "title", 500);
  const amount =
    input.amount_cents === undefined ? before.amount_cents : reqInt(input.amount_cents, "amount_cents", { min: 0 });
  let companyId = before.company_id;
  if (input.company_id !== undefined) {
    companyId = input.company_id === null ? null : reqInt(input.company_id, "company_id", { min: 1 });
    if (companyId !== null) mustExist(db, "companies", companyId, "company");
  }
  let contactId = before.contact_id;
  if (input.contact_id !== undefined) {
    contactId = input.contact_id === null ? null : reqInt(input.contact_id, "contact_id", { min: 1 });
    if (contactId !== null) mustExist(db, "contacts", contactId, "contact");
  }
  if (companyId === null && contactId === null) {
    throw new CrmError("validation", "a deal needs a company_id or a contact_id");
  }
  let expected = before.expected_close_date;
  if (input.expected_close_date !== undefined) {
    if (input.expected_close_date === null) {
      expected = null;
    } else {
      if (!isValidDate(String(input.expected_close_date))) {
        throw new CrmError("validation", "expected_close_date must be YYYY-MM-DD");
      }
      expected = String(input.expected_close_date);
    }
  }
  let ownerId = before.owner_id;
  if (input.owner_id !== undefined) {
    ownerId = input.owner_id === null ? null : reqInt(input.owner_id, "owner_id", { min: 1 });
    if (ownerId !== null) mustExist(db, "users", ownerId, "user");
  }
  return db.transaction((): DealRow => {
    db.query(
      `UPDATE deals SET title = ?, company_id = ?, contact_id = ?, stage = ?,
         amount_cents = ?, expected_close_date = ?, owner_id = ?, updated_at = ?
       WHERE id = ?`,
    ).run(title, companyId, contactId, stage, amount, expected, ownerId, nowIso(), id);
    appendAudit(db, {
      actor_id: actorId,
      action: "deal.update",
      entity_type: "deal",
      entity_id: id,
      before: { stage: before.stage, amount_cents: before.amount_cents },
      after: { stage, amount_cents: amount },
    });
    return dealRow(db, id)!;
  })();
}

// --- activities: the immutable comms log (F-S1, F-R10) ---------------------------

export interface ActivityRow {
  id: number;
  direction: string;
  channel: string;
  origin: string;
  subject: string | null;
  body: string | null;
  company_id: number | null;
  contact_id: number | null;
  deal_id: number | null;
  author_id: number | null;
  flagged_for_review: number;
  supervision_status: string;
  created_at: string;
}

export interface ActivityInput {
  direction?: unknown;
  channel?: unknown;
  origin?: unknown;
  subject?: unknown;
  body?: unknown;
  company_id?: unknown;
  contact_id?: unknown;
  deal_id?: unknown;
  flagged_for_review?: unknown;
}

const DIRECTIONS = ["in", "out", "internal"] as const;
const CHANNELS = ["email", "phone", "meeting", "note", "other"] as const;

function activityRow(db: Database, id: number): ActivityRow | null {
  const row = db.query("SELECT * FROM activities WHERE id = ?").get(id) as ActivityRow | undefined;
  return row ?? null;
}

export function getActivity(db: Database, id: number): ActivityRow | null {
  return activityRow(db, id);
}

export function listActivities(
  db: Database,
  opts: {
    company_id?: number;
    contact_id?: number;
    deal_id?: number;
    flagged_for_review?: boolean;
    origin?: string;
    direction?: string;
  } = {},
): ActivityRow[] {
  const where: string[] = [];
  const params: (number | string)[] = [];
  if (opts.company_id !== undefined) {
    where.push("company_id = ?");
    params.push(opts.company_id);
  }
  if (opts.contact_id !== undefined) {
    where.push("contact_id = ?");
    params.push(opts.contact_id);
  }
  if (opts.deal_id !== undefined) {
    where.push("deal_id = ?");
    params.push(opts.deal_id);
  }
  if (opts.flagged_for_review !== undefined) {
    where.push("flagged_for_review = ?");
    params.push(opts.flagged_for_review ? 1 : 0);
  }
  if (opts.origin !== undefined) {
    if (!["manual", "ai_agent"].includes(opts.origin)) {
      throw new CrmError("validation", `unknown activity origin '${opts.origin}'`);
    }
    where.push("origin = ?");
    params.push(opts.origin);
  }
  if (opts.direction !== undefined) {
    if (!(DIRECTIONS as readonly string[]).includes(opts.direction)) {
      throw new CrmError("validation", `unknown activity direction '${opts.direction}'`);
    }
    where.push("direction = ?");
    params.push(opts.direction);
  }
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
  return db.query(`SELECT * FROM activities ${clause} ORDER BY id DESC`).all(...params) as ActivityRow[];
}

export function createActivity(
  db: Database,
  input: ActivityInput,
  actorId: number | null,
): ActivityRow {
  const direction = reqStr(input.direction, "direction");
  if (!(DIRECTIONS as readonly string[]).includes(direction)) {
    throw new CrmError("validation", `unknown activity direction '${direction}'`);
  }
  const channel = reqStr(input.channel, "channel");
  if (!(CHANNELS as readonly string[]).includes(channel)) {
    throw new CrmError("validation", `unknown activity channel '${channel}'`);
  }
  const origin = input.origin === undefined ? "manual" : reqStr(input.origin, "origin");
  if (!["manual", "ai_agent"].includes(origin)) {
    throw new CrmError("validation", `unknown activity origin '${origin}'`);
  }
  const subject = optStr(input.subject);
  const body = optStr(input.body, 20000);
  if (subject === null && body === null) {
    throw new CrmError("validation", "an activity needs a subject or a body");
  }
  let companyId: number | null = null;
  let contactId: number | null = null;
  let dealId: number | null = null;
  if (input.company_id !== undefined && input.company_id !== null) {
    companyId = reqInt(input.company_id, "company_id", { min: 1 });
    mustExist(db, "companies", companyId, "company");
  }
  if (input.contact_id !== undefined && input.contact_id !== null) {
    contactId = reqInt(input.contact_id, "contact_id", { min: 1 });
    mustExist(db, "contacts", contactId, "contact");
  }
  if (input.deal_id !== undefined && input.deal_id !== null) {
    dealId = reqInt(input.deal_id, "deal_id", { min: 1 });
    mustExist(db, "deals", dealId, "deal");
  }
  // F-S4: an AI-agent communication is unreviewed supervision by
  // construction — it always enters the review queue, whether or not
  // the caller flagged it. Manual comms enter only when flagged.
  const flagged = origin === "ai_agent" || input.flagged_for_review === true;
  const supervisionStatus = origin === "ai_agent" ? "unreviewed" : "not_required";
  const now = nowIso();
  return db.transaction((): ActivityRow => {
    const info = db
      .query(
        `INSERT INTO activities
           (direction, channel, origin, subject, body, company_id, contact_id,
            deal_id, author_id, flagged_for_review, supervision_status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        direction,
        channel,
        origin,
        subject,
        body,
        companyId,
        contactId,
        dealId,
        actorId,
        flagged ? 1 : 0,
        supervisionStatus,
        now,
      );
    const id = Number(info.lastInsertRowid);
    appendAudit(db, {
      actor_id: actorId,
      action: "activity.create",
      entity_type: "activity",
      entity_id: id,
      after: { direction, channel, origin, flagged_for_review: flagged },
    });
    return activityRow(db, id)!;
  })();
}

// --- comms reviews: principal review queue (F-S1, F-S3) -------------------------

export interface ReviewQueueRow extends ActivityRow {
  author_email: string | null;
}

export interface CommsReviewRow {
  id: number;
  activity_id: number;
  reviewer_id: number;
  reviewer_email: string | null;
  disposition: string;
  notes: string | null;
  reviewed_at: string;
}

/** Flagged activities with no review row yet — the principal's queue. */
export function reviewQueue(db: Database): ReviewQueueRow[] {
  return db
    .query(
      `SELECT a.*, u.email AS author_email FROM activities a
       LEFT JOIN comms_reviews r ON r.activity_id = a.id
       LEFT JOIN users u ON u.id = a.author_id
       WHERE a.flagged_for_review = 1 AND r.id IS NULL
       ORDER BY a.id ASC`,
    )
    .all() as ReviewQueueRow[];
}

export function getCommsReview(db: Database, activityId: number): CommsReviewRow | null {
  const row = db
    .query(
      `SELECT r.*, u.email AS reviewer_email FROM comms_reviews r
       LEFT JOIN users u ON u.id = r.reviewer_id WHERE r.activity_id = ?`,
    )
    .get(activityId) as CommsReviewRow | undefined;
  return row ?? null;
}

function isPrincipal(db: Database, userId: number): boolean {
  const row = db.query("SELECT is_principal FROM users WHERE id = ?").get(userId) as
    | { is_principal: number }
    | undefined;
  return row?.is_principal === 1;
}

/**
 * Principal review of a flagged communication. Order of checks matters:
 * a principal reviewing their own comm is self_review (F-S3 no
 * self-supervision), not merely not_principal — the specific code is
 * the supervision evidence.
 */
export function reviewActivity(
  db: Database,
  activityId: number,
  reviewerId: number,
  disposition: string,
  notes: string | null,
): CommsReviewRow {
  const activity = activityRow(db, activityId);
  if (!activity) throw new CrmError("not_found", `activity ${activityId} not found`);
  if (activity.flagged_for_review !== 1) {
    throw new CrmError("not_flagged", `activity ${activityId} was not flagged for review`);
  }
  if (getCommsReview(db, activityId)) {
    throw new CrmError("already_reviewed", `activity ${activityId} already has a review`);
  }
  if (activity.author_id !== null && activity.author_id === reviewerId) {
    throw new CrmError(
      "self_review",
      "a principal cannot review their own communication (no self-supervision)",
    );
  }
  if (!isPrincipal(db, reviewerId)) {
    throw new CrmError("not_principal", "reviewer is not a designated principal");
  }
  if (!["approved", "rejected"].includes(disposition)) {
    throw new CrmError("validation", `unknown disposition '${disposition}'`);
  }
  const now = nowIso();
  return db.transaction((): CommsReviewRow => {
    const info = db
      .query(
        `INSERT INTO comms_reviews (activity_id, reviewer_id, disposition, notes, reviewed_at)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(activityId, reviewerId, disposition, notes, now);
    void info;
    appendAudit(db, {
      actor_id: reviewerId,
      action: "comm.review",
      entity_type: "activity",
      entity_id: activityId,
      before: { supervision_status: activity.supervision_status },
      after: { disposition, reviewed_by: reviewerId },
    });
    return getCommsReview(db, activityId)!;
  })();
}

// --- supervisory personnel (F-S3) ----------------------------------------------

export interface PrincipalRow {
  id: number;
  email: string;
  title: string | null;
  location: string | null;
  is_principal: number;
}

export function listPrincipals(db: Database): PrincipalRow[] {
  return db
    .query(
      "SELECT id, email, title, location, is_principal FROM users WHERE is_principal = 1 ORDER BY id ASC",
    )
    .all() as PrincipalRow[];
}

export function designatePrincipal(
  db: Database,
  userId: number,
  title: string | null,
  location: string | null,
  actorId: number | null,
): PrincipalRow {
  const user = db.query("SELECT * FROM users WHERE id = ?").get(userId) as
    | { is_principal: number; email: string }
    | undefined;
  if (!user) throw new CrmError("not_found", `user ${userId} not found`);
  if (user.is_principal === 1) {
    throw new CrmError("already_principal", `user ${userId} is already a designated principal`);
  }
  return db.transaction((): PrincipalRow => {
    db.query("UPDATE users SET is_principal = 1, title = ?, location = ?, updated_at = ? WHERE id = ?").run(
      title,
      location,
      nowIso(),
      userId,
    );
    appendAudit(db, {
      actor_id: actorId,
      action: "crm.principal_designate",
      entity_type: "user",
      entity_id: userId,
      before: { is_principal: 0 },
      after: { is_principal: 1, title, location },
    });
    return db.query(
      "SELECT id, email, title, location, is_principal FROM users WHERE id = ?",
    ).get(userId) as PrincipalRow;
  })();
}

export function revokePrincipal(
  db: Database,
  userId: number,
  actorId: number | null,
): PrincipalRow {
  const user = db.query("SELECT * FROM users WHERE id = ?").get(userId) as
    | { is_principal: number }
    | undefined;
  if (!user) throw new CrmError("not_found", `user ${userId} not found`);
  if (user.is_principal !== 1) {
    throw new CrmError("not_principal", `user ${userId} is not a designated principal`);
  }
  return db.transaction((): PrincipalRow => {
    db.query("UPDATE users SET is_principal = 0, updated_at = ? WHERE id = ?").run(nowIso(), userId);
    appendAudit(db, {
      actor_id: actorId,
      action: "crm.principal_revoke",
      entity_type: "user",
      entity_id: userId,
      before: { is_principal: 1 },
      after: { is_principal: 0 },
    });
    return db.query(
      "SELECT id, email, title, location, is_principal FROM users WHERE id = ?",
    ).get(userId) as PrincipalRow;
  })();
}

// --- complaints (F-R9, F-S2) ------------------------------------------------------

export interface ComplaintRow {
  id: number;
  company_id: number | null;
  contact_id: number | null;
  subject: string;
  description: string | null;
  status: string;
  ack_sla_days: number;
  received_at: string;
  acknowledged_at: string | null;
  responded_at: string | null;
  created_by: number | null;
  created_at: string;
  updated_at: string;
}

export interface ComplaintView extends ComplaintRow {
  acknowledged_overdue: boolean;
}

export interface ComplaintInput {
  company_id?: unknown;
  contact_id?: unknown;
  subject?: unknown;
  description?: unknown;
  ack_sla_days?: unknown;
}

function complaintRow(db: Database, id: number): ComplaintRow | null {
  const row = db.query("SELECT * FROM complaints WHERE id = ?").get(id) as ComplaintRow | undefined;
  return row ?? null;
}

/** Unacknowledged past its SLA date (received_at + ack_sla_days < today). */
export function complaintView(row: ComplaintRow): ComplaintView {
  let overdue = false;
  if (row.status === "received") {
    const received = Date.parse(row.received_at);
    if (!Number.isNaN(received)) {
      overdue = received + row.ack_sla_days * 24 * 60 * 60 * 1000 < Date.now();
    }
  }
  return { ...row, acknowledged_overdue: overdue };
}

export function getComplaint(db: Database, id: number): ComplaintView | null {
  const row = complaintRow(db, id);
  return row ? complaintView(row) : null;
}

export function listComplaints(
  db: Database,
  opts: { status?: string; overdue_ack?: boolean } = {},
): ComplaintView[] {
  if (opts.status !== undefined && !["received", "acknowledged", "responded"].includes(opts.status)) {
    throw new CrmError("validation", `unknown complaint status '${opts.status}'`);
  }
  const where: string[] = [];
  const params: string[] = [];
  if (opts.status !== undefined) {
    where.push("status = ?");
    params.push(opts.status);
  }
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const rows = db.query(`SELECT * FROM complaints ${clause} ORDER BY id DESC`).all(...params) as ComplaintRow[];
  const views = rows.map(complaintView);
  return opts.overdue_ack === true ? views.filter((v) => v.acknowledged_overdue) : views;
}

export function createComplaint(
  db: Database,
  input: ComplaintInput,
  actorId: number | null,
): ComplaintView {
  const subject = reqStr(input.subject, "subject", 500);
  let companyId: number | null = null;
  let contactId: number | null = null;
  if (input.company_id !== undefined && input.company_id !== null) {
    companyId = reqInt(input.company_id, "company_id", { min: 1 });
    mustExist(db, "companies", companyId, "company");
  }
  if (input.contact_id !== undefined && input.contact_id !== null) {
    contactId = reqInt(input.contact_id, "contact_id", { min: 1 });
    mustExist(db, "contacts", contactId, "contact");
  }
  if (companyId === null && contactId === null) {
    throw new CrmError("validation", "a complaint needs a company_id or a contact_id");
  }
  const sla =
    input.ack_sla_days === undefined ? 7 : reqInt(input.ack_sla_days, "ack_sla_days", { min: 1 });
  const now = nowIso();
  return db.transaction((): ComplaintView => {
    const info = db
      .query(
        `INSERT INTO complaints
           (company_id, contact_id, subject, description, status, ack_sla_days,
            received_at, created_by, created_at, updated_at)
         VALUES (?, ?, ?, ?, 'received', ?, ?, ?, ?, ?)`,
      )
      .run(
        companyId,
        contactId,
        subject,
        optStr(input.description, 20000),
        sla,
        now,
        actorId,
        now,
        now,
      );
    const id = Number(info.lastInsertRowid);
    appendAudit(db, {
      actor_id: actorId,
      action: "complaint.create",
      entity_type: "complaint",
      entity_id: id,
      after: { subject, status: "received" },
    });
    return complaintView(complaintRow(db, id)!);
  })();
}

function transitionComplaint(
  db: Database,
  id: number,
  from: string,
  to: string,
  timestampCol: string,
  actorId: number | null,
): ComplaintView {
  const before = complaintRow(db, id);
  if (!before) throw new CrmError("not_found", `complaint ${id} not found`);
  if (before.status !== from) {
    throw new CrmError(
      "state_regression",
      `complaint ${id} is ${before.status} and cannot move to ${to} (expected ${from} first)`,
    );
  }
  const now = nowIso();
  return db.transaction((): ComplaintView => {
    db.query(
      `UPDATE complaints SET status = ?, ${timestampCol} = ?, updated_at = ? WHERE id = ?`,
    ).run(to, now, now, id);
    appendAudit(db, {
      actor_id: actorId,
      action: `complaint.${to}`,
      entity_type: "complaint",
      entity_id: id,
      before: { status: before.status },
      after: { status: to },
    });
    return complaintView(complaintRow(db, id)!);
  })();
}

/** received → acknowledged (starts the response clock, F-S2). */
export function acknowledgeComplaint(
  db: Database,
  id: number,
  actorId: number | null,
): ComplaintView {
  return transitionComplaint(db, id, "received", "acknowledged", "acknowledged_at", actorId);
}

/** acknowledged → responded (closes the complaint workflow). */
export function respondComplaint(
  db: Database,
  id: number,
  actorId: number | null,
): ComplaintView {
  return transitionComplaint(db, id, "acknowledged", "responded", "responded_at", actorId);
}
