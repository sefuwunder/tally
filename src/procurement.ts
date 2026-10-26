// Tally ERP — procurement.ts
// Phase 6: purchase orders (+lines, status machine), receivings that
// post inventory movements AND accrue AP, atomically.
//
// Status machine:
//   draft → open → partially_received → fully_received → closed
//   draft / open / partially_received → cancelled
// A fully_received PO cannot be cancelled (the goods are in stock —
// close it instead); a closed or cancelled PO never moves again.
// Draft-only edits, like AP bills: once a PO is open, its lines are
// history in progress, corrected only by receiving less / closing.
//
// Receiving (the acceptance-critical path):
//   - Every receiving line must reference a line OF THIS PO — a line
//     id that does not exist is not_found; one from another PO is
//     line_mismatch. There is no way to receive "without a PO line":
//     the input carries no item_id at all, only po_line_id + quantity,
//     so the item and the price always come from the PO line itself.
//   - Quantities are validated against the remaining quantity
//     (ordered − received) BEFORE any write, including combined
//     duplicates in one receiving; the po_lines CHECK
//     (received <= ordered) is the DB-level backstop.
//   - One transaction books everything: the accrual journal
//     (Dr each item's Inventory account / Cr AP 2000, grouped by
//     account), the stock receipt movements (via inventory
//     receiveStock, so weighted-average costing moves with the
//     goods), the receiving rows (append-only triggers, F-R3), the
//     po_lines quantity_received bumps, and the PO status step.
//     A closed period, an inactive item, or an over-receipt rolls
//     the whole receiving back — never a movement without its
//     accrual, never an accrual without its movement.
//   - The accrual is a journal entry, NOT a bills row: a bill must
//     still pass AP maker-checker approval (Phase 4), so receiving
//     never mints an approved bill on its own. Matching a later
//     vendor invoice bill against this accrual (3-way match /
//     GR-IR clearing) is post-v1 — the receiving's accrued_entry_id
//     is the hook it will match against. Until then, do NOT also
//     post a bill for the same goods: the accrual already credits
//     AP 2000 for them.
//   - Zero-cost receivings (free goods) post no journal entry — a
//     0-cent entry would fail postJournal's balance rule — and
//     accrued_entry_id stays null, exactly like zero-cost issues.
//
// Conventions from phases 0–5: money in integer cents; all writes in
// transactions; audit row inside the same transaction (sync
// appendAudit); ProcurementError with a stable .code the HTTP layer
// maps to a status. LedgerError passes through untouched.

import type { Database } from "bun:sqlite";
import { appendAudit } from "./audit";
import { nowIso } from "./db";
import { postJournal, LedgerError } from "./ledger";
import { receiveStock, getItem } from "./inventory";
import { getVendor } from "./ap";

export class ProcurementError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "ProcurementError";
    this.code = code;
  }
}

function isValidDate(d: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) return false;
  const dt = new Date(`${d}T00:00:00Z`);
  return !Number.isNaN(dt.getTime()) && dt.toISOString().slice(0, 10) === d;
}

function todayDate(): string {
  return new Date().toISOString().slice(0, 10);
}

function reqInt(v: unknown, label: string, opts: { min?: number } = {}): number {
  if (typeof v !== "number" || !Number.isInteger(v)) {
    throw new ProcurementError("validation", `${label} must be an integer`);
  }
  if (opts.min !== undefined && v < opts.min) {
    throw new ProcurementError("validation", `${label} must be >= ${opts.min}`);
  }
  return v;
}

function reqDate(v: unknown, label: string): string {
  if (typeof v !== "string" || !isValidDate(v)) {
    throw new ProcurementError("validation", `${label} must be YYYY-MM-DD`);
  }
  return v;
}

/** Monotonic document numbers, allocated inside the caller's transaction. */
function nextDocNo(db: Database, name: string, prefix: string): string {
  const row = db
    .query(
      `INSERT INTO sequences (name, next_val) VALUES (?, 1)
       ON CONFLICT (name) DO UPDATE SET next_val = next_val + 1
       RETURNING next_val`,
    )
    .get(name) as { next_val: number };
  return `${prefix}-${String(row.next_val).padStart(6, "0")}`;
}

// --- purchase orders ------------------------------------------------------------

export interface PoLineInput {
  item_id: number;
  quantity_ordered: number;
  unit_cost_cents: number;
}

export interface PoLineRow {
  id: number;
  po_id: number;
  item_id: number;
  sku: string;
  quantity_ordered: number;
  unit_cost_cents: number;
  quantity_received: number;
  remaining_cents: number;
  remaining_quantity: number;
  ordered_total_cents: number;
}

export interface PurchaseOrderRow {
  id: number;
  po_no: string;
  vendor_id: number;
  status: string;
  order_date: string;
  expected_date: string | null;
  notes: string | null;
  created_by: number | null;
  created_at: string;
  updated_at: string;
}

export interface PurchaseOrderView extends PurchaseOrderRow {
  lines: PoLineRow[];
  ordered_total_cents: number;
  received_total_cents: number;
}

export interface PurchaseOrderInput {
  vendor_id: number;
  order_date: string;
  expected_date?: string | null;
  notes?: string | null;
  lines: PoLineInput[];
}

function poLines(db: Database, poId: number): PoLineRow[] {
  const rows = db
    .query(
      `SELECT pl.id, pl.po_id, pl.item_id, i.sku, pl.quantity_ordered,
              pl.unit_cost_cents, pl.quantity_received
       FROM po_lines pl JOIN items i ON i.id = pl.item_id
       WHERE pl.po_id = ? ORDER BY pl.id ASC`,
    )
    .all(poId) as {
    id: number;
    po_id: number;
    item_id: number;
    sku: string;
    quantity_ordered: number;
    unit_cost_cents: number;
    quantity_received: number;
  }[];
  return rows.map((r) => ({
    ...r,
    remaining_quantity: r.quantity_ordered - r.quantity_received,
    remaining_cents: (r.quantity_ordered - r.quantity_received) * r.unit_cost_cents,
    ordered_total_cents: r.quantity_ordered * r.unit_cost_cents,
  }));
}

function poView(db: Database, po: PurchaseOrderRow): PurchaseOrderView {
  const lines = poLines(db, po.id);
  return {
    ...po,
    lines,
    ordered_total_cents: lines.reduce((s, l) => s + l.ordered_total_cents, 0),
    received_total_cents: lines.reduce((s, l) => s + l.quantity_received * l.unit_cost_cents, 0),
  };
}

function getPoRow(db: Database, id: number): PurchaseOrderRow | null {
  const row = db.query("SELECT * FROM purchase_orders WHERE id = ?").get(id) as
    | PurchaseOrderRow
    | undefined;
  return row ?? null;
}

export function getPurchaseOrder(db: Database, id: number): PurchaseOrderView | null {
  const row = getPoRow(db, id);
  return row ? poView(db, row) : null;
}

export function listPurchaseOrders(
  db: Database,
  opts: { vendor_id?: number; status?: string } = {},
): PurchaseOrderView[] {
  const where: string[] = [];
  const params: (number | string)[] = [];
  if (opts.vendor_id !== undefined) {
    where.push("vendor_id = ?");
    params.push(opts.vendor_id);
  }
  if (opts.status !== undefined) {
    if (
      !["draft", "open", "partially_received", "fully_received", "closed", "cancelled"].includes(
        opts.status,
      )
    ) {
      throw new ProcurementError("validation", `unknown PO status '${opts.status}'`);
    }
    where.push("status = ?");
    params.push(opts.status);
  }
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const rows = db
    .query(`SELECT * FROM purchase_orders ${clause} ORDER BY id DESC`)
    .all(...params) as PurchaseOrderRow[];
  return rows.map((r) => poView(db, r));
}

function validatePoLines(db: Database, raw: unknown): PoLineInput[] {
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new ProcurementError("validation", "a purchase order needs at least one line");
  }
  const lines: PoLineInput[] = [];
  let i = 0;
  for (const ln of raw) {
    i++;
    if (typeof ln !== "object" || ln === null) {
      throw new ProcurementError("validation", `line ${i}: must be an object`);
    }
    const l = ln as Record<string, unknown>;
    const itemId = reqInt(l.item_id, `line ${i}: item_id`, { min: 1 });
    if (!getItem(db, itemId)) {
      throw new ProcurementError("not_found", `line ${i}: item ${itemId} not found`);
    }
    const qty = reqInt(l.quantity_ordered, `line ${i}: quantity_ordered`, { min: 1 });
    const unitCost = reqInt(l.unit_cost_cents, `line ${i}: unit_cost_cents`, { min: 0 });
    lines.push({ item_id: itemId, quantity_ordered: qty, unit_cost_cents: unitCost });
  }
  return lines;
}

export function createPurchaseOrder(
  db: Database,
  input: PurchaseOrderInput,
  actorId: number | null,
): PurchaseOrderView {
  const vendorId = reqInt(input.vendor_id, "vendor_id", { min: 1 });
  if (!getVendor(db, vendorId)) {
    throw new ProcurementError("not_found", `vendor ${vendorId} not found`);
  }
  const orderDate = reqDate(input.order_date, "order_date");
  let expectedDate: string | null = null;
  if (input.expected_date !== undefined && input.expected_date !== null) {
    expectedDate = reqDate(input.expected_date, "expected_date");
    if (expectedDate < orderDate) {
      throw new ProcurementError("validation", "expected_date must not be before order_date");
    }
  }
  const notes =
    typeof input.notes === "string" ? input.notes.trim().slice(0, 2000) : null;
  const lines = validatePoLines(db, input.lines);
  const now = nowIso();
  return db.transaction((): PurchaseOrderView => {
    const poNo = nextDocNo(db, "purchase_order", "PO");
    const info = db
      .query(
        `INSERT INTO purchase_orders
           (po_no, vendor_id, status, order_date, expected_date, notes,
            created_by, created_at, updated_at)
         VALUES (?, ?, 'draft', ?, ?, ?, ?, ?, ?)`,
      )
      .run(poNo, vendorId, orderDate, expectedDate, notes, actorId, now, now);
    const id = Number(info.lastInsertRowid);
    const insertLine = db.query(
      "INSERT INTO po_lines (po_id, item_id, quantity_ordered, unit_cost_cents) VALUES (?, ?, ?, ?)",
    );
    for (const l of lines) {
      insertLine.run(id, l.item_id, l.quantity_ordered, l.unit_cost_cents);
    }
    appendAudit(db, {
      actor_id: actorId,
      action: "po.create",
      entity_type: "purchase_order",
      entity_id: poNo,
      after: { vendor_id: vendorId, lines: lines.length },
    });
    return getPurchaseOrder(db, id)!;
  })();
}

/** Draft-only edit: vendor, dates, notes, and/or a full line replacement. */
export function updatePurchaseOrderDraft(
  db: Database,
  id: number,
  input: {
    vendor_id?: number;
    order_date?: string;
    expected_date?: string | null;
    notes?: string | null;
    lines?: PoLineInput[];
  },
  actorId: number | null,
): PurchaseOrderView {
  const po = getPoRow(db, id);
  if (!po) throw new ProcurementError("not_found", `purchase order ${id} not found`);
  if (po.status !== "draft") {
    throw new ProcurementError(
      "not_draft",
      `PO ${po.po_no} is ${po.status} and cannot be edited (close or cancel it instead)`,
    );
  }
  let vendorId = po.vendor_id;
  if (input.vendor_id !== undefined) {
    vendorId = reqInt(input.vendor_id, "vendor_id", { min: 1 });
    if (!getVendor(db, vendorId)) {
      throw new ProcurementError("not_found", `vendor ${vendorId} not found`);
    }
  }
  let orderDate = po.order_date;
  if (input.order_date !== undefined) orderDate = reqDate(input.order_date, "order_date");
  let expectedDate = po.expected_date;
  if (input.expected_date !== undefined) {
    expectedDate =
      input.expected_date === null ? null : reqDate(input.expected_date, "expected_date");
  }
  if (expectedDate !== null && expectedDate < orderDate) {
    throw new ProcurementError("validation", "expected_date must not be before order_date");
  }
  const notes =
    input.notes === undefined
      ? po.notes
      : typeof input.notes === "string"
        ? input.notes.trim().slice(0, 2000)
        : null;
  let lines: PoLineInput[] | null = null;
  if (input.lines !== undefined) lines = validatePoLines(db, input.lines);
  return db.transaction((): PurchaseOrderView => {
    if (lines !== null) {
      db.query("DELETE FROM po_lines WHERE po_id = ?").run(id);
      const insertLine = db.query(
        "INSERT INTO po_lines (po_id, item_id, quantity_ordered, unit_cost_cents) VALUES (?, ?, ?, ?)",
      );
      for (const l of lines) {
        insertLine.run(id, l.item_id, l.quantity_ordered, l.unit_cost_cents);
      }
    }
    db.query(
      "UPDATE purchase_orders SET vendor_id = ?, order_date = ?, expected_date = ?, notes = ?, updated_at = ? WHERE id = ?",
    ).run(vendorId, orderDate, expectedDate, notes, nowIso(), id);
    appendAudit(db, {
      actor_id: actorId,
      action: "po.update",
      entity_type: "purchase_order",
      entity_id: po.po_no,
      before: { vendor_id: po.vendor_id, status: "draft" },
      after: { vendor_id: vendorId, status: "draft" },
    });
    return getPurchaseOrder(db, id)!;
  })();
}

function transitionPo(
  db: Database,
  id: number,
  action: string,
  allowed: string[],
  target: string,
  actorId: number | null,
  blockedCode: (po: PurchaseOrderRow) => string | null,
): PurchaseOrderView {
  const po = getPoRow(db, id);
  if (!po) throw new ProcurementError("not_found", `purchase order ${id} not found`);
  const blocked = blockedCode(po);
  if (blocked) throw new ProcurementError(blocked, `PO ${po.po_no} is ${po.status} and cannot be ${action}`);
  if (!allowed.includes(po.status)) {
    throw new ProcurementError(
      "not_receivable",
      `PO ${po.po_no} is ${po.status} and cannot be ${action}`,
    );
  }
  const now = nowIso();
  return db.transaction((): PurchaseOrderView => {
    db.query("UPDATE purchase_orders SET status = ?, updated_at = ? WHERE id = ?").run(
      target,
      now,
      id,
    );
    appendAudit(db, {
      actor_id: actorId,
      action: `po.${action}`,
      entity_type: "purchase_order",
      entity_id: po.po_no,
      before: { status: po.status },
      after: { status: target },
    });
    return getPurchaseOrder(db, id)!;
  })();
}

/** draft → open. */
export function submitPurchaseOrder(
  db: Database,
  id: number,
  actorId: number | null,
): PurchaseOrderView {
  const po = getPoRow(db, id);
  if (!po) throw new ProcurementError("not_found", `purchase order ${id} not found`);
  if (po.status !== "draft") {
    if (po.status === "closed") throw new ProcurementError("already_closed", `PO ${po.po_no} is closed`);
    if (po.status === "cancelled") throw new ProcurementError("already_cancelled", `PO ${po.po_no} is cancelled`);
    throw new ProcurementError("not_draft", `PO ${po.po_no} is ${po.status}, not draft`);
  }
  return transitionPo(db, id, "submit", ["draft"], "open", actorId, () => null);
}

/** open / partially_received / fully_received → closed. */
export function closePurchaseOrder(
  db: Database,
  id: number,
  actorId: number | null,
): PurchaseOrderView {
  return transitionPo(db, id, "close", ["open", "partially_received", "fully_received"], "closed", actorId, (po) => {
    if (po.status === "closed") return "already_closed";
    if (po.status === "cancelled") return "already_cancelled";
    if (po.status === "draft") return "not_submitted";
    return null;
  });
}

/** draft / open / partially_received → cancelled. Fully received goods are
 *  in stock, so a fully_received PO closes instead of cancelling. */
export function cancelPurchaseOrder(
  db: Database,
  id: number,
  actorId: number | null,
): PurchaseOrderView {
  return transitionPo(db, id, "cancel", ["draft", "open", "partially_received"], "cancelled", actorId, (po) => {
    if (po.status === "closed") return "already_closed";
    if (po.status === "cancelled") return "already_cancelled";
    if (po.status === "fully_received") return "not_cancellable";
    return null;
  });
}

// --- receivings -----------------------------------------------------------------

export interface ReceivingLineInput {
  po_line_id: number;
  quantity: number;
}

export interface ReceivingLineRow {
  id: number;
  receiving_id: number;
  po_line_id: number;
  item_id: number;
  sku: string;
  quantity: number;
  unit_cost_cents: number;
  total_cents: number;
}

export interface ReceivingRow {
  id: number;
  receiving_no: string;
  po_id: number;
  po_no: string;
  warehouse_id: number;
  warehouse_code: string;
  receiving_date: string;
  accrued_entry_id: number | null;
  accrued_entry_no: string | null;
  received_by: number | null;
  created_at: string;
}

export interface ReceivingView extends ReceivingRow {
  lines: ReceivingLineRow[];
  total_cents: number;
}

export interface ReceivingInput {
  warehouse_id: number;
  receiving_date?: string;
  lines: ReceivingLineInput[];
}

function receivingLines(db: Database, receivingId: number): ReceivingLineRow[] {
  const rows = db
    .query(
      `SELECT rl.id, rl.receiving_id, rl.po_line_id, rl.item_id, i.sku,
              rl.quantity, rl.unit_cost_cents
       FROM receiving_lines rl JOIN items i ON i.id = rl.item_id
       WHERE rl.receiving_id = ? ORDER BY rl.id ASC`,
    )
    .all(receivingId) as {
    id: number;
    receiving_id: number;
    po_line_id: number;
    item_id: number;
    sku: string;
    quantity: number;
    unit_cost_cents: number;
  }[];
  return rows.map((r) => ({ ...r, total_cents: r.quantity * r.unit_cost_cents }));
}

function receivingView(db: Database, r: ReceivingRow): ReceivingView {
  const lines = receivingLines(db, r.id);
  return { ...r, lines, total_cents: lines.reduce((s, l) => s + l.total_cents, 0) };
}

function getReceivingRow(db: Database, id: number): ReceivingRow | null {
  const row = db
    .query(
      `SELECT r.id, r.receiving_no, r.po_id, po.po_no, r.warehouse_id, w.code AS warehouse_code,
              r.receiving_date, r.accrued_entry_id, je.entry_no AS accrued_entry_no,
              r.received_by, r.created_at
       FROM receivings r
       JOIN purchase_orders po ON po.id = r.po_id
       JOIN warehouses w ON w.id = r.warehouse_id
       LEFT JOIN journal_entries je ON je.id = r.accrued_entry_id
       WHERE r.id = ?`,
    )
    .get(id) as ReceivingRow | undefined;
  return row ?? null;
}

export function getReceiving(db: Database, id: number): ReceivingView | null {
  const row = getReceivingRow(db, id);
  return row ? receivingView(db, row) : null;
}

export function listReceivings(
  db: Database,
  opts: { po_id?: number; warehouse_id?: number } = {},
): ReceivingView[] {
  const where: string[] = [];
  const params: number[] = [];
  if (opts.po_id !== undefined) {
    where.push("r.po_id = ?");
    params.push(opts.po_id);
  }
  if (opts.warehouse_id !== undefined) {
    where.push("r.warehouse_id = ?");
    params.push(opts.warehouse_id);
  }
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const rows = db
    .query(
      `SELECT r.id, r.receiving_no, r.po_id, po.po_no, r.warehouse_id, w.code AS warehouse_code,
              r.receiving_date, r.accrued_entry_id, je.entry_no AS accrued_entry_no,
              r.received_by, r.created_at
       FROM receivings r
       JOIN purchase_orders po ON po.id = r.po_id
       JOIN warehouses w ON w.id = r.warehouse_id
       LEFT JOIN journal_entries je ON je.id = r.accrued_entry_id
       ${clause} ORDER BY r.id DESC`,
    )
    .all(...params) as ReceivingRow[];
  return rows.map((r) => receivingView(db, r));
}

/**
 * Book a receiving: stock movements + AP accrual + PO progress, atomically.
 * See the module header for the full contract.
 */
export function receivePurchaseOrder(
  db: Database,
  poId: number,
  input: ReceivingInput,
  actorId: number | null,
): ReceivingView {
  const po = getPoRow(db, poId);
  if (!po) throw new ProcurementError("not_found", `purchase order ${poId} not found`);
  if (po.status !== "open" && po.status !== "partially_received") {
    throw new ProcurementError(
      "not_receivable",
      `PO ${po.po_no} is ${po.status} and cannot receive goods`,
    );
  }
  const warehouseId = reqInt(input.warehouse_id, "warehouse_id", { min: 1 });
  const warehouse = db.query("SELECT id FROM warehouses WHERE id = ?").get(warehouseId) as
    | { id: number }
    | undefined;
  if (!warehouse) throw new ProcurementError("not_found", `warehouse ${warehouseId} not found`);
  const receivingDate =
    input.receiving_date !== undefined ? reqDate(input.receiving_date, "receiving_date") : todayDate();
  if (!Array.isArray(input.lines) || input.lines.length === 0) {
    throw new ProcurementError("validation", "a receiving needs at least one line");
  }

  // Validate every line BEFORE writing anything. Duplicates of the same
  // PO line in one receiving are combined (AP-payment precedent) and
  // checked jointly against the remaining quantity.
  const poLineById = new Map<number, PoLineRow>();
  for (const l of poLines(db, poId)) poLineById.set(l.id, l);
  const combined = new Map<number, number>();
  let i = 0;
  for (const ln of input.lines) {
    i++;
    if (typeof ln !== "object" || ln === null) {
      throw new ProcurementError("validation", `line ${i}: must be an object`);
    }
    const l = ln as Record<string, unknown>;
    const poLineId = reqInt(l.po_line_id, `line ${i}: po_line_id`, { min: 1 });
    const qty = reqInt(l.quantity, `line ${i}: quantity`, { min: 1 });
    const poLine = db.query("SELECT * FROM po_lines WHERE id = ?").get(poLineId) as
      | { id: number; po_id: number; item_id: number; quantity_ordered: number; unit_cost_cents: number; quantity_received: number }
      | undefined;
    if (!poLine) throw new ProcurementError("not_found", `line ${i}: PO line ${poLineId} not found`);
    if (poLine.po_id !== poId) {
      throw new ProcurementError(
        "line_mismatch",
        `line ${i}: PO line ${poLineId} belongs to a different purchase order, not ${po.po_no}`,
      );
    }
    combined.set(poLineId, (combined.get(poLineId) ?? 0) + qty);
  }
  const resolved: { poLine: PoLineRow; quantity: number }[] = [];
  for (const [poLineId, qty] of combined) {
    const poLine = poLineById.get(poLineId)!;
    if (qty > poLine.remaining_quantity) {
      throw new ProcurementError(
        "over_received",
        `receiving ${qty} of ${poLine.sku} exceeds the remaining ${poLine.remaining_quantity} on ${po.po_no}`,
      );
    }
    resolved.push({ poLine, quantity: qty });
  }

  const now = nowIso();
  return db.transaction((): ReceivingView => {
    // 1. Accrual journal first (fail fast on a closed period): Dr each
    //    item's Inventory account / Cr AP 2000, grouped by account.
    const byAccount = new Map<string, number>();
    let total = 0;
    for (const { poLine, quantity } of resolved) {
      const item = getItem(db, poLine.item_id)!;
      const amount = quantity * poLine.unit_cost_cents;
      total += amount;
      if (amount > 0) {
        byAccount.set(
          item.inventory_account_code,
          (byAccount.get(item.inventory_account_code) ?? 0) + amount,
        );
      }
    }
    const posted =
      total > 0
        ? postJournal(db, {
            memo: `Receiving for ${po.po_no}`,
            lines: [
              ...[...byAccount.entries()].map(([account_code, debit_cents]) => ({
                account_code,
                debit_cents,
              })),
              { account_code: "2000", credit_cents: total },
            ],
            actor_id: actorId,
            posted_on: receivingDate,
            source_type: "procurement",
            source_id: `receiving:${po.po_no}`,
          })
        : null;

    // 2. Receiving header + lines. (Receivings are append-only, so the
    //    entry id must be known before the insert — hence journal first.)
    const receivingNo = nextDocNo(db, "receiving", "RCV");
    const info = db
      .query(
        `INSERT INTO receivings
           (receiving_no, po_id, warehouse_id, receiving_date,
            accrued_entry_id, received_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(receivingNo, poId, warehouseId, receivingDate, posted?.id ?? null, actorId, now);
    const receivingId = Number(info.lastInsertRowid);
    const insertLine = db.query(
      "INSERT INTO receiving_lines (receiving_id, po_line_id, item_id, quantity, unit_cost_cents) VALUES (?, ?, ?, ?, ?)",
    );
    for (const { poLine, quantity } of resolved) {
      insertLine.run(receivingId, poLine.id, poLine.item_id, quantity, poLine.unit_cost_cents);
    }

    // 3. Stock movements (weighted-average costing moves with the goods)
    //    and PO progress, in the same transaction.
    for (const { poLine, quantity } of resolved) {
      receiveStock(db, {
        item_id: poLine.item_id,
        warehouse_id: warehouseId,
        quantity,
        unit_cost_cents: poLine.unit_cost_cents,
        movement_date: receivingDate,
        reason: `Receiving ${receivingNo} for ${po.po_no}`,
        source_type: "procurement",
        source_id: `receiving:${receivingNo}`,
      }, actorId);
      db.query("UPDATE po_lines SET quantity_received = quantity_received + ? WHERE id = ?").run(
        quantity,
        poLine.id,
      );
    }
    const remaining = poLines(db, poId);
    const newStatus = remaining.every((l) => l.remaining_quantity === 0)
      ? "fully_received"
      : "partially_received";
    db.query("UPDATE purchase_orders SET status = ?, updated_at = ? WHERE id = ?").run(
      newStatus,
      now,
      poId,
    );
    appendAudit(db, {
      actor_id: actorId,
      action: "po.receive",
      entity_type: "purchase_order",
      entity_id: po.po_no,
      after: {
        receiving_no: receivingNo,
        entry_no: posted?.entry_no ?? null,
        total_cents: total,
        status: newStatus,
        lines: resolved.map((r) => ({ po_line_id: r.poLine.id, quantity: r.quantity })),
      },
    });
    return getReceiving(db, receivingId)!;
  })();
}

// Re-exported so callers can distinguish ledger failures from procurement failures.
export { LedgerError };
