// Tally ERP — inventory.ts
// Phase 5: items, warehouses, append-only stock movements, weighted-average
// costing, COGS posting on issue/sale.
//
// Rules (roadmap Phase 5):
//  - stock_movements are append-only (trigger-enforced, F-R3). Corrections
//    happen via new adjustment movements, never by editing history.
//  - stock_levels (view) always equals SUM(movements) per item×warehouse;
//    stock_costs.quantity is maintained in the same transaction and the
//    recompute check in tests proves the two agree.
//  - Weighted-average cost: on receipt, new_avg = round((old_qty*old_avg +
//    qty*cost) / (old_qty+qty)) in integer cents. Issues and negative
//    adjustments consume at the current average; the average does not
//    move on an issue. Averages are per item×warehouse.
//  - Negative stock is blocked unless the item allows it
//    (negative_stock, 409). An issue also needs a cost basis: issuing
//    from a location with no receipt history has no COGS to post
//    (no_cost_basis, 400).
//  - COGS posting on issue: Dr COGS (item's cogs_account_code, default
//    5000) / Cr Inventory (item's inventory_account_code, default 1200),
//    amount = qty × avg cost, posted_on = movement_date (open-period
//    rules enforced by postJournal). Receipts, adjustments, and transfers
//    post NO journal entry in v1: receipts are quantity+cost events
//    (Phase 6 procurement posts Dr Inventory / Cr accrual on receiving),
//    adjustments are count corrections reconciled at period end, and a
//    transfer keeps value inside Inventory. This is a documented gap,
//    not an oversight — the GL only ever moves via postJournal.
//  - All financial writes inside one SQLite transaction, audit row inside
//    the same transaction (sync appendAudit).

import type { Database } from "bun:sqlite";
import { appendAudit } from "./audit";
import { nowIso } from "./db";
import { postJournal, LedgerError } from "./ledger";

export class InventoryError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "InventoryError";
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
    throw new InventoryError("validation", `${label} must be an integer`);
  }
  if (opts.min !== undefined && v < opts.min) {
    throw new InventoryError("validation", `${label} must be >= ${opts.min}`);
  }
  return v;
}

function reqDate(v: unknown, label: string): string {
  if (typeof v !== "string" || !isValidDate(v)) {
    throw new InventoryError("validation", `${label} must be YYYY-MM-DD`);
  }
  return v;
}

function reqStr(v: unknown, label: string, max: number): string {
  if (typeof v !== "string" || !v.trim()) {
    throw new InventoryError("validation", `${label} is required`);
  }
  if (v.trim().length > max) {
    throw new InventoryError("validation", `${label} is too long (max ${max} chars)`);
  }
  return v.trim();
}

/** The account code must exist and not be soft-deleted. */
function assertAccountExists(db: Database, code: string, label: string): void {
  const row = db
    .query("SELECT id FROM accounts WHERE code = ? AND deleted_at IS NULL")
    .get(code) as { id: number } | undefined;
  if (!row) throw new InventoryError("validation", `${label}: account code '${code}' not found`);
}

// --- items ----------------------------------------------------------------------

export interface ItemRow {
  id: number;
  sku: string;
  name: string;
  description: string | null;
  unit: string;
  allow_negative_stock: number;
  inventory_account_code: string;
  cogs_account_code: string;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface ItemInput {
  sku: string;
  name: string;
  description?: string | null;
  unit?: string;
  allow_negative_stock?: boolean;
  inventory_account_code?: string;
  cogs_account_code?: string;
  status?: string;
}

function validateItemInput(input: Partial<ItemInput>, partial: boolean): Partial<ItemInput> {
  const out: Partial<ItemInput> = {};
  if (input.sku !== undefined || !partial) out.sku = reqStr(input.sku, "sku", 100);
  if (input.name !== undefined || !partial) out.name = reqStr(input.name, "name", 500);
  if (input.description !== undefined) {
    out.description =
      typeof input.description === "string" ? input.description.trim().slice(0, 2000) : null;
  }
  if (input.unit !== undefined) out.unit = reqStr(input.unit, "unit", 50);
  if (input.allow_negative_stock !== undefined) {
    if (typeof input.allow_negative_stock !== "boolean") {
      throw new InventoryError("validation", "allow_negative_stock must be a boolean");
    }
    out.allow_negative_stock = input.allow_negative_stock;
  }
  if (input.inventory_account_code !== undefined) {
    out.inventory_account_code = reqStr(input.inventory_account_code, "inventory_account_code", 20);
  }
  if (input.cogs_account_code !== undefined) {
    out.cogs_account_code = reqStr(input.cogs_account_code, "cogs_account_code", 20);
  }
  if (input.status !== undefined) {
    if (input.status !== "active" && input.status !== "inactive") {
      throw new InventoryError("validation", "status must be active or inactive");
    }
    out.status = input.status;
  }
  return out;
}

export function getItem(db: Database, id: number): ItemRow | null {
  const row = db.query("SELECT * FROM items WHERE id = ?").get(id) as ItemRow | undefined;
  return row ?? null;
}

export function listItems(db: Database, opts: { status?: string } = {}): ItemRow[] {
  const where: string[] = [];
  const params: string[] = [];
  if (opts.status) {
    if (opts.status !== "active" && opts.status !== "inactive") {
      throw new InventoryError("validation", "status must be active or inactive");
    }
    where.push("status = ?");
    params.push(opts.status);
  }
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
  return db.query(`SELECT * FROM items ${clause} ORDER BY sku ASC, id ASC`).all(...params) as ItemRow[];
}

export function createItem(db: Database, input: ItemInput, actorId: number | null): ItemRow {
  const v = validateItemInput(input, false);
  const invCode = v.inventory_account_code ?? "1200";
  const cogsCode = v.cogs_account_code ?? "5000";
  assertAccountExists(db, invCode, "inventory_account_code");
  assertAccountExists(db, cogsCode, "cogs_account_code");
  const now = nowIso();
  return db.transaction((): ItemRow => {
    const existing = db.query("SELECT id FROM items WHERE sku = ?").get(v.sku!) as
      | { id: number }
      | undefined;
    if (existing) throw new InventoryError("validation", `item sku '${v.sku}' already exists`);
    const info = db
      .query(
        `INSERT INTO items
           (sku, name, description, unit, allow_negative_stock,
            inventory_account_code, cogs_account_code, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        v.sku!,
        v.name!,
        v.description ?? null,
        v.unit ?? "each",
        v.allow_negative_stock ? 1 : 0,
        invCode,
        cogsCode,
        v.status ?? "active",
        now,
        now,
      );
    const id = Number(info.lastInsertRowid);
    appendAudit(db, {
      actor_id: actorId,
      action: "item.create",
      entity_type: "item",
      entity_id: v.sku!,
      after: { name: v.name, unit: v.unit ?? "each" },
    });
    return getItem(db, id)!;
  })();
}

/**
 * Item edit: name/description/unit/allow_negative_stock/status. Account
 * codes may change only while the item has no movements — after that,
 * the codes are part of posted history (COGS entries reference them).
 */
export function updateItem(
  db: Database,
  id: number,
  input: Partial<ItemInput>,
  actorId: number | null,
): ItemRow {
  const before = getItem(db, id);
  if (!before) throw new InventoryError("not_found", `item ${id} not found`);
  const v = validateItemInput(input, true);
  if (v.sku !== undefined && v.sku !== before.sku) {
    throw new InventoryError("validation", "sku cannot change (it is the item's identity)");
  }
  if (v.inventory_account_code !== undefined || v.cogs_account_code !== undefined) {
    const moved = db.query("SELECT id FROM stock_movements WHERE item_id = ? LIMIT 1").get(id) as
      | { id: number }
      | undefined;
    if (moved) {
      throw new InventoryError(
        "validation",
        "account codes cannot change once the item has stock movements",
      );
    }
    if (v.inventory_account_code !== undefined) {
      assertAccountExists(db, v.inventory_account_code, "inventory_account_code");
    }
    if (v.cogs_account_code !== undefined) {
      assertAccountExists(db, v.cogs_account_code, "cogs_account_code");
    }
  }
  return db.transaction((): ItemRow => {
    const sets: string[] = ["updated_at = ?"];
    const params: (string | number | null)[] = [nowIso()];
    if (v.name !== undefined) {
      sets.push("name = ?");
      params.push(v.name);
    }
    if (v.description !== undefined) {
      sets.push("description = ?");
      params.push(v.description);
    }
    if (v.unit !== undefined) {
      sets.push("unit = ?");
      params.push(v.unit);
    }
    if (v.allow_negative_stock !== undefined) {
      sets.push("allow_negative_stock = ?");
      params.push(v.allow_negative_stock ? 1 : 0);
    }
    if (v.inventory_account_code !== undefined) {
      sets.push("inventory_account_code = ?");
      params.push(v.inventory_account_code);
    }
    if (v.cogs_account_code !== undefined) {
      sets.push("cogs_account_code = ?");
      params.push(v.cogs_account_code);
    }
    if (v.status !== undefined) {
      sets.push("status = ?");
      params.push(v.status);
    }
    params.push(id);
    db.query(`UPDATE items SET ${sets.join(", ")} WHERE id = ?`).run(...params);
    appendAudit(db, {
      actor_id: actorId,
      action: "item.update",
      entity_type: "item",
      entity_id: before.sku,
      before: { name: before.name, status: before.status },
      after: { name: v.name ?? before.name, status: v.status ?? before.status },
    });
    return getItem(db, id)!;
  })();
}

// --- warehouses -----------------------------------------------------------------

export interface WarehouseRow {
  id: number;
  code: string;
  name: string;
  location: string | null;
  created_at: string;
  updated_at: string;
}

export interface WarehouseInput {
  code: string;
  name: string;
  location?: string | null;
}

export function getWarehouse(db: Database, id: number): WarehouseRow | null {
  const row = db.query("SELECT * FROM warehouses WHERE id = ?").get(id) as
    | WarehouseRow
    | undefined;
  return row ?? null;
}

export function listWarehouses(db: Database): WarehouseRow[] {
  return db.query("SELECT * FROM warehouses ORDER BY code ASC, id ASC").all() as WarehouseRow[];
}

export function createWarehouse(
  db: Database,
  input: WarehouseInput,
  actorId: number | null,
): WarehouseRow {
  const code = reqStr(input.code, "code", 100);
  const name = reqStr(input.name, "name", 500);
  const location =
    typeof input.location === "string" ? input.location.trim().slice(0, 1000) : null;
  const now = nowIso();
  return db.transaction((): WarehouseRow => {
    const existing = db.query("SELECT id FROM warehouses WHERE code = ?").get(code) as
      | { id: number }
      | undefined;
    if (existing) throw new InventoryError("validation", `warehouse code '${code}' already exists`);
    const info = db
      .query(
        "INSERT INTO warehouses (code, name, location, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
      )
      .run(code, name, location, now, now);
    const id = Number(info.lastInsertRowid);
    appendAudit(db, {
      actor_id: actorId,
      action: "warehouse.create",
      entity_type: "warehouse",
      entity_id: code,
      after: { name },
    });
    return getWarehouse(db, id)!;
  })();
}

export function updateWarehouse(
  db: Database,
  id: number,
  input: Partial<WarehouseInput>,
  actorId: number | null,
): WarehouseRow {
  const before = getWarehouse(db, id);
  if (!before) throw new InventoryError("not_found", `warehouse ${id} not found`);
  const name = input.name !== undefined ? reqStr(input.name, "name", 500) : undefined;
  const location =
    input.location !== undefined
      ? typeof input.location === "string"
        ? input.location.trim().slice(0, 1000)
        : null
      : undefined;
  if (input.code !== undefined && input.code !== before.code) {
    throw new InventoryError("validation", "code cannot change (it is the warehouse's identity)");
  }
  return db.transaction((): WarehouseRow => {
    const sets: string[] = ["updated_at = ?"];
    const params: (string | null)[] = [nowIso()];
    if (name !== undefined) {
      sets.push("name = ?");
      params.push(name);
    }
    if (location !== undefined) {
      sets.push("location = ?");
      params.push(location);
    }
    params.push(String(id));
    db.query(`UPDATE warehouses SET ${sets.join(", ")} WHERE id = ?`).run(...params);
    appendAudit(db, {
      actor_id: actorId,
      action: "warehouse.update",
      entity_type: "warehouse",
      entity_id: before.code,
      before: { name: before.name },
      after: { name: name ?? before.name },
    });
    return getWarehouse(db, id)!;
  })();
}

// --- costing + movements --------------------------------------------------------

export interface StockCostRow {
  item_id: number;
  warehouse_id: number;
  quantity: number;
  avg_cost_cents: number;
}

export interface MovementRow {
  id: number;
  item_id: number;
  warehouse_id: number;
  movement_type: string;
  quantity: number;
  unit_cost_cents: number | null;
  total_cost_cents: number | null;
  movement_date: string;
  reason: string | null;
  source_type: string | null;
  source_id: string | null;
  posted_entry_id: number | null;
  created_by: number | null;
  created_at: string;
}

export function getStockCost(db: Database, itemId: number, warehouseId: number): StockCostRow | null {
  const row = db
    .query("SELECT * FROM stock_costs WHERE item_id = ? AND warehouse_id = ?")
    .get(itemId, warehouseId) as StockCostRow | undefined;
  return row ?? null;
}

/** Current on-hand quantity from the costing ledger (== SUM(movements)). */
export function onHand(db: Database, itemId: number, warehouseId: number): number {
  return getStockCost(db, itemId, warehouseId)?.quantity ?? 0;
}

function assertActiveItemWarehouse(
  db: Database,
  itemId: number,
  warehouseId: number,
): { item: ItemRow; warehouse: WarehouseRow } {
  const item = getItem(db, itemId);
  if (!item) throw new InventoryError("not_found", `item ${itemId} not found`);
  const warehouse = getWarehouse(db, warehouseId);
  if (!warehouse) throw new InventoryError("not_found", `warehouse ${warehouseId} not found`);
  if (item.status !== "active") {
    throw new InventoryError("validation", `item ${item.sku} is ${item.status} and cannot move stock`);
  }
  return { item, warehouse };
}

/** Block a move that would take stock negative, unless the item allows it. */
function assertStockFloor(item: ItemRow, newQty: number, sku: string): void {
  if (newQty < 0 && !item.allow_negative_stock) {
    throw new InventoryError(
      "negative_stock",
      `movement would take ${sku} to ${newQty} on hand; negative stock is not allowed for this item`,
    );
  }
}

function insertMovement(
  db: Database,
  m: Omit<MovementRow, "id" | "created_at">,
  now: string,
): MovementRow {
  const info = db
    .query(
      `INSERT INTO stock_movements
         (item_id, warehouse_id, movement_type, quantity, unit_cost_cents,
          total_cost_cents, movement_date, reason, source_type, source_id,
          posted_entry_id, created_by, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      m.item_id,
      m.warehouse_id,
      m.movement_type,
      m.quantity,
      m.unit_cost_cents,
      m.total_cost_cents,
      m.movement_date,
      m.reason,
      m.source_type,
      m.source_id,
      m.posted_entry_id,
      m.created_by,
      now,
    );
  const id = Number(info.lastInsertRowid);
  return db.query("SELECT * FROM stock_movements WHERE id = ?").get(id) as MovementRow;
}

/** Upsert the costing row after a quantity/avg change (same transaction). */
function upsertStockCost(
  db: Database,
  itemId: number,
  warehouseId: number,
  quantity: number,
  avgCost: number,
): void {
  db.query(
    `INSERT INTO stock_costs (item_id, warehouse_id, quantity, avg_cost_cents)
     VALUES (?, ?, ?, ?)
     ON CONFLICT (item_id, warehouse_id) DO UPDATE SET quantity = ?, avg_cost_cents = ?`,
  ).run(itemId, warehouseId, quantity, avgCost, quantity, avgCost);
}

/** Weighted-average update on a receipt: integer-cent rounding, half-up. */
export function weightedAverage(
  oldQty: number,
  oldAvg: number,
  qty: number,
  unitCost: number,
): number {
  const totalQty = oldQty + qty;
  if (totalQty === 0) return oldAvg;
  return Math.round((oldQty * oldAvg + qty * unitCost) / totalQty);
}

export interface ReceiptInput {
  item_id: number;
  warehouse_id: number;
  quantity: number;
  unit_cost_cents: number;
  movement_date?: string;
  reason?: string | null;
  source_type?: string | null;
  source_id?: string | null;
}

export function receiveStock(db: Database, input: ReceiptInput, actorId: number | null): MovementRow {
  const itemId = reqInt(input.item_id, "item_id", { min: 1 });
  const warehouseId = reqInt(input.warehouse_id, "warehouse_id", { min: 1 });
  const qty = reqInt(input.quantity, "quantity", { min: 1 });
  const unitCost = reqInt(input.unit_cost_cents, "unit_cost_cents", { min: 0 });
  const movementDate = input.movement_date !== undefined ? reqDate(input.movement_date, "movement_date") : todayDate();
  const reason = typeof input.reason === "string" ? input.reason.trim().slice(0, 1000) : null;
  const { item } = assertActiveItemWarehouse(db, itemId, warehouseId);
  const now = nowIso();
  return db.transaction((): MovementRow => {
    const cost = getStockCost(db, itemId, warehouseId);
    const oldQty = cost?.quantity ?? 0;
    const oldAvg = cost?.avg_cost_cents ?? 0;
    const newAvg = weightedAverage(oldQty, oldAvg, qty, unitCost);
    const newQty = oldQty + qty;
    const m = insertMovement(
      db,
      {
        item_id: itemId,
        warehouse_id: warehouseId,
        movement_type: "receipt",
        quantity: qty,
        unit_cost_cents: unitCost,
        total_cost_cents: qty * unitCost,
        movement_date: movementDate,
        reason,
        source_type: input.source_type ?? null,
        source_id: input.source_id ?? null,
        posted_entry_id: null,
        created_by: actorId,
      },
      now,
    );
    upsertStockCost(db, itemId, warehouseId, newQty, newAvg);
    appendAudit(db, {
      actor_id: actorId,
      action: "stock.receipt",
      entity_type: "stock_movement",
      entity_id: String(m.id),
      after: { sku: item.sku, quantity: qty, unit_cost_cents: unitCost, avg_cost_cents: newAvg },
    });
    return m;
  })();
}

export interface IssueInput {
  item_id: number;
  warehouse_id: number;
  quantity: number;
  movement_date?: string;
  reason?: string | null;
  source_type?: string | null;
  source_id?: string | null;
}

/**
 * Issue stock: consumes at the current weighted-average cost and posts
 * Dr COGS / Cr Inventory for qty × avg via postJournal (nested
 * transaction — movement, costing, GL entry, and audit are atomic).
 */
export function issueStock(db: Database, input: IssueInput, actorId: number | null): MovementRow {
  const itemId = reqInt(input.item_id, "item_id", { min: 1 });
  const warehouseId = reqInt(input.warehouse_id, "warehouse_id", { min: 1 });
  const qty = reqInt(input.quantity, "quantity", { min: 1 });
  const movementDate = input.movement_date !== undefined ? reqDate(input.movement_date, "movement_date") : todayDate();
  const reason = typeof input.reason === "string" ? input.reason.trim().slice(0, 1000) : null;
  const { item } = assertActiveItemWarehouse(db, itemId, warehouseId);
  const cost = getStockCost(db, itemId, warehouseId);
  if (!cost) {
    // No receipt history at this warehouse: there is no cost basis, so
    // no COGS can be posted. (A cost row with quantity <= 0 still carries
    // the last average — negative-stock items issue against it.)
    throw new InventoryError(
      "no_cost_basis",
      `item ${item.sku} has no receipt history at this warehouse; receive stock before issuing`,
    );
  }
  const avg = cost.avg_cost_cents;
  const newQty = cost.quantity - qty;
  assertStockFloor(item, newQty, item.sku);
  const cogs = qty * avg;
  const now = nowIso();
  return db.transaction((): MovementRow => {
    // postJournal runs in a nested transaction (savepoint) — atomic with
    // the movement below. Its open-period check gates the movement date.
    // A zero-cost issue (free stock) posts no journal: a 0-cent entry
    // would fail postJournal's balance rule, and there is nothing to move.
    const posted =
      cogs > 0
        ? postJournal(db, {
            memo: `COGS issue ${item.sku} x${qty}`,
            lines: [
              { account_code: item.cogs_account_code, debit_cents: cogs },
              { account_code: item.inventory_account_code, credit_cents: cogs },
            ],
            actor_id: actorId,
            posted_on: movementDate,
            source_type: "inventory",
            source_id: `issue:${itemId}:${warehouseId}`,
          })
        : null;
    const m = insertMovement(
      db,
      {
        item_id: itemId,
        warehouse_id: warehouseId,
        movement_type: "issue",
        quantity: -qty,
        unit_cost_cents: avg,
        total_cost_cents: cogs,
        movement_date: movementDate,
        reason,
        source_type: input.source_type ?? null,
        source_id: input.source_id ?? null,
        posted_entry_id: posted?.id ?? null,
        created_by: actorId,
      },
      now,
    );
    upsertStockCost(db, itemId, warehouseId, newQty, avg);
    appendAudit(db, {
      actor_id: actorId,
      action: "stock.issue",
      entity_type: "stock_movement",
      entity_id: String(m.id),
      after: { sku: item.sku, quantity: qty, cogs_cents: cogs, entry_no: posted?.entry_no ?? null },
    });
    return m;
  })();
}

export interface AdjustmentInput {
  item_id: number;
  warehouse_id: number;
  quantity: number; // signed: +found stock, -shrinkage; never 0
  unit_cost_cents?: number; // required when quantity > 0
  movement_date?: string;
  reason: string; // required: a count correction must say why
  source_type?: string | null;
  source_id?: string | null;
}

/**
 * Count correction. Positive adjustments re-average like a receipt;
 * negative adjustments consume at the current average. No GL entry in
 * v1 (see module header) — the correction is visible in movements and
 * in the audit trail, and the next period-end process reconciles it.
 */
export function adjustStock(db: Database, input: AdjustmentInput, actorId: number | null): MovementRow {
  const itemId = reqInt(input.item_id, "item_id", { min: 1 });
  const warehouseId = reqInt(input.warehouse_id, "warehouse_id", { min: 1 });
  const qty = reqInt(input.quantity, "quantity");
  if (qty === 0) throw new InventoryError("validation", "adjustment quantity must not be 0");
  const reason = reqStr(input.reason, "reason", 1000);
  const movementDate = input.movement_date !== undefined ? reqDate(input.movement_date, "movement_date") : todayDate();
  let unitCost: number | null = null;
  if (qty > 0) unitCost = reqInt(input.unit_cost_cents, "unit_cost_cents", { min: 0 });
  const { item } = assertActiveItemWarehouse(db, itemId, warehouseId);
  const cost = getStockCost(db, itemId, warehouseId);
  const oldQty = cost?.quantity ?? 0;
  const oldAvg = cost?.avg_cost_cents ?? 0;
  const newQty = oldQty + qty;
  if (qty < 0) assertStockFloor(item, newQty, item.sku);
  const newAvg = qty > 0 ? weightedAverage(oldQty, oldAvg, qty, unitCost!) : oldAvg;
  const total = qty > 0 ? qty * unitCost! : qty * oldAvg;
  const now = nowIso();
  return db.transaction((): MovementRow => {
    const m = insertMovement(
      db,
      {
        item_id: itemId,
        warehouse_id: warehouseId,
        movement_type: "adjustment",
        quantity: qty,
        unit_cost_cents: qty > 0 ? unitCost : oldAvg,
        total_cost_cents: total,
        movement_date: movementDate,
        reason,
        source_type: input.source_type ?? null,
        source_id: input.source_id ?? null,
        posted_entry_id: null,
        created_by: actorId,
      },
      now,
    );
    upsertStockCost(db, itemId, warehouseId, newQty, newAvg);
    appendAudit(db, {
      actor_id: actorId,
      action: "stock.adjust",
      entity_type: "stock_movement",
      entity_id: String(m.id),
      after: { sku: item.sku, quantity: qty, reason, avg_cost_cents: newAvg },
    });
    return m;
  })();
}

export interface TransferInput {
  item_id: number;
  from_warehouse_id: number;
  to_warehouse_id: number;
  quantity: number;
  movement_date?: string;
  reason?: string | null;
}

/**
 * Move stock between warehouses at the source's current average cost
 * (value stays inside Inventory — no GL entry). Two movements, one
 * transaction: the source leg and the destination leg always agree.
 */
export function transferStock(
  db: Database,
  input: TransferInput,
  actorId: number | null,
): { out: MovementRow; in: MovementRow } {
  const itemId = reqInt(input.item_id, "item_id", { min: 1 });
  const fromId = reqInt(input.from_warehouse_id, "from_warehouse_id", { min: 1 });
  const toId = reqInt(input.to_warehouse_id, "to_warehouse_id", { min: 1 });
  if (fromId === toId) {
    throw new InventoryError("validation", "transfer source and destination must differ");
  }
  const qty = reqInt(input.quantity, "quantity", { min: 1 });
  const movementDate = input.movement_date !== undefined ? reqDate(input.movement_date, "movement_date") : todayDate();
  const reason = typeof input.reason === "string" ? input.reason.trim().slice(0, 1000) : null;
  const { item } = assertActiveItemWarehouse(db, itemId, fromId);
  const dest = getWarehouse(db, toId);
  if (!dest) throw new InventoryError("not_found", `warehouse ${toId} not found`);
  const sourceCost = getStockCost(db, itemId, fromId);
  if (!sourceCost) {
    throw new InventoryError(
      "no_cost_basis",
      `item ${item.sku} has no stock at the source warehouse; receive stock before transferring`,
    );
  }
  const avg = sourceCost.avg_cost_cents;
  const newSourceQty = sourceCost.quantity - qty;
  assertStockFloor(item, newSourceQty, item.sku);
  const now = nowIso();
  return db.transaction((): { out: MovementRow; in: MovementRow } => {
    const out = insertMovement(
      db,
      {
        item_id: itemId,
        warehouse_id: fromId,
        movement_type: "transfer_out",
        quantity: -qty,
        unit_cost_cents: avg,
        total_cost_cents: qty * avg,
        movement_date: movementDate,
        reason,
        source_type: "inventory",
        source_id: `transfer:${itemId}:${fromId}:${toId}`,
        posted_entry_id: null,
        created_by: actorId,
      },
      now,
    );
    const destCost = getStockCost(db, itemId, toId);
    const destOldQty = destCost?.quantity ?? 0;
    const destOldAvg = destCost?.avg_cost_cents ?? 0;
    const destNewAvg = weightedAverage(destOldQty, destOldAvg, qty, avg);
    const inn = insertMovement(
      db,
      {
        item_id: itemId,
        warehouse_id: toId,
        movement_type: "transfer_in",
        quantity: qty,
        unit_cost_cents: avg,
        total_cost_cents: qty * avg,
        movement_date: movementDate,
        reason,
        source_type: "inventory",
        source_id: `transfer:${itemId}:${fromId}:${toId}`,
        posted_entry_id: null,
        created_by: actorId,
      },
      now,
    );
    upsertStockCost(db, itemId, fromId, newSourceQty, avg);
    upsertStockCost(db, itemId, toId, destOldQty + qty, destNewAvg);
    appendAudit(db, {
      actor_id: actorId,
      action: "stock.transfer",
      entity_type: "stock_movement",
      entity_id: String(out.id),
      after: { sku: item.sku, quantity: qty, from_warehouse_id: fromId, to_warehouse_id: toId },
    });
    return { out, in: inn };
  })();
}

// --- reads ----------------------------------------------------------------------

export interface StockLevelRow {
  item_id: number;
  sku: string;
  warehouse_id: number;
  warehouse_code: string;
  quantity: number;
  avg_cost_cents: number | null;
  value_cents: number | null;
}

export function listStockLevels(
  db: Database,
  opts: { item_id?: number; warehouse_id?: number } = {},
): StockLevelRow[] {
  const where: string[] = [];
  const params: number[] = [];
  if (opts.item_id !== undefined) {
    where.push("sl.item_id = ?");
    params.push(opts.item_id);
  }
  if (opts.warehouse_id !== undefined) {
    where.push("sl.warehouse_id = ?");
    params.push(opts.warehouse_id);
  }
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
  return db
    .query(
      `SELECT sl.item_id, i.sku, sl.warehouse_id, w.code AS warehouse_code, sl.quantity,
              sc.avg_cost_cents, sl.quantity * sc.avg_cost_cents AS value_cents
       FROM stock_levels sl
       JOIN items i ON i.id = sl.item_id
       JOIN warehouses w ON w.id = sl.warehouse_id
       LEFT JOIN stock_costs sc ON sc.item_id = sl.item_id AND sc.warehouse_id = sl.warehouse_id
       ${clause}
       ORDER BY i.sku ASC, w.code ASC`,
    )
    .all(...params) as StockLevelRow[];
}

export function listMovements(
  db: Database,
  opts: { item_id?: number; warehouse_id?: number; movement_type?: string } = {},
): MovementRow[] {
  const where: string[] = [];
  const params: (number | string)[] = [];
  if (opts.item_id !== undefined) {
    where.push("item_id = ?");
    params.push(opts.item_id);
  }
  if (opts.warehouse_id !== undefined) {
    where.push("warehouse_id = ?");
    params.push(opts.warehouse_id);
  }
  if (opts.movement_type !== undefined) {
    if (!["receipt", "issue", "adjustment", "transfer_in", "transfer_out"].includes(opts.movement_type)) {
      throw new InventoryError("validation", `unknown movement_type '${opts.movement_type}'`);
    }
    where.push("movement_type = ?");
    params.push(opts.movement_type);
  }
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
  return db
    .query(`SELECT * FROM stock_movements ${clause} ORDER BY id DESC`)
    .all(...params) as MovementRow[];
}

/**
 * Recompute check: for every item×warehouse in stock_costs, compare the
 * costing ledger's quantity against SUM(movements) (and the view).
 * Returns mismatches — empty means levels always equal Σmovements.
 */
export function recomputeStockLevels(db: Database): { item_id: number; warehouse_id: number; ledger_qty: number; movements_qty: number }[] {
  const rows = db
    .query(
      `SELECT sc.item_id, sc.warehouse_id, sc.quantity AS ledger_qty,
              COALESCE(SUM(sm.quantity), 0) AS movements_qty
       FROM stock_costs sc
       LEFT JOIN stock_movements sm
         ON sm.item_id = sc.item_id AND sm.warehouse_id = sc.warehouse_id
       GROUP BY sc.item_id, sc.warehouse_id
       HAVING ledger_qty != movements_qty`,
    )
    .all() as { item_id: number; warehouse_id: number; ledger_qty: number; movements_qty: number }[];
  return rows;
}

// Re-exported so callers can distinguish ledger failures from inventory failures.
export { LedgerError };
