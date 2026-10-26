// Phase 6 tests: procurement — purchase orders, status machine,
// receivings (movement + AP accrual, atomically), RBAC.

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import {
  makeTestEnv,
  loginAs,
  authHeaders,
  createTestUser,
  type TestEnv,
} from "./helpers";

let env: TestEnv;
let adminToken: string;
let accountantToken: string;
let clerkToken: string;
let auditorToken: string;

beforeAll(async () => {
  env = await makeTestEnv();
  const admin = await loginAs(env.base, "admin@example.local", "Changeme-123456");
  expect(admin.status).toBe(200);
  adminToken = admin.token;

  await createTestUser(env.db, "acct6@example.local", "Acctpass-123456", "accountant");
  await createTestUser(env.db, "clerk6@example.local", "Clerkpass-123456", "ap_clerk");
  await createTestUser(env.db, "aud6@example.local", "Auditorpass-123456", "auditor");
  accountantToken = (await loginAs(env.base, "acct6@example.local", "Acctpass-123456")).token;
  clerkToken = (await loginAs(env.base, "clerk6@example.local", "Clerkpass-123456")).token;
  auditorToken = (await loginAs(env.base, "aud6@example.local", "Auditorpass-123456")).token;
});

afterAll(() => env.cleanup());

const A = (t: string) => authHeaders(t);
const J = (o: unknown) => JSON.stringify(o);
const today = () => new Date().toISOString().slice(0, 10);

async function api(
  method: string,
  path: string,
  token: string,
  body?: unknown,
  extraHeaders: Record<string, string> = {},
) {
  const res = await fetch(`${env.base}${path}`, {
    method,
    headers: { "content-type": "application/json", ...A(token), ...extraHeaders },
    body: body === undefined ? undefined : J(body),
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}

async function makeVendor(token: string, name: string): Promise<any> {
  const { status, json } = await api("POST", "/api/v1/ap/vendors", token, { name });
  expect(status).toBe(201);
  return json.data;
}

async function makeItem(token: string, sku: string): Promise<any> {
  const { status, json } = await api("POST", "/api/v1/inventory/items", token, {
    sku,
    name: `Item ${sku}`,
  });
  expect(status).toBe(201);
  return json.data;
}

async function makeWarehouse(token: string, code: string): Promise<any> {
  const { status, json } = await api("POST", "/api/v1/inventory/warehouses", token, {
    code,
    name: `Warehouse ${code}`,
  });
  expect(status).toBe(201);
  return json.data;
}

async function makePO(
  token: string,
  vendorId: number,
  lines: { item_id: number; quantity_ordered: number; unit_cost_cents: number }[],
): Promise<any> {
  const { status, json } = await api("POST", "/api/v1/procurement/purchase-orders", token, {
    vendor_id: vendorId,
    order_date: today(),
    lines,
  });
  expect(status).toBe(201);
  return json.data;
}

async function submitPO(token: string, poId: number) {
  const { status, json } = await api(
    "POST",
    `/api/v1/procurement/purchase-orders/${poId}/submit`,
    token,
  );
  expect(status).toBe(200);
  return json.data;
}

async function receive(
  token: string,
  poId: number,
  warehouseId: number,
  lines: { po_line_id: number; quantity: number }[],
  extraHeaders: Record<string, string> = {},
) {
  return api(
    "POST",
    `/api/v1/procurement/purchase-orders/${poId}/receive`,
    token,
    { warehouse_id: warehouseId, receiving_date: today(), lines },
    extraHeaders,
  );
}

async function getPO(token: string, poId: number): Promise<any> {
  const { status, json } = await api(
    "GET",
    `/api/v1/procurement/purchase-orders/${poId}`,
    token,
  );
  expect(status).toBe(200);
  return json.data;
}

function journalEntryLines(entryId: number): { code: string; debit: number; credit: number }[] {
  return env.db
    .query(
      `SELECT a.code, jl.debit_cents AS debit, jl.credit_cents AS credit
       FROM journal_lines jl JOIN accounts a ON a.id = jl.account_id
       WHERE jl.entry_id = ? ORDER BY jl.id ASC`,
    )
    .all(entryId) as { code: string; debit: number; credit: number }[];
}

function count(table: string): number {
  return (env.db.query(`SELECT COUNT(*) AS n FROM ${table}`).get() as { n: number }).n;
}

function levels(itemId: number, warehouseId: number): number {
  const row = env.db
    .query("SELECT quantity FROM stock_levels WHERE item_id = ? AND warehouse_id = ?")
    .get(itemId, warehouseId) as { quantity: number } | undefined;
  return row?.quantity ?? 0;
}

describe("purchase orders", () => {
  test("create validates lines and items", async () => {
    const vendor = await makeVendor(adminToken, "Vendor PO-1");
    const item = await makeItem(adminToken, "PO-ITEM-1");
    const noLines = await api("POST", "/api/v1/procurement/purchase-orders", accountantToken, {
      vendor_id: vendor.id,
      order_date: today(),
      lines: [],
    });
    expect(noLines.status).toBe(400);
    const badItem = await api("POST", "/api/v1/procurement/purchase-orders", accountantToken, {
      vendor_id: vendor.id,
      order_date: today(),
      lines: [{ item_id: 999999, quantity_ordered: 5, unit_cost_cents: 100 }],
    });
    expect(badItem.status).toBe(404);
    const ok = await makePO(accountantToken, vendor.id, [
      { item_id: item.id, quantity_ordered: 10, unit_cost_cents: 250 },
    ]);
    expect(ok.status).toBe("draft");
    expect(ok.po_no).toMatch(/^PO-\d{6}$/);
    expect(ok.ordered_total_cents).toBe(2500);
    expect(ok.lines[0].remaining_quantity).toBe(10);
  });

  test("draft-only edit; edit after submit rejected", async () => {
    const vendor = await makeVendor(adminToken, "Vendor PO-2");
    const item = await makeItem(adminToken, "PO-ITEM-2");
    const po = await makePO(accountantToken, vendor.id, [
      { item_id: item.id, quantity_ordered: 4, unit_cost_cents: 100 },
    ]);
    const edited = await api(
      "PATCH",
      `/api/v1/procurement/purchase-orders/${po.id}`,
      accountantToken,
      { lines: [{ item_id: item.id, quantity_ordered: 6, unit_cost_cents: 120 }] },
    );
    expect(edited.status).toBe(200);
    expect(edited.json.data.ordered_total_cents).toBe(720);
    await submitPO(accountantToken, po.id);
    const late = await api("PATCH", `/api/v1/procurement/purchase-orders/${po.id}`, accountantToken, {
      notes: "too late",
    });
    expect(late.status).toBe(409);
    expect(late.json.error.code).toBe("not_draft");
  });

  test("submit/close/cancel state machine", async () => {
    const vendor = await makeVendor(adminToken, "Vendor PO-3");
    const item = await makeItem(adminToken, "PO-ITEM-3");
    const draft = await makePO(accountantToken, vendor.id, [
      { item_id: item.id, quantity_ordered: 2, unit_cost_cents: 100 },
    ]);
    const closeDraft = await api(
      "POST",
      `/api/v1/procurement/purchase-orders/${draft.id}/close`,
      accountantToken,
    );
    expect(closeDraft.status).toBe(409);
    expect(closeDraft.json.error.code).toBe("not_submitted");
    const cancelled = await api(
      "POST",
      `/api/v1/procurement/purchase-orders/${draft.id}/cancel`,
      accountantToken,
    );
    expect(cancelled.status).toBe(200);
    expect(cancelled.json.data.status).toBe("cancelled");
    const again = await api(
      "POST",
      `/api/v1/procurement/purchase-orders/${draft.id}/cancel`,
      accountantToken,
    );
    expect(again.status).toBe(409);
    expect(again.json.error.code).toBe("already_cancelled");
    const submitCancelled = await api(
      "POST",
      `/api/v1/procurement/purchase-orders/${draft.id}/submit`,
      accountantToken,
    );
    expect(submitCancelled.status).toBe(409);
    expect(submitCancelled.json.error.code).toBe("already_cancelled");
  });
});

describe("receivings", () => {
  test("partial receivings track; movement + accrual booked together", async () => {
    const vendor = await makeVendor(adminToken, "Vendor RCV-1");
    const item = await makeItem(adminToken, "RCV-ITEM-1");
    const wh = await makeWarehouse(adminToken, "RCV-WH-1");
    const po = await makePO(accountantToken, vendor.id, [
      { item_id: item.id, quantity_ordered: 10, unit_cost_cents: 300 },
    ]);
    await submitPO(accountantToken, po.id);
    const journalsBefore = count("journal_entries");
    const { status, json } = await receive(adminToken, po.id, wh.id, [
      { po_line_id: po.lines[0].id, quantity: 4 },
    ]);
    expect(status).toBe(201);
    const rcv = json.data;
    expect(rcv.total_cents).toBe(1200);
    expect(rcv.accrued_entry_id).not.toBeNull();
    // Accrual: Dr Inventory 1200 / Cr AP 2000, balanced.
    const lines = journalEntryLines(rcv.accrued_entry_id);
    expect(lines).toEqual([
      { code: "1200", debit: 1200, credit: 0 },
      { code: "2000", debit: 0, credit: 1200 },
    ]);
    expect(count("journal_entries")).toBe(journalsBefore + 1);
    // Stock moved with the goods.
    expect(levels(item.id, wh.id)).toBe(4);
    // PO progress tracked.
    const after = await getPO(adminToken, po.id);
    expect(after.status).toBe("partially_received");
    expect(after.lines[0].quantity_received).toBe(4);
    expect(after.lines[0].remaining_quantity).toBe(6);
    expect(after.received_total_cents).toBe(1200);
    // Finish it: fully received.
    const done = await receive(adminToken, po.id, wh.id, [
      { po_line_id: po.lines[0].id, quantity: 6 },
    ]);
    expect(done.status).toBe(201);
    expect(levels(item.id, wh.id)).toBe(10);
    const finalPo = await getPO(adminToken, po.id);
    expect(finalPo.status).toBe("fully_received");
    // No more receiving on a fully received PO.
    const extra = await receive(adminToken, po.id, wh.id, [
      { po_line_id: po.lines[0].id, quantity: 1 },
    ]);
    expect(extra.status).toBe(409);
    expect(extra.json.error.code).toBe("not_receivable");
  });

  test("receiving without a valid PO line is rejected in all shapes", async () => {
    const vendor = await makeVendor(adminToken, "Vendor RCV-2");
    const item = await makeItem(adminToken, "RCV-ITEM-2");
    const wh = await makeWarehouse(adminToken, "RCV-WH-2");
    const po = await makePO(accountantToken, vendor.id, [
      { item_id: item.id, quantity_ordered: 5, unit_cost_cents: 100 },
    ]);
    const other = await makePO(accountantToken, vendor.id, [
      { item_id: item.id, quantity_ordered: 5, unit_cost_cents: 100 },
    ]);
    await submitPO(accountantToken, po.id);
    await submitPO(accountantToken, other.id);
    // Draft PO cannot receive at all.
    const draftPo = await makePO(accountantToken, vendor.id, [
      { item_id: item.id, quantity_ordered: 5, unit_cost_cents: 100 },
    ]);
    const onDraft = await receive(adminToken, draftPo.id, wh.id, [
      { po_line_id: draftPo.lines[0].id, quantity: 1 },
    ]);
    expect(onDraft.status).toBe(409);
    expect(onDraft.json.error.code).toBe("not_receivable");
    // Nonexistent line.
    const ghost = await receive(adminToken, po.id, wh.id, [{ po_line_id: 999999, quantity: 1 }]);
    expect(ghost.status).toBe(404);
    // Line from another PO.
    const foreign = await receive(adminToken, po.id, wh.id, [
      { po_line_id: other.lines[0].id, quantity: 1 },
    ]);
    expect(foreign.status).toBe(400);
    expect(foreign.json.error.code).toBe("line_mismatch");
    // Over-receipt, single and combined duplicates.
    const over = await receive(adminToken, po.id, wh.id, [
      { po_line_id: po.lines[0].id, quantity: 6 },
    ]);
    expect(over.status).toBe(400);
    expect(over.json.error.code).toBe("over_received");
    const overCombined = await receive(adminToken, po.id, wh.id, [
      { po_line_id: po.lines[0].id, quantity: 3 },
      { po_line_id: po.lines[0].id, quantity: 3 },
    ]);
    expect(overCombined.status).toBe(400);
    expect(overCombined.json.error.code).toBe("over_received");
    // None of the failures booked anything on this PO.
    const poAfter = await getPO(adminToken, po.id);
    expect(poAfter.status).toBe("open");
    expect(poAfter.lines[0].quantity_received).toBe(0);
    expect(levels(item.id, wh.id)).toBe(0);
  });

  test("failed receiving is fully atomic (inactive item rolls everything back)", async () => {
    const vendor = await makeVendor(adminToken, "Vendor RCV-3");
    const item = await makeItem(adminToken, "RCV-ITEM-3");
    const wh = await makeWarehouse(adminToken, "RCV-WH-3");
    const po = await makePO(accountantToken, vendor.id, [
      { item_id: item.id, quantity_ordered: 3, unit_cost_cents: 200 },
    ]);
    await submitPO(accountantToken, po.id);
    // Deactivate the item after the PO is open: receiving must fail.
    const off = await api("PATCH", `/api/v1/inventory/items/${item.id}`, adminToken, {
      status: "inactive",
    });
    expect(off.status).toBe(200);
    const journalsBefore = count("journal_entries");
    const movBefore = count("stock_movements");
    const rcvBefore = count("receivings");
    const failed = await receive(adminToken, po.id, wh.id, [
      { po_line_id: po.lines[0].id, quantity: 2 },
    ]);
    expect(failed.status).toBe(400);
    expect(count("journal_entries")).toBe(journalsBefore);
    expect(count("stock_movements")).toBe(movBefore);
    expect(count("receivings")).toBe(rcvBefore);
    const poAfter = await getPO(adminToken, po.id);
    expect(poAfter.status).toBe("open");
    expect(poAfter.lines[0].quantity_received).toBe(0);
  });

  test("receiving idempotency: replay returns the original, books once", async () => {
    const vendor = await makeVendor(adminToken, "Vendor RCV-4");
    const item = await makeItem(adminToken, "RCV-ITEM-4");
    const wh = await makeWarehouse(adminToken, "RCV-WH-4");
    const po = await makePO(accountantToken, vendor.id, [
      { item_id: item.id, quantity_ordered: 4, unit_cost_cents: 150 },
    ]);
    await submitPO(accountantToken, po.id);
    const key = { "idempotency-key": "rcv-once-001" };
    const first = await receive(adminToken, po.id, wh.id, [
      { po_line_id: po.lines[0].id, quantity: 2 },
    ], key);
    expect(first.status).toBe(201);
    const second = await receive(adminToken, po.id, wh.id, [
      { po_line_id: po.lines[0].id, quantity: 2 },
    ], key);
    expect(second.status).toBe(201);
    expect(second.json.data.receiving_no).toBe(first.json.data.receiving_no);
    const mine = await api(
      "GET",
      `/api/v1/procurement/receivings?po_id=${po.id}`,
      adminToken,
    );
    expect(mine.status).toBe(200);
    expect(mine.json.data).toHaveLength(1);
    expect(levels(item.id, wh.id)).toBe(2);
  });

  test("zero-cost receiving books stock with no journal entry", async () => {
    const vendor = await makeVendor(adminToken, "Vendor RCV-5");
    const item = await makeItem(adminToken, "RCV-ITEM-5");
    const wh = await makeWarehouse(adminToken, "RCV-WH-5");
    const po = await makePO(accountantToken, vendor.id, [
      { item_id: item.id, quantity_ordered: 2, unit_cost_cents: 0 },
    ]);
    await submitPO(accountantToken, po.id);
    const { status, json } = await receive(adminToken, po.id, wh.id, [
      { po_line_id: po.lines[0].id, quantity: 2 },
    ]);
    expect(status).toBe(201);
    expect(json.data.accrued_entry_id).toBeNull();
    expect(levels(item.id, wh.id)).toBe(2);
    const poAfter = await getPO(adminToken, po.id);
    expect(poAfter.status).toBe("fully_received");
  });

  test("receivings are append-only at the DB level", async () => {
    const vendor = await makeVendor(adminToken, "Vendor RCV-6");
    const item = await makeItem(adminToken, "RCV-ITEM-6");
    const wh = await makeWarehouse(adminToken, "RCV-WH-6");
    const po = await makePO(accountantToken, vendor.id, [
      { item_id: item.id, quantity_ordered: 1, unit_cost_cents: 100 },
    ]);
    await submitPO(accountantToken, po.id);
    const { status, json } = await receive(adminToken, po.id, wh.id, [
      { po_line_id: po.lines[0].id, quantity: 1 },
    ]);
    expect(status).toBe(201);
    const rid = json.data.id;
    expect(() =>
      env.db.query("UPDATE receivings SET receiving_date = '2001-01-01' WHERE id = ?").run(rid),
    ).toThrow();
    expect(() => env.db.query("DELETE FROM receivings WHERE id = ?").run(rid)).toThrow();
    expect(() =>
      env.db.query("DELETE FROM receiving_lines WHERE receiving_id = ?").run(rid),
    ).toThrow();
  });

  test("close after partial receive blocks further receiving; cancel of fully received refused", async () => {
    const vendor = await makeVendor(adminToken, "Vendor RCV-7");
    const item = await makeItem(adminToken, "RCV-ITEM-7");
    const wh = await makeWarehouse(adminToken, "RCV-WH-7");
    const po = await makePO(accountantToken, vendor.id, [
      { item_id: item.id, quantity_ordered: 5, unit_cost_cents: 100 },
    ]);
    await submitPO(accountantToken, po.id);
    await receive(adminToken, po.id, wh.id, [{ po_line_id: po.lines[0].id, quantity: 2 }]);
    const closed = await api(
      "POST",
      `/api/v1/procurement/purchase-orders/${po.id}/close`,
      accountantToken,
    );
    expect(closed.status).toBe(200);
    expect(closed.json.data.status).toBe("closed");
    const late = await receive(adminToken, po.id, wh.id, [
      { po_line_id: po.lines[0].id, quantity: 1 },
    ]);
    expect(late.status).toBe(409);
    expect(late.json.error.code).toBe("not_receivable");

    const po2 = await makePO(accountantToken, vendor.id, [
      { item_id: item.id, quantity_ordered: 1, unit_cost_cents: 100 },
    ]);
    await submitPO(accountantToken, po2.id);
    await receive(adminToken, po2.id, wh.id, [{ po_line_id: po2.lines[0].id, quantity: 1 }]);
    const cancelFull = await api(
      "POST",
      `/api/v1/procurement/purchase-orders/${po2.id}/cancel`,
      accountantToken,
    );
    expect(cancelFull.status).toBe(409);
    expect(cancelFull.json.error.code).toBe("not_cancellable");
    const closeFull = await api(
      "POST",
      `/api/v1/procurement/purchase-orders/${po2.id}/close`,
      accountantToken,
    );
    expect(closeFull.status).toBe(200);
  });
});

describe("procurement RBAC", () => {
  test("accountant manages POs but cannot receive; clerk and auditor read-only", async () => {
    const vendor = await makeVendor(adminToken, "Vendor RBAC-6");
    const item = await makeItem(adminToken, "RBAC-ITEM-6");
    const wh = await makeWarehouse(adminToken, "RBAC-WH-6");
    const po = await makePO(accountantToken, vendor.id, [
      { item_id: item.id, quantity_ordered: 2, unit_cost_cents: 100 },
    ]);
    expect(po.po_no).toMatch(/^PO-/);
    await submitPO(accountantToken, po.id);
    // Seeded matrix: accountant has procurement write, not post.
    const acctReceive = await receive(accountantToken, po.id, wh.id, [
      { po_line_id: po.lines[0].id, quantity: 1 },
    ]);
    expect(acctReceive.status).toBe(403);
    const clerkReceive = await receive(clerkToken, po.id, wh.id, [
      { po_line_id: po.lines[0].id, quantity: 1 },
    ]);
    expect(clerkReceive.status).toBe(403);
    const clerkCreate = await api("POST", "/api/v1/procurement/purchase-orders", clerkToken, {
      vendor_id: vendor.id,
      order_date: today(),
      lines: [{ item_id: item.id, quantity_ordered: 1, unit_cost_cents: 100 }],
    });
    expect(clerkCreate.status).toBe(403);
    const audRead = await api(
      "GET",
      `/api/v1/procurement/purchase-orders/${po.id}`,
      auditorToken,
    );
    expect(audRead.status).toBe(200);
    const audReceive = await receive(auditorToken, po.id, wh.id, [
      { po_line_id: po.lines[0].id, quantity: 1 },
    ]);
    expect(audReceive.status).toBe(403);
  });
});
