// Phase 5 tests: inventory — items/warehouses, weighted-average costing,
// append-only movements, COGS posting on issue, negative-stock rules,
// transfers, idempotency, RBAC.

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import {
  makeTestEnv,
  loginAs,
  authHeaders,
  createTestUser,
  type TestEnv,
} from "./helpers";
import { recomputeStockLevels } from "../src/inventory";

let env: TestEnv;
let adminToken: string;
let accountantToken: string;
let salesToken: string;
let auditorToken: string;
let apClerkToken: string;

beforeAll(async () => {
  env = await makeTestEnv();
  const admin = await loginAs(env.base, "admin@example.local", "Changeme-123456");
  expect(admin.status).toBe(200);
  adminToken = admin.token;

  await createTestUser(env.db, "acct1@example.local", "Acctpass-123456", "accountant");
  await createTestUser(env.db, "sales1@example.local", "Salespass-123456", "sales");
  await createTestUser(env.db, "auditor1@example.local", "Auditorpass-123456", "auditor");
  await createTestUser(env.db, "clerk1@example.local", "Clerkpass-123456", "ap_clerk");
  accountantToken = (await loginAs(env.base, "acct1@example.local", "Acctpass-123456")).token;
  salesToken = (await loginAs(env.base, "sales1@example.local", "Salespass-123456")).token;
  auditorToken = (await loginAs(env.base, "auditor1@example.local", "Auditorpass-123456")).token;
  apClerkToken = (await loginAs(env.base, "clerk1@example.local", "Clerkpass-123456")).token;
});

afterAll(() => env.cleanup());

const A = (t: string) => authHeaders(t);
const J = (o: unknown) => JSON.stringify(o);

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

async function makeItem(token: string, sku: string, over: Record<string, unknown> = {}): Promise<any> {
  const { status, json } = await api("POST", "/api/v1/inventory/items", token, {
    sku,
    name: `Item ${sku}`,
    ...over,
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

async function receipt(
  token: string,
  itemId: number,
  warehouseId: number,
  quantity: number,
  unitCost: number,
  extraHeaders: Record<string, string> = {},
) {
  return api(
    "POST",
    "/api/v1/inventory/movements/receipt",
    token,
    { item_id: itemId, warehouse_id: warehouseId, quantity, unit_cost_cents: unitCost },
    extraHeaders,
  );
}

async function levels(itemId: number, warehouseId: number): Promise<any[]> {
  const { status, json } = await api(
    "GET",
    `/api/v1/inventory/levels?item_id=${itemId}&warehouse_id=${warehouseId}`,
    adminToken,
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

function journalCount(): number {
  return (env.db.query("SELECT COUNT(*) AS n FROM journal_entries").get() as { n: number }).n;
}

function movementCount(itemId: number): number {
  return (
    env.db.query("SELECT COUNT(*) AS n FROM stock_movements WHERE item_id = ?").get(itemId) as {
      n: number;
    }
  ).n;
}

describe("items and warehouses", () => {
  test("create + duplicate sku/code rejected", async () => {
    const item = await makeItem(adminToken, "WIDGET-A");
    expect(item.sku).toBe("WIDGET-A");
    expect(item.inventory_account_code).toBe("1200");
    expect(item.cogs_account_code).toBe("5000");
    const dup = await api("POST", "/api/v1/inventory/items", adminToken, {
      sku: "WIDGET-A",
      name: "again",
    });
    expect(dup.status).toBe(400);
    expect(dup.json.error.code).toBe("validation");

    const wh = await makeWarehouse(adminToken, "WH-MAIN");
    expect(wh.code).toBe("WH-MAIN");
    const dupWh = await api("POST", "/api/v1/inventory/warehouses", adminToken, {
      code: "WH-MAIN",
      name: "again",
    });
    expect(dupWh.status).toBe(400);
  });

  test("account codes frozen once movements exist", async () => {
    const item = await makeItem(adminToken, "WIDGET-B");
    const wh = await makeWarehouse(adminToken, "WH-B");
    const ok = await api("PATCH", `/api/v1/inventory/items/${item.id}`, adminToken, {
      cogs_account_code: "6200",
    });
    expect(ok.status).toBe(200);
    expect(ok.json.data.cogs_account_code).toBe("6200");
    const r = await receipt(adminToken, item.id, wh.id, 2, 500);
    expect(r.status).toBe(201);
    const frozen = await api("PATCH", `/api/v1/inventory/items/${item.id}`, adminToken, {
      cogs_account_code: "5000",
    });
    expect(frozen.status).toBe(400);
  });
});

describe("receipts and weighted-average costing", () => {
  test("weighted average: 10 @ 100 then 10 @ 300 -> avg 200", async () => {
    const item = await makeItem(adminToken, "WIDGET-C");
    const wh = await makeWarehouse(adminToken, "WH-C");
    expect((await receipt(adminToken, item.id, wh.id, 10, 100)).status).toBe(201);
    let lv = await levels(item.id, wh.id);
    expect(lv).toHaveLength(1);
    expect(lv[0].quantity).toBe(10);
    expect(lv[0].avg_cost_cents).toBe(100);
    expect(lv[0].value_cents).toBe(1000);

    expect((await receipt(adminToken, item.id, wh.id, 10, 300)).status).toBe(201);
    lv = await levels(item.id, wh.id);
    expect(lv[0].quantity).toBe(20);
    expect(lv[0].avg_cost_cents).toBe(200);
    expect(lv[0].value_cents).toBe(4000);
  });

  test("levels always equal SUM(movements) — recompute clean", async () => {
    expect(recomputeStockLevels(env.db)).toEqual([]);
    const raw = env.db
      .query(
        `SELECT item_id, warehouse_id, SUM(quantity) AS qty FROM stock_movements
         GROUP BY item_id, warehouse_id`,
      )
      .all() as { item_id: number; warehouse_id: number; qty: number }[];
    for (const r of raw) {
      const lv = await levels(r.item_id, r.warehouse_id);
      expect(lv).toHaveLength(1);
      expect(lv[0].quantity).toBe(r.qty);
    }
  });
});

describe("issues and COGS", () => {
  test("issue posts balanced Dr COGS / Cr Inventory at average cost", async () => {
    const item = await makeItem(adminToken, "WIDGET-D");
    const wh = await makeWarehouse(adminToken, "WH-D");
    await receipt(adminToken, item.id, wh.id, 10, 100);
    await receipt(adminToken, item.id, wh.id, 10, 300); // avg 200
    const { status, json } = await api("POST", "/api/v1/inventory/movements/issue", adminToken, {
      item_id: item.id,
      warehouse_id: wh.id,
      quantity: 5,
    });
    expect(status).toBe(201);
    expect(json.data.movement_type).toBe("issue");
    expect(json.data.quantity).toBe(-5);
    expect(json.data.unit_cost_cents).toBe(200);
    expect(json.data.posted_entry_id).not.toBeNull();

    const lines = journalEntryLines(json.data.posted_entry_id);
    expect(lines).toHaveLength(2);
    const debits = lines.reduce((s, l) => s + l.debit, 0);
    const credits = lines.reduce((s, l) => s + l.credit, 0);
    expect(debits).toBe(credits);
    expect(debits).toBe(1000); // 5 x 200
    expect(lines.find((l) => l.code === "5000")?.debit).toBe(1000);
    expect(lines.find((l) => l.code === "1200")?.credit).toBe(1000);

    const lv = await levels(item.id, wh.id);
    expect(lv[0].quantity).toBe(15);
    expect(lv[0].avg_cost_cents).toBe(200); // issue does not move the average
    expect(recomputeStockLevels(env.db)).toEqual([]);
  });

  test("issue over stock blocked (negative_stock), no movement written", async () => {
    const item = await makeItem(adminToken, "WIDGET-E");
    const wh = await makeWarehouse(adminToken, "WH-E");
    await receipt(adminToken, item.id, wh.id, 3, 100);
    const before = movementCount(item.id);
    const { status, json } = await api("POST", "/api/v1/inventory/movements/issue", adminToken, {
      item_id: item.id,
      warehouse_id: wh.id,
      quantity: 4,
    });
    expect(status).toBe(409);
    expect(json.error.code).toBe("negative_stock");
    expect(movementCount(item.id)).toBe(before);
  });

  test("allow_negative_stock item may go negative, at current average", async () => {
    const item = await makeItem(adminToken, "WIDGET-F", { allow_negative_stock: true });
    const wh = await makeWarehouse(adminToken, "WH-F");
    await receipt(adminToken, item.id, wh.id, 2, 250);
    const { status, json } = await api("POST", "/api/v1/inventory/movements/issue", adminToken, {
      item_id: item.id,
      warehouse_id: wh.id,
      quantity: 5,
    });
    expect(status).toBe(201);
    expect(json.data.total_cost_cents).toBe(1250);
    const lv = await levels(item.id, wh.id);
    expect(lv[0].quantity).toBe(-3);
  });

  test("issue with no receipt history -> no_cost_basis", async () => {
    const item = await makeItem(adminToken, "WIDGET-G");
    const wh = await makeWarehouse(adminToken, "WH-G");
    const { status, json } = await api("POST", "/api/v1/inventory/movements/issue", adminToken, {
      item_id: item.id,
      warehouse_id: wh.id,
      quantity: 1,
    });
    expect(status).toBe(400);
    expect(json.error.code).toBe("no_cost_basis");
  });

  test("zero-cost issue posts no journal entry", async () => {
    const item = await makeItem(adminToken, "WIDGET-H");
    const wh = await makeWarehouse(adminToken, "WH-H");
    await receipt(adminToken, item.id, wh.id, 4, 0);
    const before = journalCount();
    const { status, json } = await api("POST", "/api/v1/inventory/movements/issue", adminToken, {
      item_id: item.id,
      warehouse_id: wh.id,
      quantity: 2,
    });
    expect(status).toBe(201);
    expect(json.data.posted_entry_id).toBeNull();
    expect(journalCount()).toBe(before);
  });
});

describe("adjustments", () => {
  test("positive adjustment re-averages; negative keeps average; no GL entry", async () => {
    const item = await makeItem(adminToken, "WIDGET-I");
    const wh = await makeWarehouse(adminToken, "WH-I");
    await receipt(adminToken, item.id, wh.id, 10, 100);
    const before = journalCount();
    const adj = await api("POST", "/api/v1/inventory/movements/adjust", adminToken, {
      item_id: item.id,
      warehouse_id: wh.id,
      quantity: 10,
      unit_cost_cents: 300,
      reason: "cycle count found extra case",
    });
    expect(adj.status).toBe(201);
    let lv = await levels(item.id, wh.id);
    expect(lv[0].quantity).toBe(20);
    expect(lv[0].avg_cost_cents).toBe(200);

    const shrink = await api("POST", "/api/v1/inventory/movements/adjust", adminToken, {
      item_id: item.id,
      warehouse_id: wh.id,
      quantity: -4,
      reason: "damaged in handling",
    });
    expect(shrink.status).toBe(201);
    lv = await levels(item.id, wh.id);
    expect(lv[0].quantity).toBe(16);
    expect(lv[0].avg_cost_cents).toBe(200);
    expect(journalCount()).toBe(before);
    expect(recomputeStockLevels(env.db)).toEqual([]);
  });

  test("adjustment below zero blocked; reason required", async () => {
    const item = await makeItem(adminToken, "WIDGET-J");
    const wh = await makeWarehouse(adminToken, "WH-J");
    await receipt(adminToken, item.id, wh.id, 2, 100);
    const blocked = await api("POST", "/api/v1/inventory/movements/adjust", adminToken, {
      item_id: item.id,
      warehouse_id: wh.id,
      quantity: -3,
      reason: "shrinkage",
    });
    expect(blocked.status).toBe(409);
    expect(blocked.json.error.code).toBe("negative_stock");
    const noReason = await api("POST", "/api/v1/inventory/movements/adjust", adminToken, {
      item_id: item.id,
      warehouse_id: wh.id,
      quantity: 1,
      unit_cost_cents: 100,
    });
    expect(noReason.status).toBe(400);
  });
});

describe("transfers", () => {
  test("transfer moves qty at source average, no GL entry, both legs recorded", async () => {
    const item = await makeItem(adminToken, "WIDGET-K");
    const src = await makeWarehouse(adminToken, "WH-K1");
    const dst = await makeWarehouse(adminToken, "WH-K2");
    await receipt(adminToken, item.id, src.id, 10, 100);
    await receipt(adminToken, item.id, src.id, 10, 300); // src avg 200
    const before = journalCount();
    const { status, json } = await api("POST", "/api/v1/inventory/movements/transfer", adminToken, {
      item_id: item.id,
      from_warehouse_id: src.id,
      to_warehouse_id: dst.id,
      quantity: 4,
    });
    expect(status).toBe(201);
    expect(json.data.out.movement_type).toBe("transfer_out");
    expect(json.data.in.movement_type).toBe("transfer_in");
    expect(json.data.in.unit_cost_cents).toBe(200);
    expect((await levels(item.id, src.id))[0].quantity).toBe(16);
    const dstLv = await levels(item.id, dst.id);
    expect(dstLv[0].quantity).toBe(4);
    expect(dstLv[0].avg_cost_cents).toBe(200);
    expect(journalCount()).toBe(before);
    expect(recomputeStockLevels(env.db)).toEqual([]);
  });

  test("transfer to same warehouse rejected", async () => {
    const item = await makeItem(adminToken, "WIDGET-L");
    const wh = await makeWarehouse(adminToken, "WH-L");
    const { status } = await api("POST", "/api/v1/inventory/movements/transfer", adminToken, {
      item_id: item.id,
      from_warehouse_id: wh.id,
      to_warehouse_id: wh.id,
      quantity: 1,
    });
    expect(status).toBe(400);
  });
});

describe("append-only movements and idempotency", () => {
  test("raw UPDATE/DELETE on stock_movements aborts at DB level", async () => {
    const item = await makeItem(adminToken, "WIDGET-M");
    const wh = await makeWarehouse(adminToken, "WH-M");
    const r = await receipt(adminToken, item.id, wh.id, 1, 100);
    const id = r.json.data.id;
    expect(() =>
      env.db.query("UPDATE stock_movements SET quantity = 99 WHERE id = ?").run(id),
    ).toThrow();
    expect(() => env.db.query("DELETE FROM stock_movements WHERE id = ?").run(id)).toThrow();
    const row = env.db.query("SELECT quantity FROM stock_movements WHERE id = ?").get(id) as {
      quantity: number;
    };
    expect(row.quantity).toBe(1);
  });

  test("idempotency key replays a receipt, one movement only", async () => {
    const item = await makeItem(adminToken, "WIDGET-N");
    const wh = await makeWarehouse(adminToken, "WH-N");
    const key = { "idempotency-key": "inv-receipt-1" };
    const first = await receipt(adminToken, item.id, wh.id, 5, 100, key);
    expect(first.status).toBe(201);
    const second = await receipt(adminToken, item.id, wh.id, 5, 100, key);
    expect(second.status).toBe(201);
    expect(second.json.data.id).toBe(first.json.data.id);
    expect(movementCount(item.id)).toBe(1);
  });
});

describe("RBAC", () => {
  test("sales and auditor cannot move stock; ap_clerk cannot issue; accountant can", async () => {
    const item = await makeItem(adminToken, "WIDGET-O");
    const wh = await makeWarehouse(adminToken, "WH-O");
    const salesReceipt = await receipt(salesToken, item.id, wh.id, 1, 100);
    expect(salesReceipt.status).toBe(403);
    const auditorReceipt = await receipt(auditorToken, item.id, wh.id, 1, 100);
    expect(auditorReceipt.status).toBe(403);
    const clerkIssue = await api("POST", "/api/v1/inventory/movements/issue", apClerkToken, {
      item_id: item.id,
      warehouse_id: wh.id,
      quantity: 1,
    });
    expect(clerkIssue.status).toBe(403);
    // accountant has inventory:post — but no cost basis yet, so the
    // permission passes and the domain error surfaces instead.
    const acctIssue = await api("POST", "/api/v1/inventory/movements/issue", accountantToken, {
      item_id: item.id,
      warehouse_id: wh.id,
      quantity: 1,
    });
    expect(acctIssue.status).toBe(400);
    expect(acctIssue.json.error.code).toBe("no_cost_basis");
    // accountant can receive and issue end to end
    expect((await receipt(accountantToken, item.id, wh.id, 3, 100)).status).toBe(201);
    const acctIssue2 = await api("POST", "/api/v1/inventory/movements/issue", accountantToken, {
      item_id: item.id,
      warehouse_id: wh.id,
      quantity: 1,
    });
    expect(acctIssue2.status).toBe(201);
    // auditor can read levels
    const lv = await api("GET", `/api/v1/inventory/levels?item_id=${item.id}`, auditorToken);
    expect(lv.status).toBe(200);
  });
});
