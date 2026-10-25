-- Tally ERP — Phase 5: Inventory.
-- items, warehouses, append-only stock_movements (trigger-immutable, F-R3),
-- stock_costs (weighted-average costing ledger, one row per item×warehouse),
-- stock_levels (derived view: levels always equal SUM(movements)).

CREATE TABLE items (
  id INTEGER PRIMARY KEY,
  sku TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  description TEXT,
  unit TEXT NOT NULL DEFAULT 'each',
  allow_negative_stock INTEGER NOT NULL DEFAULT 0 CHECK (allow_negative_stock IN (0, 1)),
  inventory_account_code TEXT NOT NULL DEFAULT '1200',
  cogs_account_code TEXT NOT NULL DEFAULT '5000',
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE warehouses (
  id INTEGER PRIMARY KEY,
  code TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  location TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE stock_movements (
  id INTEGER PRIMARY KEY,
  item_id INTEGER NOT NULL REFERENCES items (id),
  warehouse_id INTEGER NOT NULL REFERENCES warehouses (id),
  movement_type TEXT NOT NULL CHECK (movement_type IN ('receipt', 'issue', 'adjustment', 'transfer_in', 'transfer_out')),
  quantity INTEGER NOT NULL CHECK (quantity != 0),
  unit_cost_cents INTEGER,
  total_cost_cents INTEGER,
  movement_date TEXT NOT NULL,
  reason TEXT,
  source_type TEXT,
  source_id TEXT,
  posted_entry_id INTEGER REFERENCES journal_entries (id),
  created_by INTEGER REFERENCES users (id),
  created_at TEXT NOT NULL
);

CREATE INDEX idx_movements_item_warehouse ON stock_movements (item_id, warehouse_id, id);
CREATE INDEX idx_movements_date ON stock_movements (movement_date);

-- Append-only: stock movements are books-and-records rows (F-R3). Corrections
-- happen via new reversing/adjustment movements, never by editing history.
CREATE TRIGGER stock_movements_no_update
BEFORE UPDATE ON stock_movements
BEGIN
  SELECT RAISE(ABORT, 'stock_movements are append-only');
END;

CREATE TRIGGER stock_movements_no_delete
BEFORE DELETE ON stock_movements
BEGIN
  SELECT RAISE(ABORT, 'stock_movements are append-only');
END;

-- Weighted-average cost ledger: quantity must always equal SUM(movements)
-- for the same item×warehouse (checked by tests + recomputeStockLevels).
CREATE TABLE stock_costs (
  item_id INTEGER NOT NULL REFERENCES items (id),
  warehouse_id INTEGER NOT NULL REFERENCES warehouses (id),
  quantity INTEGER NOT NULL DEFAULT 0,
  avg_cost_cents INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (item_id, warehouse_id)
);

-- Derived levels view: the single source of truth for "how much is here".
CREATE VIEW stock_levels AS
SELECT item_id, warehouse_id, SUM(quantity) AS quantity
FROM stock_movements
GROUP BY item_id, warehouse_id;
