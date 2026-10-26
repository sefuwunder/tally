-- Tally ERP — migration 007: procurement (Phase 6)
-- purchase_orders (+lines, status machine draft → open →
-- partially_received / fully_received → closed, or cancelled) ·
-- receivings (+lines) that post inventory movements and accrue AP.
-- A receiving is a books-and-records row (F-R3): triggers reject
-- UPDATE/DELETE on receivings and receiving_lines. Corrections happen
-- via a new receiving, never by editing history. PO lines carry
-- quantity_received, guarded at the DB level (never above ordered):
-- partial receivings track correctly even if application code slips.
-- The AP accrual itself is a journal entry (Dr Inventory / Cr AP 2000)
-- recorded as receivings.accrued_entry_id — it is NOT a bills row:
-- a bill must still pass AP maker-checker approval (Phase 4), so
-- receiving never mints an approved bill on its own. Matching a later
-- vendor invoice bill against the accrual (3-way match / GR-IR
-- clearing) is post-v1; see procurement.ts and README.

CREATE TABLE purchase_orders (
  id               INTEGER PRIMARY KEY,
  po_no            TEXT NOT NULL UNIQUE,
  vendor_id        INTEGER NOT NULL REFERENCES vendors(id),
  status           TEXT NOT NULL DEFAULT 'draft'
                   CHECK (status IN ('draft', 'open', 'partially_received',
                                     'fully_received', 'closed', 'cancelled')),
  order_date       TEXT NOT NULL, -- ISO date YYYY-MM-DD
  expected_date    TEXT NULL, -- ISO date YYYY-MM-DD
  notes            TEXT NULL,
  created_by       INTEGER NULL REFERENCES users(id),
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE TABLE po_lines (
  id               INTEGER PRIMARY KEY,
  po_id            INTEGER NOT NULL REFERENCES purchase_orders(id),
  item_id          INTEGER NOT NULL REFERENCES items(id),
  quantity_ordered INTEGER NOT NULL CHECK (quantity_ordered > 0),
  unit_cost_cents  INTEGER NOT NULL CHECK (unit_cost_cents >= 0),
  quantity_received INTEGER NOT NULL DEFAULT 0
                   CHECK (quantity_received >= 0
                          AND quantity_received <= quantity_ordered)
);

CREATE TABLE receivings (
  id               INTEGER PRIMARY KEY,
  receiving_no     TEXT NOT NULL UNIQUE,
  po_id            INTEGER NOT NULL REFERENCES purchase_orders(id),
  warehouse_id     INTEGER NOT NULL REFERENCES warehouses(id),
  receiving_date   TEXT NOT NULL, -- ISO date YYYY-MM-DD; also the GL posted_on
  accrued_entry_id INTEGER NULL REFERENCES journal_entries(id),
  received_by      INTEGER NULL REFERENCES users(id),
  created_at       TEXT NOT NULL
);

CREATE TABLE receiving_lines (
  id              INTEGER PRIMARY KEY,
  receiving_id    INTEGER NOT NULL REFERENCES receivings(id),
  po_line_id      INTEGER NOT NULL REFERENCES po_lines(id),
  item_id         INTEGER NOT NULL REFERENCES items(id),
  quantity        INTEGER NOT NULL CHECK (quantity > 0),
  unit_cost_cents INTEGER NOT NULL CHECK (unit_cost_cents >= 0)
);

CREATE INDEX idx_po_vendor      ON purchase_orders(vendor_id);
CREATE INDEX idx_po_status      ON purchase_orders(status);
CREATE INDEX idx_polines_po     ON po_lines(po_id);
CREATE INDEX idx_receivings_po  ON receivings(po_id);
CREATE INDEX idx_rlines_recv    ON receiving_lines(receiving_id);
CREATE INDEX idx_rlines_poline  ON receiving_lines(po_line_id);

-- Append-only receivings (F-R3): a receiving, once booked, is history.
CREATE TRIGGER receivings_no_update
BEFORE UPDATE ON receivings
BEGIN
  SELECT RAISE(ABORT, 'receivings are append-only');
END;

CREATE TRIGGER receivings_no_delete
BEFORE DELETE ON receivings
BEGIN
  SELECT RAISE(ABORT, 'receivings are append-only');
END;

CREATE TRIGGER receiving_lines_no_update
BEFORE UPDATE ON receiving_lines
BEGIN
  SELECT RAISE(ABORT, 'receiving_lines are append-only');
END;

CREATE TRIGGER receiving_lines_no_delete
BEFORE DELETE ON receiving_lines
BEGIN
  SELECT RAISE(ABORT, 'receiving_lines are append-only');
END;
