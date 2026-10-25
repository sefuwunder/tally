-- Tally ERP — migration 005: accounts payable (Phase 4)
-- vendors · bills (+lines, each line carries its expense account) ·
-- bill payments (+applications). Maker-checker: a bill moves
-- draft → approved → posted, and the approver must differ from the
-- creator (enforced in ap.ts, recorded as approved_by).
-- GL effects always flow through postJournal() (ledger.ts); posted bills
-- are corrected only via void (reversing entry), never in place.

CREATE TABLE vendors (
  id                  INTEGER PRIMARY KEY,
  name                TEXT NOT NULL,
  email               TEXT NULL,
  phone               TEXT NULL,
  remittance_address  TEXT NULL,
  status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
  created_at          TEXT NOT NULL,
  updated_at          TEXT NOT NULL
);

CREATE TABLE bills (
  id               INTEGER PRIMARY KEY,
  bill_no          TEXT NOT NULL UNIQUE,
  vendor_id        INTEGER NOT NULL REFERENCES vendors(id),
  status           TEXT NOT NULL DEFAULT 'draft'
                   CHECK (status IN ('draft', 'approved', 'posted', 'partially_paid', 'paid', 'void')),
  bill_date        TEXT NOT NULL, -- ISO date YYYY-MM-DD; also the GL posted_on
  due_date         TEXT NOT NULL, -- ISO date YYYY-MM-DD
  subtotal_cents   INTEGER NOT NULL DEFAULT 0 CHECK (subtotal_cents >= 0),
  tax_cents        INTEGER NOT NULL DEFAULT 0 CHECK (tax_cents >= 0),
  total_cents      INTEGER NOT NULL DEFAULT 0 CHECK (total_cents >= 0),
  paid_cents       INTEGER NOT NULL DEFAULT 0 CHECK (paid_cents >= 0),
  posted_entry_id  INTEGER NULL REFERENCES journal_entries(id),
  void_entry_id    INTEGER NULL REFERENCES journal_entries(id),
  created_by       INTEGER NULL REFERENCES users(id),
  approved_by      INTEGER NULL REFERENCES users(id),
  approved_at      TEXT NULL,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE TABLE bill_lines (
  id               INTEGER PRIMARY KEY,
  bill_id          INTEGER NOT NULL REFERENCES bills(id),
  description      TEXT NOT NULL,
  quantity         INTEGER NOT NULL CHECK (quantity > 0),
  unit_price_cents INTEGER NOT NULL CHECK (unit_price_cents >= 0),
  amount_cents     INTEGER NOT NULL CHECK (amount_cents >= 0),
  account_code     TEXT NOT NULL -- expense/asset account debited at post time
);

CREATE TABLE bill_payments (
  id               INTEGER PRIMARY KEY,
  payment_no       TEXT NOT NULL UNIQUE,
  vendor_id        INTEGER NOT NULL REFERENCES vendors(id),
  method           TEXT NOT NULL, -- cash, check, card, wire, other
  amount_cents     INTEGER NOT NULL CHECK (amount_cents > 0),
  unapplied_cents  INTEGER NOT NULL CHECK (unapplied_cents >= 0),
  paid_on          TEXT NOT NULL, -- ISO date YYYY-MM-DD; also the GL posted_on
  posted_entry_id  INTEGER NULL REFERENCES journal_entries(id),
  created_by       INTEGER NULL REFERENCES users(id),
  created_at       TEXT NOT NULL
);

-- A payment may be applied to several bills, and the same bill may
-- receive several applications (initial + later apply of unapplied
-- credit), so there is deliberately NO unique constraint on
-- (payment_id, bill_id) — same rationale as AR payment_applications.
CREATE TABLE bill_payment_applications (
  id           INTEGER PRIMARY KEY,
  payment_id   INTEGER NOT NULL REFERENCES bill_payments(id),
  bill_id      INTEGER NOT NULL REFERENCES bills(id),
  amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
  applied_at   TEXT NOT NULL
);

CREATE INDEX idx_vendors_status    ON vendors(status);
CREATE INDEX idx_bills_vendor      ON bills(vendor_id);
CREATE INDEX idx_bills_status      ON bills(status);
CREATE INDEX idx_blines_bill       ON bill_lines(bill_id);
CREATE INDEX idx_bpay_vendor       ON bill_payments(vendor_id);
CREATE INDEX idx_bpapp_payment      ON bill_payment_applications(payment_id);
CREATE INDEX idx_bpapp_bill         ON bill_payment_applications(bill_id);
