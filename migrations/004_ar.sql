-- Tally ERP — migration 004: accounts receivable (Phase 3)
-- customers · invoices (+lines) · payments (+applications) · credit memos
-- GL effects always flow through postJournal() (ledger.ts); posted invoices
-- are edited only via void (reversing entry) or credit memo, never in place.

CREATE TABLE customers (
  id                 INTEGER PRIMARY KEY,
  name               TEXT NOT NULL,
  email              TEXT NULL,
  phone              TEXT NULL,
  billing_address    TEXT NULL,
  credit_limit_cents INTEGER NOT NULL DEFAULT 0 CHECK (credit_limit_cents >= 0),
  status             TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
  created_at         TEXT NOT NULL,
  updated_at         TEXT NOT NULL
);

CREATE TABLE invoices (
  id               INTEGER PRIMARY KEY,
  invoice_no       TEXT NOT NULL UNIQUE,
  customer_id      INTEGER NOT NULL REFERENCES customers(id),
  status           TEXT NOT NULL DEFAULT 'draft'
                   CHECK (status IN ('draft', 'posted', 'partially_paid', 'paid', 'void')),
  issue_date       TEXT NOT NULL, -- ISO date YYYY-MM-DD; also the GL posted_on
  due_date         TEXT NOT NULL, -- ISO date YYYY-MM-DD
  subtotal_cents   INTEGER NOT NULL DEFAULT 0 CHECK (subtotal_cents >= 0),
  tax_cents        INTEGER NOT NULL DEFAULT 0 CHECK (tax_cents >= 0),
  total_cents      INTEGER NOT NULL DEFAULT 0 CHECK (total_cents >= 0),
  paid_cents       INTEGER NOT NULL DEFAULT 0 CHECK (paid_cents >= 0),
  credited_cents   INTEGER NOT NULL DEFAULT 0 CHECK (credited_cents >= 0),
  posted_entry_id  INTEGER NULL REFERENCES journal_entries(id),
  void_entry_id    INTEGER NULL REFERENCES journal_entries(id),
  created_by       INTEGER NULL REFERENCES users(id),
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE TABLE invoice_lines (
  id               INTEGER PRIMARY KEY,
  invoice_id       INTEGER NOT NULL REFERENCES invoices(id),
  description      TEXT NOT NULL,
  quantity         INTEGER NOT NULL CHECK (quantity > 0),
  unit_price_cents INTEGER NOT NULL CHECK (unit_price_cents >= 0),
  amount_cents     INTEGER NOT NULL CHECK (amount_cents >= 0)
);

CREATE TABLE payments (
  id               INTEGER PRIMARY KEY,
  payment_no       TEXT NOT NULL UNIQUE,
  customer_id      INTEGER NOT NULL REFERENCES customers(id),
  method           TEXT NOT NULL, -- cash, check, card, wire, other
  amount_cents     INTEGER NOT NULL CHECK (amount_cents > 0),
  unapplied_cents  INTEGER NOT NULL CHECK (unapplied_cents >= 0),
  received_on      TEXT NOT NULL, -- ISO date YYYY-MM-DD; also the GL posted_on
  posted_entry_id  INTEGER NULL REFERENCES journal_entries(id),
  created_by       INTEGER NULL REFERENCES users(id),
  created_at       TEXT NOT NULL
);

-- A payment may be applied to several invoices, and the same invoice may
-- receive several applications (initial + later apply of unapplied credit),
-- so there is deliberately NO unique constraint on (payment_id, invoice_id).
CREATE TABLE payment_applications (
  id           INTEGER PRIMARY KEY,
  payment_id   INTEGER NOT NULL REFERENCES payments(id),
  invoice_id   INTEGER NOT NULL REFERENCES invoices(id),
  amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
  applied_at   TEXT NOT NULL
);

CREATE TABLE credit_memos (
  id              INTEGER PRIMARY KEY,
  memo_no         TEXT NOT NULL UNIQUE,
  customer_id     INTEGER NOT NULL REFERENCES customers(id),
  invoice_id      INTEGER NOT NULL REFERENCES invoices(id),
  status          TEXT NOT NULL DEFAULT 'draft'
                  CHECK (status IN ('draft', 'posted', 'void')),
  amount_cents    INTEGER NOT NULL CHECK (amount_cents > 0),
  reason          TEXT NOT NULL,
  posted_entry_id INTEGER NULL REFERENCES journal_entries(id),
  void_entry_id   INTEGER NULL REFERENCES journal_entries(id),
  created_by      INTEGER NULL REFERENCES users(id),
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL
);

CREATE INDEX idx_customers_status   ON customers(status);
CREATE INDEX idx_invoices_customer  ON invoices(customer_id);
CREATE INDEX idx_invoices_status    ON invoices(status);
CREATE INDEX idx_ilines_invoice     ON invoice_lines(invoice_id);
CREATE INDEX idx_payments_customer  ON payments(customer_id);
CREATE INDEX idx_papp_payment       ON payment_applications(payment_id);
CREATE INDEX idx_papp_invoice       ON payment_applications(invoice_id);
CREATE INDEX idx_cmemos_customer     ON credit_memos(customer_id);
CREATE INDEX idx_cmemos_invoice      ON credit_memos(invoice_id);
