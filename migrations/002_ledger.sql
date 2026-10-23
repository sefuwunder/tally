-- Tally ERP — migration 002: ledger core (Phase 1)
-- chart of accounts · fiscal periods · journal entries/lines (immutable) ·
-- sequence counter · idempotency records

CREATE TABLE accounts (
  id         INTEGER PRIMARY KEY,
  code       TEXT NOT NULL UNIQUE,
  name       TEXT NOT NULL,
  type       TEXT NOT NULL CHECK (type IN ('asset', 'liability', 'equity', 'revenue', 'expense')),
  parent_id  INTEGER NULL REFERENCES accounts(id),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  deleted_at TEXT NULL
);

CREATE TABLE fiscal_periods (
  id         INTEGER PRIMARY KEY,
  name       TEXT NOT NULL,
  starts_on  TEXT NOT NULL, -- ISO date YYYY-MM-DD
  ends_on    TEXT NOT NULL,
  closed_at  TEXT NULL,     -- NULL = open
  created_at TEXT NOT NULL,
  created_by INTEGER NULL REFERENCES users(id),
  UNIQUE (starts_on, ends_on)
);

CREATE TABLE journal_entries (
  id          INTEGER PRIMARY KEY,
  entry_no    TEXT NOT NULL UNIQUE,
  period_id   INTEGER NOT NULL REFERENCES fiscal_periods(id),
  memo        TEXT NOT NULL,
  source_type TEXT NULL,     -- which module posted: ar, ap, inventory, hr, manual
  source_id   TEXT NULL,     -- module's record id
  posted_on   TEXT NOT NULL, -- ISO date YYYY-MM-DD
  posted_at   TEXT NOT NULL, -- ISO datetime
  posted_by   INTEGER NULL REFERENCES users(id),
  reversed_by INTEGER NULL,  -- set on the *reversal* entry, points at the original
  created_at  TEXT NOT NULL
);

CREATE TABLE journal_lines (
  id           INTEGER PRIMARY KEY,
  entry_id     INTEGER NOT NULL REFERENCES journal_entries(id),
  account_id   INTEGER NOT NULL REFERENCES accounts(id),
  debit_cents  INTEGER NOT NULL DEFAULT 0 CHECK (debit_cents >= 0),
  credit_cents INTEGER NOT NULL DEFAULT 0 CHECK (credit_cents >= 0),
  CHECK (
    (debit_cents > 0 AND credit_cents = 0) OR
    (credit_cents > 0 AND debit_cents = 0)
  )
);

-- Posted entries are immutable (F-R3): no UPDATE, no DELETE, ever.
-- Corrections happen only via reversing entries (see ledger.ts reverseJournal).
CREATE TRIGGER journal_entries_no_update
BEFORE UPDATE ON journal_entries
BEGIN
  SELECT RAISE(ABORT, 'journal_entries is immutable: UPDATE rejected (post a reversing entry)');
END;

CREATE TRIGGER journal_entries_no_delete
BEFORE DELETE ON journal_entries
BEGIN
  SELECT RAISE(ABORT, 'journal_entries is immutable: DELETE rejected');
END;

CREATE TRIGGER journal_lines_no_update
BEFORE UPDATE ON journal_lines
BEGIN
  SELECT RAISE(ABORT, 'journal_lines is immutable: UPDATE rejected');
END;

CREATE TRIGGER journal_lines_no_delete
BEFORE DELETE ON journal_lines
BEGIN
  SELECT RAISE(ABORT, 'journal_lines is immutable: DELETE rejected');
END;

-- Monotonic document numbers, allocated inside the posting transaction.
CREATE TABLE sequences (
  name     TEXT PRIMARY KEY,
  next_val INTEGER NOT NULL
);

-- Idempotency records for financial mutations (double-submit safe retries).
CREATE TABLE idempotency_records (
  key           TEXT PRIMARY KEY,
  actor_id      INTEGER NULL REFERENCES users(id),
  method        TEXT NOT NULL,
  path          TEXT NOT NULL,
  response_code INTEGER NOT NULL,
  response_json TEXT NOT NULL,
  created_at    TEXT NOT NULL
);

CREATE INDEX idx_accounts_parent ON accounts(parent_id);
CREATE INDEX idx_accounts_type   ON accounts(type);
CREATE INDEX idx_journal_period  ON journal_entries(period_id);
CREATE INDEX idx_journal_posted  ON journal_entries(posted_on);
CREATE INDEX idx_journal_source  ON journal_entries(source_type, source_id);
CREATE INDEX idx_jlines_entry    ON journal_lines(entry_id);
CREATE INDEX idx_jlines_account  ON journal_lines(account_id);
CREATE INDEX idx_periods_range   ON fiscal_periods(starts_on, ends_on);
