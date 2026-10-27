-- Tally ERP — migration 009: HR / payroll (Phase 8)
-- employees carry PII encrypted at rest (H-T4): ssn/dob/bank_account live
-- ONLY as AES-256-GCM blobs (ssn_enc/dob_enc/bank_account_enc); the HTTP
-- surface never returns them — it returns ssn_last4 (display only).
-- Names + employment fields stay in clear: they are the operational
-- identifiers pay runs and lists key on, and they are not secrets.
-- deduction_types are the pay-line deduction config (percent-of-gross
-- in basis points, or a fixed amount); a type is active or not.
-- pay_runs move draft -> approved -> paid under maker-checker
-- (approver != creator, F-S supervision angle); paying posts ONE
-- summary journal entry (Dr Wages / Cr Cash / Cr Payroll Liabilities)
-- via postJournal() — per-employee detail never hits the GL directly.
-- pay_lines freeze once the run leaves draft (triggers); a paid run's
-- content columns are trigger-immutable (only status/timestamps/
-- journal_entry_id move), so a paid run is history, not editable state.

CREATE TABLE employees (
  id                INTEGER PRIMARY KEY,
  employee_no       TEXT NOT NULL UNIQUE,
  first_name        TEXT NOT NULL,
  last_name         TEXT NOT NULL,
  email             TEXT NULL,
  status            TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'inactive', 'terminated')),
  hire_date         TEXT NULL,
  pay_type          TEXT NOT NULL DEFAULT 'salary'
                    CHECK (pay_type IN ('salary', 'hourly')),
  base_pay_cents    INTEGER NOT NULL DEFAULT 0 CHECK (base_pay_cents >= 0),
  ssn_enc           TEXT NULL,
  ssn_last4         TEXT NULL,
  dob_enc           TEXT NULL,
  bank_account_enc  TEXT NULL,
  created_by        INTEGER NULL REFERENCES users(id),
  created_at        TEXT NOT NULL,
  updated_at        TEXT NOT NULL
);

CREATE TABLE deduction_types (
  id            INTEGER PRIMARY KEY,
  code          TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL,
  kind          TEXT NOT NULL CHECK (kind IN ('percent', 'fixed')),
  percent_bps   INTEGER NULL CHECK (percent_bps IS NULL OR (percent_bps >= 0 AND percent_bps <= 10000)),
  amount_cents  INTEGER NULL CHECK (amount_cents IS NULL OR amount_cents >= 0),
  active        INTEGER NOT NULL DEFAULT 1,
  created_by    INTEGER NULL REFERENCES users(id),
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL,
  CHECK (
    (kind = 'percent' AND percent_bps IS NOT NULL AND amount_cents IS NULL)
    OR (kind = 'fixed' AND amount_cents IS NOT NULL AND percent_bps IS NULL)
  )
);

CREATE TABLE pay_runs (
  id                INTEGER PRIMARY KEY,
  period_start      TEXT NOT NULL,
  period_end        TEXT NOT NULL,
  pay_date          TEXT NOT NULL,
  status            TEXT NOT NULL DEFAULT 'draft'
                    CHECK (status IN ('draft', 'approved', 'paid')),
  created_by        INTEGER NULL REFERENCES users(id),
  approved_by       INTEGER NULL REFERENCES users(id),
  approved_at       TEXT NULL,
  paid_at           TEXT NULL,
  journal_entry_id  INTEGER NULL REFERENCES journal_entries(id),
  created_at        TEXT NOT NULL,
  updated_at        TEXT NOT NULL,
  CHECK (period_start <= period_end)
);

CREATE TABLE pay_lines (
  id              INTEGER PRIMARY KEY,
  pay_run_id      INTEGER NOT NULL REFERENCES pay_runs(id),
  employee_id     INTEGER NOT NULL REFERENCES employees(id),
  gross_cents     INTEGER NOT NULL CHECK (gross_cents >= 0),
  deductions_json TEXT NOT NULL DEFAULT '[]',
  deductions_cents INTEGER NOT NULL DEFAULT 0 CHECK (deductions_cents >= 0),
  net_cents       INTEGER NOT NULL CHECK (net_cents >= 0),
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL,
  UNIQUE (pay_run_id, employee_id),
  CHECK (deductions_cents <= gross_cents)
);

-- A pay line is editable only while its run is a draft; once approved or
-- paid it is a book/record (F-R3).
CREATE TRIGGER pay_lines_no_update_when_frozen
BEFORE UPDATE ON pay_lines
WHEN (SELECT status FROM pay_runs WHERE id = OLD.pay_run_id) != 'draft'
BEGIN
  SELECT RAISE(ABORT, 'pay lines are frozen once the run leaves draft');
END;

CREATE TRIGGER pay_lines_no_delete_when_frozen
BEFORE DELETE ON pay_lines
WHEN (SELECT status FROM pay_runs WHERE id = OLD.pay_run_id) != 'draft'
BEGIN
  SELECT RAISE(ABORT, 'pay lines are frozen once the run leaves draft');
END;

-- A pay run's content is immutable once written; only the workflow columns
-- (status + approver/payer timestamps + journal link + updated_at) move.
CREATE TRIGGER pay_runs_content_immutable
BEFORE UPDATE ON pay_runs
WHEN OLD.period_start IS NOT NEW.period_start
  OR OLD.period_end IS NOT NEW.period_end
  OR OLD.pay_date IS NOT NEW.pay_date
  OR OLD.created_by IS NOT NEW.created_by
BEGIN
  SELECT RAISE(ABORT, 'pay run content is immutable: only status/timestamps may change');
END;

CREATE TRIGGER pay_runs_no_delete
BEFORE DELETE ON pay_runs
BEGIN
  SELECT RAISE(ABORT, 'pay runs are records: DELETE rejected');
END;

CREATE INDEX idx_employees_status ON employees(status);
CREATE INDEX idx_employees_no ON employees(employee_no);
CREATE INDEX idx_deduction_types_code ON deduction_types(code);
CREATE INDEX idx_pay_runs_status ON pay_runs(status);
CREATE INDEX idx_pay_lines_run ON pay_lines(pay_run_id);
CREATE INDEX idx_pay_lines_employee ON pay_lines(employee_id);
