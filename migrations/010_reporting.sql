-- Tally ERP — migration 010: reporting (Phase 9)
-- report_runs: pinned report snapshots. A pinned run records WHAT was
-- generated (report_type + params), WHEN, BY WHOM, and the sha256 of the
-- canonical JSON output, so a later re-run can prove whether the same
-- inputs still reproduce the same output (F-R4 "recreate the original
-- record" for reports). Pinned runs are immutable: the triggers below
-- reject UPDATE and DELETE outright — a pin is evidence, not a draft.
-- (Retention: report_runs are covered by the `report` retention policy,
-- 6y, and are retained indefinitely in v1 like journal/audit rows.)

CREATE TABLE report_runs (
  id             INTEGER PRIMARY KEY,
  report_type    TEXT NOT NULL CHECK (report_type IN
                   ('profit_loss', 'balance_sheet', 'cash_flow',
                    'ar_aging', 'ap_aging')),
  params_json    TEXT NOT NULL, -- the exact params the report was run with
  output_json    TEXT NOT NULL, -- the pinned output (canonical JSON)
  output_sha256  TEXT NOT NULL, -- sha256 of output_json
  generated_by   INTEGER NULL REFERENCES users(id),
  generated_at   TEXT NOT NULL,
  created_at     TEXT NOT NULL
);

CREATE TRIGGER trg_report_runs_no_update
BEFORE UPDATE ON report_runs
BEGIN
  SELECT RAISE(ABORT, 'report_runs are immutable once pinned');
END;

CREATE TRIGGER trg_report_runs_no_delete
BEFORE DELETE ON report_runs
BEGIN
  SELECT RAISE(ABORT, 'report_runs are immutable once pinned');
END;

CREATE INDEX idx_report_runs_type ON report_runs(report_type);
CREATE INDEX idx_report_runs_generated ON report_runs(generated_at);
