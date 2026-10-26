-- Tally ERP — migration 008: CRM + supervision surfaces (Phase 7)
-- companies (FINRA 4512 field set, completeness validated in crm.ts),
-- contacts, deals pipeline, immutable activities (comms log, F-S1/F-R10),
-- comms_reviews (principal review evidence, immutable once written),
-- complaints (F-R9/F-S2 state machine; content immutable, status moves).
-- F-S3: supervisory personnel are users with is_principal + title/location.

ALTER TABLE users ADD COLUMN is_principal INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN title TEXT NULL;
ALTER TABLE users ADD COLUMN location TEXT NULL;

CREATE TABLE companies (
  id                    INTEGER PRIMARY KEY,
  name                  TEXT NOT NULL,
  legal_name            TEXT NULL,
  address               TEXT NULL,
  tax_id                TEXT NULL,
  investment_objectives TEXT NULL,
  authorized_parties    TEXT NULL,
  status                TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
  created_by            INTEGER NULL REFERENCES users(id),
  created_at            TEXT NOT NULL,
  updated_at            TEXT NOT NULL
);

CREATE TABLE contacts (
  id          INTEGER PRIMARY KEY,
  company_id  INTEGER NULL REFERENCES companies(id),
  name        TEXT NOT NULL,
  email       TEXT NULL,
  phone       TEXT NULL,
  address     TEXT NULL,
  status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
  created_by  INTEGER NULL REFERENCES users(id),
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);

CREATE TABLE deals (
  id                  INTEGER PRIMARY KEY,
  title               TEXT NOT NULL,
  company_id          INTEGER NULL REFERENCES companies(id),
  contact_id          INTEGER NULL REFERENCES contacts(id),
  stage               TEXT NOT NULL DEFAULT 'lead'
                      CHECK (stage IN ('lead', 'qualified', 'proposal', 'negotiation', 'won', 'lost')),
  amount_cents        INTEGER NOT NULL DEFAULT 0 CHECK (amount_cents >= 0),
  expected_close_date TEXT NULL,
  owner_id            INTEGER NULL REFERENCES users(id),
  created_by          INTEGER NULL REFERENCES users(id),
  created_at          TEXT NOT NULL,
  updated_at          TEXT NOT NULL
);

CREATE TABLE activities (
  id                INTEGER PRIMARY KEY,
  direction         TEXT NOT NULL CHECK (direction IN ('in', 'out', 'internal')),
  channel           TEXT NOT NULL CHECK (channel IN ('email', 'phone', 'meeting', 'note', 'other')),
  origin            TEXT NOT NULL DEFAULT 'manual' CHECK (origin IN ('manual', 'ai_agent')),
  subject           TEXT NULL,
  body              TEXT NULL,
  company_id        INTEGER NULL REFERENCES companies(id),
  contact_id        INTEGER NULL REFERENCES contacts(id),
  deal_id           INTEGER NULL REFERENCES deals(id),
  author_id         INTEGER NULL REFERENCES users(id),
  flagged_for_review INTEGER NOT NULL DEFAULT 0,
  supervision_status TEXT NOT NULL DEFAULT 'not_required'
                      CHECK (supervision_status IN ('not_required', 'unreviewed', 'reviewed')),
  created_at        TEXT NOT NULL
);

-- Append-only: a comms record is a book/record (F-R1/F-R3). Review evidence
-- lives in comms_reviews, never as an edit to the activity itself.
CREATE TRIGGER activities_no_update
BEFORE UPDATE ON activities
BEGIN
  SELECT RAISE(ABORT, 'activities are append-only: UPDATE rejected');
END;

CREATE TRIGGER activities_no_delete
BEFORE DELETE ON activities
BEGIN
  SELECT RAISE(ABORT, 'activities are append-only: DELETE rejected');
END;

CREATE TABLE comms_reviews (
  id          INTEGER PRIMARY KEY,
  activity_id INTEGER NOT NULL UNIQUE REFERENCES activities(id),
  reviewer_id INTEGER NOT NULL REFERENCES users(id),
  disposition TEXT NOT NULL CHECK (disposition IN ('approved', 'rejected')),
  notes       TEXT NULL,
  reviewed_at TEXT NOT NULL
);

-- Review evidence is itself immutable (F-S1: review "evidenced in writing").
CREATE TRIGGER comms_reviews_no_update
BEFORE UPDATE ON comms_reviews
BEGIN
  SELECT RAISE(ABORT, 'comms_reviews are append-only: UPDATE rejected');
END;

CREATE TRIGGER comms_reviews_no_delete
BEFORE DELETE ON comms_reviews
BEGIN
  SELECT RAISE(ABORT, 'comms_reviews are append-only: DELETE rejected');
END;

CREATE TABLE complaints (
  id              INTEGER PRIMARY KEY,
  company_id      INTEGER NULL REFERENCES companies(id),
  contact_id      INTEGER NULL REFERENCES contacts(id),
  subject         TEXT NOT NULL,
  description     TEXT NULL,
  status          TEXT NOT NULL DEFAULT 'received'
                    CHECK (status IN ('received', 'acknowledged', 'responded')),
  ack_sla_days    INTEGER NOT NULL DEFAULT 7 CHECK (ack_sla_days >= 1),
  received_at     TEXT NOT NULL,
  acknowledged_at TEXT NULL,
  responded_at    TEXT NULL,
  created_by      INTEGER NULL REFERENCES users(id),
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL
);

-- Complaint content is immutable once filed (F-R9); only the workflow
-- columns (status + its timestamps + updated_at) may move.
CREATE TRIGGER complaints_content_immutable
BEFORE UPDATE ON complaints
WHEN OLD.company_id IS NOT NEW.company_id
  OR OLD.contact_id IS NOT NEW.contact_id
  OR OLD.subject IS NOT NEW.subject
  OR OLD.description IS NOT NEW.description
  OR OLD.ack_sla_days IS NOT NEW.ack_sla_days
  OR OLD.received_at IS NOT NEW.received_at
BEGIN
  SELECT RAISE(ABORT, 'complaint content is immutable: only status/timestamps may change');
END;

CREATE INDEX idx_contacts_company ON contacts(company_id);
CREATE INDEX idx_deals_company ON deals(company_id);
CREATE INDEX idx_deals_stage ON deals(stage);
CREATE INDEX idx_activities_company ON activities(company_id);
CREATE INDEX idx_activities_contact ON activities(contact_id);
CREATE INDEX idx_activities_flagged ON activities(flagged_for_review);
CREATE INDEX idx_complaints_status ON complaints(status);
CREATE INDEX idx_users_principal ON users(is_principal);
