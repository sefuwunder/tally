-- Tally ERP — migration 003: WORM document store + retention engine (Phase 2)
--
-- documents: content-addressed (content_sha256 = sha256 of PLAINTEXT bytes),
-- ciphertext at rest (iv(12) || AES-256-GCM, see crypto.ts encryptBytes),
-- WORM while retained: triggers reject UPDATE always, and DELETE while
-- retain_until is in the future (F-R3 WORM path, F-R7 periods).

CREATE TABLE doc_retention_years (
  doc_type TEXT PRIMARY KEY,
  years    INTEGER NOT NULL CHECK (years >= 3)  -- F-R7 floor: everything else >= 3y
);

CREATE TABLE documents (
  id             INTEGER PRIMARY KEY,
  uuid           TEXT NOT NULL UNIQUE,
  title          TEXT NOT NULL,
  doc_type       TEXT NOT NULL,
  mime_type      TEXT NOT NULL DEFAULT 'application/octet-stream',
  size_bytes     INTEGER NOT NULL,
  content_sha256 TEXT NOT NULL UNIQUE,
  content        BLOB NOT NULL,
  retain_until   TEXT NOT NULL,   -- ISO date (YYYY-MM-DD); deletion blocked while > today
  uploaded_by    INTEGER NULL REFERENCES users(id),
  created_at     TEXT NOT NULL
);

-- WORM: stored documents are never rewritten.
CREATE TRIGGER documents_no_update
BEFORE UPDATE ON documents
BEGIN
  SELECT RAISE(ABORT, 'documents are WORM: UPDATE rejected');
END;

-- WORM while retained: deletion blocked until retain_until passes.
CREATE TRIGGER documents_no_delete_retained
BEFORE DELETE ON documents
WHEN (OLD.retain_until > date('now'))
BEGIN
  SELECT RAISE(ABORT, 'documents are WORM while retained: DELETE rejected');
END;

CREATE INDEX idx_documents_type ON documents(doc_type);
CREATE INDEX idx_documents_sha  ON documents(content_sha256);
