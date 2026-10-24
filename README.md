# Tally ERP

Self-hosted, soup-to-nuts ERP (accounting, HR/payroll, CRM, inventory,
procurement, reporting) engineered for HIPAA and FINRA compliance from the
ground up. **Bun + zero npm dependencies + SQLite.** One process, one local
database file, REST JSON API.

> Honest posture: Tally builds the *technical controls* mapped to specific
> rule citations (HIPAA Security Rule safeguards; FINRA 4510-series books &
> records, WORM retention, 3110 supervision). Legal attestation and
> certification stay with you and your counsel — code cannot certify itself.
> No PHI/PII is ever committed to this repo: seed data is synthetic only.

## Quick start

```sh
# 1. set the field-encryption key (32 bytes, hex or base64; never commit it)
export TALLY_DATA_KEY=$(openssl rand -hex 32)

# 2. dev mode: allow plain HTTP on loopback (production serves TLS only)
export TALLY_ALLOW_INSECURE=1

# 3. migrate + seed, then serve
bun src/cli.ts migrate
bun src/cli.ts seed
bun src/cli.ts serve            # port 3041, or TALLY_PORT / --port
```

`bun test` runs the suite (uses ephemeral ports and temp databases).
`bun src/cli.ts verify` checks storage integrity (audit chain, document
hashes, retention coverage) — the 17a-4(f)(2)(ii) automatic verification.

## Configuration

| Var | Default | Purpose |
|---|---|---|
| `TALLY_PORT` | `3041` | HTTP port |
| `TALLY_DB` | `./data/tally.db` | SQLite file |
| `TALLY_DATA_KEY` | — | 32-byte field-encryption key (64-char hex or base64) |
| `TALLY_IDLE_TIMEOUT_MS` | `900000` (15 min) | session idle timeout (H-T3) |
| `TALLY_ABSOLUTE_MAX_MS` | `43200000` (12 h) | absolute session lifetime |
| `TALLY_TLS_CERT` / `TALLY_TLS_KEY` | — | TLS cert/key; plain HTTP refuses to start without these unless `TALLY_ALLOW_INSECURE=1` |
| `TALLY_ALLOW_INSECURE` | unset | dev-only flag permitting plain HTTP |

## API (Phase 0–3 surface)

Base: `/api/v1`. Errors: `{ error: { code, message } }` with stable machine
codes (`unauthorized`, `session_expired`, `forbidden`, `validation`,
`invalid_credentials`, `account_locked`, `not_found`, `unbalanced`,
`period_closed`, `already_reversed`, `in_use`, `overlap`, `no_open_period`,
`retained`, `corrupt`, `over_applied`, `not_draft`, `not_posted`,
`already_posted`, `already_void`, `void_blocked`).

```
POST /api/v1/auth/login { email, password } -> { token, expires_at, must_change_password }
POST /api/v1/auth/logout                        (Bearer)
GET  /api/v1/auth/me                            (Bearer)
GET  /api/v1/compliance/audit-log               (Bearer; roles with audit:read)
     ?action= &entity_type= &actor_id= &since= &until= &page= &per_page= &verify=1
GET  /api/v1/compliance/retention-report        (Bearer; audit:read)
GET  /api/v1/compliance/verify                  (Bearer; audit:read; storage verification)
GET  /api/v1/compliance/export                  (Bearer; audit:read)
     ?entity_type=audit_log|documents|journal_entries &entity_id= &format=json|csv
GET  /api/v1/documents                          (Bearer; documents:read; ?doc_type= &page= &per_page=)
POST /api/v1/documents                          (Bearer; documents:write)
     JSON { title, doc_type, mime_type?, content_base64 }
     — or multipart form: file= + title/doc_type fields
     identical bytes dedupe to the stored row (200, deduped:true)
GET  /api/v1/documents/:id                      (Bearer; documents:read; metadata)
GET  /api/v1/documents/:id/content              (Bearer; documents:read; bytes, sha256 etag)
DELETE /api/v1/documents/:id                    (Bearer; documents:write)
     retained -> 405 retained (and audited as document.delete_denied);
     allowed only after retain_until passes (WORM trigger is the backstop)
GET  /api/v1/ledger/accounts                     (Bearer; ledger:read)
POST /api/v1/ledger/accounts { code, name, type, parent_id? }   (ledger:write)
GET  /api/v1/ledger/accounts/:id                 (ledger:read)
PATCH /api/v1/ledger/accounts/:id { name }       (ledger:write)
DELETE /api/v1/ledger/accounts/:id               (ledger:write; soft-delete, blocked while in use)
GET  /api/v1/ledger/accounts/:id/ledger          (ledger:read; ?period_id= &from= &to=)
POST /api/v1/ledger/journal { memo, lines, period_id?, posted_on? }  (ledger:post; Idempotency-Key honored)
GET  /api/v1/ledger/journal                      (ledger:read; ?period_id= &page= &per_page=)
GET  /api/v1/ledger/journal/:id                  (ledger:read)
POST /api/v1/ledger/journal/:id/reverse { memo?, posted_on?, period_id? }  (ledger:post)
GET  /api/v1/ledger/periods                      (ledger:read)
POST /api/v1/ledger/periods { name, starts_on, ends_on }   (ledger:write)
POST /api/v1/ledger/periods/:id/close            (ledger:approve; trial-balance gate)
POST /api/v1/ledger/periods/:id/reopen           (ledger:admin; audited)
GET  /api/v1/ledger/trial-balance?period_id=     (ledger:read)
POST /api/v1/ar/customers { name, email?, phone?, billing_address?, credit_limit_cents?, status? }  (ar:write)
GET  /api/v1/ar/customers                        (ar:read; ?status=)
GET  /api/v1/ar/customers/:id                    (ar:read)
PATCH /api/v1/ar/customers/:id                   (ar:write)
POST /api/v1/ar/invoices { customer_id, issue_date, due_date, tax_cents?, lines[] }  (ar:write; draft)
GET  /api/v1/ar/invoices                         (ar:read; ?customer_id= &status=)
GET  /api/v1/ar/invoices/:id                     (ar:read; includes lines + open_balance_cents)
PATCH /api/v1/ar/invoices/:id { due_date?, tax_cents?, lines? }  (ar:write; draft only)
POST /api/v1/ar/invoices/:id/post                (ar:post; Idempotency-Key honored)
     Dr AR 1100 / Cr Revenue 4000 / Cr Tax Payable 2100; GL posted_on = issue_date
POST /api/v1/ar/invoices/:id/void                (ar:approve; Idempotency-Key honored)
     reversing entry; refused while payments/credits are applied (void_blocked)
POST /api/v1/ar/payments { customer_id, method, amount_cents, received_on, applications?[] }  (ar:post; Idempotency-Key honored)
     Dr Cash 1000 / Cr AR 1100 for the full amount; applications allocate AR, never over-apply
GET  /api/v1/ar/payments                         (ar:read; ?customer_id=)
GET  /api/v1/ar/payments/:id                     (ar:read; includes applications)
POST /api/v1/ar/payments/:id/apply { invoice_id, amount_cents }  (ar:post; Idempotency-Key honored)
     applies leftover on-account credit; no new GL entry (cash already recognized)
POST /api/v1/ar/credit-memos { customer_id, invoice_id, amount_cents, reason }  (ar:write; draft)
GET  /api/v1/ar/credit-memos                     (ar:read; ?customer_id= &invoice_id=)
GET  /api/v1/ar/credit-memos/:id                 (ar:read)
POST /api/v1/ar/credit-memos/:id/post            (ar:post; Idempotency-Key honored)
     Dr Revenue 4000 / Cr AR 1100; re-validated against the CURRENT open balance
POST /api/v1/ar/credit-memos/:id/void            (ar:approve; Idempotency-Key honored)
     reversing entry; restores the invoice's open balance
GET  /health
```

Auth: argon2id passwords (≥12 chars, common-password screen), failed-login
lockout with exponential backoff, bearer sessions stored as sha256 hashes
(the raw token is shown once, at login), 15-minute sliding idle timeout and
12-hour absolute max enforced server-side on every request.

RBAC: least-privilege roles `admin`, `accountant`, `ap_clerk`, `sales`, `hr`,
`auditor`, `viewer`; default-deny; `auditor` is read-only everywhere.
Seeded admin: `admin@example.local` / `Changeme-123456` (must-change on first login).

Audit: every mutating request writes a hash-chained, append-only `audit_log`
row (`hash = sha256(prev_hash || canonical JSON)`); DB triggers reject
UPDATE/DELETE on the log; `?verify=1` recomputes the chain server-side.
Secrets (passwords, tokens, keys) are never written to the log.

Ledger: the only path to GL writes is `postJournal()` — balanced, integer
cents, open-period check; posted entries are immutable at the DB level
(triggers reject UPDATE/DELETE); corrections post reversing entries via
`reverseJournal()` (swapped debits/credits, `reversed_by` on the new entry).
Period close runs a trial-balance gate; reopening requires `ledger:admin` and
is audited. Financial mutations accept `Idempotency-Key`.

Encryption: field-level AES-256-GCM via WebCrypto for designated sensitive
columns (HR PII lands in Phase 8; the mechanism and its tests are Phase 0).
Document contents are AES-256-GCM ciphertext at rest (`iv(12) || ct`); the
content address (`sha256` of plaintext) is stored alongside, so dedupe and
`tally verify` operate on the real bytes.

WORM store + retention (Phase 2): `documents` is content-addressed, ciphertext
at rest, and WORM — DB triggers reject UPDATE always and DELETE while
`retain_until` is in the future. The retention engine maps document types to
17a-4 periods (`doc_retention_years`, F-R7 floor of 3y, conservative 6y
default); delete paths return 405 `retained` while a record is retained and
audit denied attempts. `tally verify` (or `GET /api/v1/compliance/verify`)
recomputes the audit chain, re-verifies every document (GCM authentication +
hash), and reports per-type retention coverage. `GET /api/v1/compliance/export`
streams records plus their full audit history as JSON or CSV
(17a-4(f)(2)(ii)–(iv) "ready download/transfer").

Accounts receivable (Phase 3): customers, invoices (+lines), payments with
application logic, credit memos — all GL effects via `postJournal()` /
`reverseJournal()`, never direct journal writes. Invoices are drafts until
posted (Dr AR / Cr Revenue / Cr Tax Payable, posted_on = issue_date); posted
invoices are never edited in place — corrections are voids (reversing entry,
original untouched) or credit memos. A payment's applications can never exceed
an invoice's open balance (single, combined, or against unapplied credit),
and a credit memo re-validates against the current open balance at post time,
so a balance that moved since drafting can never be over-credited. Voiding an
invoice with payments/credits applied is refused (`void_blocked`) — credit the
balance instead. Credit limits are recorded on customers but not yet enforced
(v1 honesty note; enforcement lands with AP/credit policy work).

## Layout

```
src/server.ts      HTTP API (Bun.serve)
src/db.ts          SQLite open + migrations
src/crypto.ts      AES-256-GCM field/byte encryption, sha256 helpers
src/auth.ts        passwords, lockout, sessions
src/rbac.ts        permission evaluation (permissions are seeded data)
src/audit.ts       hash-chained append-only log + chain verification
src/middleware.ts  JSON/errors, auth+RBAC wrappers, audited-mutation helper
src/ledger.ts      ledger core: postJournal/reverseJournal, accounts, periods,
                   trial balance, account ledger, idempotency
src/ar.ts          AR: customers, invoices, payments, credit memos (via ledger only)
src/documents.ts   WORM content-addressed document store
src/retention.ts   retention engine: schedules, enforcement, coverage report
src/compliance.ts  tally verify + compliance export (JSON/CSV)
src/seed.ts        roles, RBAC matrix, admin user, retention policies,
                   default chart of accounts, current-year fiscal period
src/cli.ts         `tally serve|seed|migrate|verify`
migrations/        ordered SQL migrations (tracked in schema_migrations)
tests/             bun test suite
```

## Compliance map (Phase 0–3)

H-T1 unique user IDs · H-T3 automatic logoff · H-T4 encryption ·
H-T5 audit controls · H-T6 (ledger) · H-T7 person authentication ·
H-A2 access management · H-A3 password management · H-A5 6y documentation
retention · F-R1 books/records substrate · F-R2 format/media · F-R3
immutability + WORM path · F-R4 automatic verification, export/download ·
F-R7 retention periods. Full citations in the goal workspace
`compliance-matrix.md`.
