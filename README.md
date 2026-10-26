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

## API (Phase 0–6 surface)

Base: `/api/v1`. Errors: `{ error: { code, message } }` with stable machine
codes (`unauthorized`, `session_expired`, `forbidden`, `validation`,
`invalid_credentials`, `account_locked`, `not_found`, `unbalanced`,
`period_closed`, `already_reversed`, `in_use`, `overlap`, `no_open_period`,
`retained`, `corrupt`, `over_applied`, `not_draft`, `not_posted`,
`already_posted`, `already_void`, `void_blocked`,
`not_approved`, `already_approved`, `self_approval`, `not_receivable`,
`over_received`, `line_mismatch`, `not_submitted`, `not_cancellable`,
`already_closed`, `already_cancelled`).

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
POST /api/v1/ap/vendors { name, email?, phone?, remittance_address?, status? }  (ap:write)
GET  /api/v1/ap/vendors                          (ap:read; ?status=)
GET  /api/v1/ap/vendors/:id                      (ap:read)
PATCH /api/v1/ap/vendors/:id                     (ap:write)
POST /api/v1/ap/bills { vendor_id, bill_date, due_date, tax_cents?, lines[] }  (ap:write; draft)
     each line carries account_code — the account debited at post time
GET  /api/v1/ap/bills                            (ap:read; ?vendor_id= &status=)
GET  /api/v1/ap/bills/:id                        (ap:read; includes lines + open_balance_cents)
PATCH /api/v1/ap/bills/:id { due_date?, tax_cents?, lines? }  (ap:write; draft only)
POST /api/v1/ap/bills/:id/approve                (ap:approve; maker-checker)
     draft -> approved; approver must differ from the creator (self_approval, 403);
     recorded as approved_by/approved_at
POST /api/v1/ap/bills/:id/post                   (ap:post; Idempotency-Key honored)
     approved only (not_approved, 409); Dr each line's account / Cr AP 2000;
     GL posted_on = bill_date
POST /api/v1/ap/bills/:id/void                   (ap:approve; Idempotency-Key honored)
POST /api/v1/inventory/items { sku, name, description?, unit?, allow_negative_stock?, inventory_account_code?, cogs_account_code?, status? }  (inventory:write)
GET  /api/v1/inventory/items                     (inventory:read; ?status=)
GET  /api/v1/inventory/items/:id                (inventory:read)
PATCH /api/v1/inventory/items/:id { name?, description?, unit?, allow_negative_stock?, status? }  (inventory:write; account codes frozen once movements exist)
POST /api/v1/inventory/warehouses { code, name, location? }  (inventory:write)
GET  /api/v1/inventory/warehouses                (inventory:read)
GET  /api/v1/inventory/warehouses/:id            (inventory:read)
PATCH /api/v1/inventory/warehouses/:id { name?, location? }  (inventory:write)
POST /api/v1/inventory/movements/receipt { item_id, warehouse_id, quantity, unit_cost_cents, movement_date?, reason? }  (inventory:post; Idempotency-Key honored)
     updates weighted-average cost; no GL entry in v1 (Phase 6 posts on receiving)
POST /api/v1/inventory/movements/issue { item_id, warehouse_id, quantity, movement_date?, reason? }  (inventory:post; Idempotency-Key honored)
     Dr COGS / Cr Inventory at average cost; blocked below zero unless the item allows it
POST /api/v1/inventory/movements/adjust { item_id, warehouse_id, quantity, unit_cost_cents?, movement_date?, reason }  (inventory:post; Idempotency-Key honored)
     signed quantity; reason required; no GL entry in v1
POST /api/v1/inventory/movements/transfer { item_id, from_warehouse_id, to_warehouse_id, quantity, movement_date?, reason? }  (inventory:post; Idempotency-Key honored)
     two legs, one transaction, at source average; no GL entry
GET  /api/v1/inventory/movements                 (inventory:read; ?item_id= &warehouse_id= &movement_type=)
GET  /api/v1/inventory/levels                    (inventory:read; ?item_id= &warehouse_id=; quantity + avg cost + value)
     reversing entry; refused while payments are applied (void_blocked)
POST /api/v1/ap/bill-payments { vendor_id, method, amount_cents, paid_on, applications?[] }  (ap:post; Idempotency-Key honored)
     Dr AP 2000 / Cr Cash 1000 for the full amount; applications allocate AP, never over-apply
GET  /api/v1/ap/bill-payments                    (ap:read; ?vendor_id=)
GET  /api/v1/ap/bill-payments/:id                (ap:read; includes applications)
POST /api/v1/ap/bill-payments/:id/apply { bill_id, amount_cents }  (ap:post; Idempotency-Key honored)
     applies leftover on-account credit; no new GL entry (cash already recognized)
POST /api/v1/procurement/purchase-orders { vendor_id, order_date, expected_date?, notes?, lines[] }  (procurement:write; draft)
GET  /api/v1/procurement/purchase-orders  (procurement:read; ?vendor_id= &status=)
GET  /api/v1/procurement/purchase-orders/:id  (procurement:read; includes lines + remaining quantities)
PATCH /api/v1/procurement/purchase-orders/:id { vendor_id?, order_date?, expected_date?, notes?, lines? }  (procurement:write; draft only)
POST /api/v1/procurement/purchase-orders/:id/submit  (procurement:write; draft -> open)
POST /api/v1/procurement/purchase-orders/:id/close  (procurement:write; open/partially/fully -> closed)
POST /api/v1/procurement/purchase-orders/:id/cancel  (procurement:write; draft/open/partially -> cancelled)
POST /api/v1/procurement/purchase-orders/:id/receive { warehouse_id, receiving_date?, lines[] }  (procurement:post; Idempotency-Key honored)
     lines carry only po_line_id + quantity; books stock movements + Dr Inventory / Cr AP 2000
     accrual + PO progress in one transaction; zero-cost receiving posts no journal entry
GET  /api/v1/procurement/receivings  (procurement:read; ?po_id= &warehouse_id=)
GET  /api/v1/procurement/receivings/:id  (procurement:read; includes lines + accrued entry)
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

Accounts payable (Phase 4): vendors, bills (+lines, each line carrying the
account debited at post time), bill payments with application logic — all GL
effects via `postJournal()` / `reverseJournal()`, never direct journal writes.
Bills move draft → approved → posted under maker-checker: approval requires
`ap:approve` AND a different user than the creator (`self_approval`, 403),
and the approver is recorded (`approved_by`/`approved_at`) so supervision can
prove the second pair of eyes. Posting an unapproved bill is refused
(`not_approved`); posting debits each line's account and credits AP 2000
(posted_on = bill_date). Payments debit AP / credit Cash for the full amount;
applications allocate AP and can never exceed a bill's open balance (single,
combined, or against unapplied credit), and voiding a bill with payments
applied is refused (`void_blocked`).

Inventory (Phase 5): items, warehouses, append-only `stock_movements`
(trigger-enforced, like posted journals), weighted-average costing per
item×warehouse, and a derived `stock_levels` view that always equals
Σmovements (a recompute check proves the costing ledger agrees).
Receipts update the average (`round((old_qty×old_avg + qty×cost) /
(old_qty+qty))` in integer cents); issues consume at the current average
and post Dr COGS / Cr Inventory via `postJournal()` (posted_on =
movement_date, so closed-period rules apply); adjustments are count
corrections with a required reason (positive re-averages like a receipt,
negative consumes at the average); transfers move stock between
warehouses at the source average with two legs in one transaction.
Negative stock is blocked unless the item allows it
(`negative_stock`, 409), and issuing from a warehouse with no receipt
history is refused (`no_cost_basis`, 400) — there is no COGS to post.
A zero-cost issue posts no journal entry (a 0-cent entry would fail the
balance rule). Receipts, adjustments, and transfers post NO journal
entry in v1 (documented gap, not oversight): receipts are quantity+cost
events (Phase 6 procurement posts Dr Inventory / Cr accrual on
receiving), adjustments are reconciled at period end, and a transfer
keeps value inside Inventory. Item account codes freeze once the item
has movements — they are part of posted history.

Procurement (Phase 6): purchase orders (+lines, each line carrying its
ordered quantity and PO unit cost), receivings, and a status machine —
draft → open → partially_received / fully_received → closed, or
cancelled from draft/open/partially_received. Draft-only edits, like AP
bills; closing a draft is refused (`not_submitted`), cancelling a fully
received PO is refused (`not_cancellable` — the goods are in stock, close
it instead). A receiving takes only `po_line_id` + quantity per line —
no item or price in the input — so the item and the cost always come
from the PO line itself: a nonexistent line is `not_found`, a line from
another PO is `line_mismatch` (400), and any quantity past the remaining
(ordered − received, checked jointly across duplicate lines in one
receiving, backstopped by a DB CHECK) is `over_received` (400). One
transaction books the receiving's stock movements (via inventory
`receiveStock`, so weighted-average costing moves with the goods), the
accrual journal (Dr each item's Inventory account / Cr AP 2000, grouped
by account, posted_on = receiving_date), the append-only receiving rows
(trigger-enforced, like posted journals), the `quantity_received` bumps,
and the PO status step — a closed period, an inactive item, or an
over-receipt rolls all of it back. A zero-cost receiving posts no journal
entry (same rule as zero-cost issues) and leaves `accrued_entry_id`
null. The accrual is a journal entry, NOT a bills row: a bill must still
pass AP maker-checker approval, so receiving never mints an approved bill
on its own — and a vendor invoice bill must not also be posted for the
same goods, since the accrual already credits AP 2000 for them. Matching
a later invoice bill against the accrual (3-way match / GR-IR clearing)
is post-v1; the receiving's `accrued_entry_id` is the hook it will match
against. Receiving requires `procurement:post` (admin in the seeded
matrix); PO lifecycle (create/edit/submit/close/cancel) requires
`procurement:write`.

CRM + supervision (Phase 7): companies, contacts, deals, an immutable
communications log, a principal review queue, supervisory personnel,
and complaints. Companies carry the FINRA 4512 field set (name,
address, tax ID, investment objectives as a free-form profile field,
authorized parties); creating or updating a company with a required
4512 field missing or cleared is a 400 that names the missing fields
(the exact 4512 element list still carries the matrix's [verify] flag
against primary rule text, so validation names fields rather than
claiming a confirmed list). Deals run lead → qualified → proposal →
negotiation → won/lost, and won/lost are terminal (`terminal_stage`,
409). Activities are the comms log and are trigger-append-only: no
UPDATE, no DELETE, ever — review evidence lives in a separate
`comms_reviews` row, never as an edit to the activity. A flagged
activity sits in `GET /api/v1/crm/comms-reviews/queue` until a
principal reviews it; review requires `crm:approve` AND the
`is_principal` flag on the reviewer, and a principal reviewing their
own comm is refused (`self_review`, 403 — no self-supervision,
3110(b)(6)); a reviewed activity leaves the queue, and re-review is
`already_reviewed` (409). AI-agent-origin activities are flagged
automatically with `supervision_status='unreviewed'` (F-S4) — they
enter the queue whether or not the caller flagged them. Supervisory
personnel are users with `is_principal` + title/location, designated
and revoked via `POST/DELETE /api/v1/crm/principals` (`crm:admin`,
audited). Complaints run received → acknowledged → responded, with
timestamps at each step; any other transition is `state_regression`
(409), complaint content is trigger-immutable (only status + its
timestamps move), and an unacknowledged complaint past its ack SLA
(default 7 calendar days, per-complaint override) reports
`acknowledged_overdue` and surfaces under `?overdue_ack=1`. Honesty
note: company tax IDs are stored in clear in v1, like AR/AP contact
details — the H-T4 field-level encryption for tax IDs lands with Phase
8 HR PII work, which is the phase that introduces encrypted columns.

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
src/ap.ts          AP: vendors, bills with maker-checker approval, bill payments (via ledger only)
src/inventory.ts   inventory: items, warehouses, append-only movements,
                   weighted-average costing, COGS posting on issue (via ledger only)
src/procurement.ts procurement: purchase orders, receivings (stock movement +
                   AP accrual, atomically, via inventory + ledger only)
src/crm.ts         CRM + supervision: companies (4512 set), contacts, deals,
                   immutable activities, principal review queue, principals,
                   complaints lifecycle
src/documents.ts   WORM content-addressed document store
src/retention.ts   retention engine: schedules, enforcement, coverage report
src/compliance.ts  tally verify + compliance export (JSON/CSV)
src/seed.ts        roles, RBAC matrix, admin user, retention policies,
                   default chart of accounts, current-year fiscal period
src/cli.ts         `tally serve|seed|migrate|verify`
migrations/        ordered SQL migrations (tracked in schema_migrations)
tests/             bun test suite
```

## Compliance map (Phase 0–7)

H-T1 unique user IDs · H-T3 automatic logoff · H-T4 encryption ·
H-T5 audit controls · H-T6 (ledger) · H-T7 person authentication ·
H-A2 access management · H-A3 password management · H-A5 6y documentation
retention · F-R1 books/records substrate · F-R2 format/media · F-R3
immutability + WORM path · F-R4 automatic verification, export/download ·
F-R7 retention periods · F-R8 customer account information (4512 field
set + completeness validation) · F-R9 written complaints records ·
F-R10 AI-agent comms as retention records (forward-looking: logged with
origin, flagged, retained — no agent exists) · F-S1 principal review of
correspondence, evidenced in writing · F-S2 complaint capture/
acknowledge/respond · F-S3 supervisory personnel documentation, no
self-supervision · F-S4 AI comms supervision hooks · F-S supervision
angle (AP maker-checker approval with recorded approver). 2210 surface:
comms are logged and review-queued; content-standard adjudication and
filing determinations remain procedural/legal, not code. Full citations
in the goal workspace `compliance-matrix.md`.
