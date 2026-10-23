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

## API (Phase 0–1 surface)

Base: `/api/v1`. Errors: `{ error: { code, message } }` with stable machine
codes (`unauthorized`, `session_expired`, `forbidden`, `validation`,
`invalid_credentials`, `account_locked`, `not_found`, `unbalanced`,
`period_closed`, `already_reversed`, `in_use`, `overlap`, `no_open_period`).

```
POST /api/v1/auth/login { email, password } -> { token, expires_at, must_change_password }
POST /api/v1/auth/logout                        (Bearer)
GET  /api/v1/auth/me                            (Bearer)
GET  /api/v1/compliance/audit-log               (Bearer; roles with audit:read)
     ?action= &entity_type= &actor_id= &since= &until= &page= &per_page= &verify=1
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

## Layout

```
src/server.ts      HTTP API (Bun.serve)
src/db.ts          SQLite open + migrations
src/crypto.ts      AES-256-GCM field encryption, sha256 helpers
src/auth.ts        passwords, lockout, sessions
src/rbac.ts        permission evaluation (permissions are seeded data)
src/audit.ts       hash-chained append-only log + chain verification
src/middleware.ts  JSON/errors, auth+RBAC wrappers, audited-mutation helper
src/ledger.ts      ledger core: postJournal/reverseJournal, accounts, periods,
                   trial balance, account ledger, idempotency
src/seed.ts        roles, RBAC matrix, admin user, retention policies,
                   default chart of accounts, current-year fiscal period
src/cli.ts         `tally serve|seed|migrate`
migrations/        ordered SQL migrations (tracked in schema_migrations)
tests/             bun test suite
```

## Compliance map (Phase 0)

H-T1 unique user IDs · H-T3 automatic logoff · H-T4 encryption ·
H-T5 audit controls · H-T7 person authentication · H-A2 access management ·
H-A3 password management. Full citations in the goal workspace
`compliance-matrix.md`.
