// Tally ERP — seed.ts
// Idempotent seed: roles, the role_permissions matrix (H-A2, least privilege),
// the initial admin user (must-change password), and retention policies.
// ALL seed data is synthetic — never seed real identifiers (no PHI/PII).

import type { Database } from "bun:sqlite";
import { hashPassword } from "./auth";
import { appendAudit } from "./audit";
import { nowIso } from "./db";

/**
 * The RBAC matrix. Default-deny: anything absent here is forbidden.
 * auditor is read-only everywhere (separation of duties — FINRA 3110 angle).
 */
export const PERMISSION_MATRIX: Record<string, Record<string, string[]>> = {
  admin: {
    ledger: ["read", "write", "post", "approve", "admin"],
    ar: ["read", "write", "post", "approve", "admin"],
    ap: ["read", "write", "post", "approve", "admin"],
    inventory: ["read", "write", "post", "approve", "admin"],
    procurement: ["read", "write", "post", "approve", "admin"],
    crm: ["read", "write", "post", "approve", "admin"],
    hr: ["read", "write", "post", "approve", "admin"],
    reports: ["read", "write", "post", "approve", "admin"],
    documents: ["read", "write", "post", "approve", "admin"],
    admin: ["read", "write", "post", "approve", "admin"],
    audit: ["read", "write", "post", "approve", "admin"],
  },
  accountant: {
    ledger: ["read", "write", "post", "approve"],
    ar: ["read", "write", "post", "approve"],
    ap: ["read", "write", "post", "approve"],
    inventory: ["read", "write", "post"],
    procurement: ["read", "write"],
    // crm:approve is the principal-review permission (Phase 7); the
    // is_principal flag on the user is the second gate — approve alone
    // does not make a reviewer a principal (F-S3).
    crm: ["read", "write", "approve"],
    hr: ["read"],
    reports: ["read", "write"],
    documents: ["read", "write"],
    audit: ["read"],
  },
  ap_clerk: {
    ledger: ["read"],
    ap: ["read", "write", "post"],
    inventory: ["read"],
    procurement: ["read"],
    crm: ["read"],
    reports: ["read"],
    documents: ["read"],
  },
  sales: {
    ar: ["read"],
    inventory: ["read"],
    crm: ["read", "write"],
    reports: ["read"],
    documents: ["read"],
  },
  hr: {
    hr: ["read", "write", "post", "approve"],
    reports: ["read"],
    documents: ["read", "write"],
  },
  auditor: {
    ledger: ["read"],
    ar: ["read"],
    ap: ["read"],
    inventory: ["read"],
    procurement: ["read"],
    crm: ["read"],
    hr: ["read"],
    reports: ["read"],
    documents: ["read"],
    admin: ["read"],
    audit: ["read"],
  },
  viewer: {
    ledger: ["read"],
    ar: ["read"],
    ap: ["read"],
    inventory: ["read"],
    procurement: ["read"],
    crm: ["read"],
    reports: ["read"],
    documents: ["read"],
  },
};

/** Default chart of accounts seeded for a new company. Codes are the dedupe key. */
export const DEFAULT_ACCOUNTS: { code: string; name: string; type: string }[] = [
  { code: "1000", name: "Cash", type: "asset" },
  { code: "1010", name: "Petty Cash", type: "asset" },
  { code: "1100", name: "Accounts Receivable", type: "asset" },
  { code: "1200", name: "Inventory", type: "asset" },
  { code: "1500", name: "Equipment", type: "asset" },
  { code: "2000", name: "Accounts Payable", type: "liability" },
  { code: "2100", name: "Sales Tax Payable", type: "liability" },
  { code: "2200", name: "Payroll Liabilities", type: "liability" },
  { code: "3000", name: "Owner Equity", type: "equity" },
  { code: "3100", name: "Retained Earnings", type: "equity" },
  { code: "4000", name: "Sales Revenue", type: "revenue" },
  { code: "4100", name: "Service Revenue", type: "revenue" },
  { code: "5000", name: "Cost of Goods Sold", type: "expense" },
  { code: "6000", name: "Wages Expense", type: "expense" },
  { code: "6100", name: "Rent Expense", type: "expense" },
  { code: "6200", name: "Office Supplies", type: "expense" },
  { code: "6300", name: "Professional Services", type: "expense" },
];

export const ADMIN_EMAIL = "admin@example.local";
export const ADMIN_PASSWORD = "Changeme-123456"; // must-change on first login

/** retention_policies seed (years). H-A5: HIPAA docs 6y; F-R7: 17a-4 periods. */
export const RETENTION_SEED: Record<string, number> = {
  journal: 6,
  comms: 6,
  crm: 6,
  hr: 6,
  audit: 6,
  document: 6,
};

/**
 * Per-document-type retention (years), F-R7. Financial/legal records take the
 * conservative 6y; everything else honors the >= 3y floor (CHECK in 003).
 */
export const DOC_RETENTION_SEED: Record<string, number> = {
  invoice: 6,
  statement: 6,
  contract: 6,
  policy: 6,
  correspondence: 6,
  payroll: 6,
  other: 3,
};

export async function seed(db: Database): Promise<void> {
  const pwHash = await hashPassword(ADMIN_PASSWORD);
  const now = nowIso();

  db.transaction(() => {
    for (const roleName of Object.keys(PERMISSION_MATRIX)) {
      db.query("INSERT OR IGNORE INTO roles (name) VALUES (?)").run(roleName);
    }
    const roleId = (name: string) =>
      (db.query("SELECT id FROM roles WHERE name = ?").get(name) as { id: number }).id;
    for (const [roleName, resources] of Object.entries(PERMISSION_MATRIX)) {
      const rid = roleId(roleName);
      for (const [resource, actions] of Object.entries(resources)) {
        for (const action of actions) {
          db.query(
            "INSERT OR IGNORE INTO role_permissions (role_id, resource, action) VALUES (?, ?, ?)",
          ).run(rid, resource, action);
        }
      }
      appendAudit(db, {
        actor_id: null,
        action: "system.seed",
        entity_type: "role",
        entity_id: roleName,
        after: { resources: Object.keys(resources).length },
      });
    }

    const adminRoleId = roleId("admin");
    const existing = db.query("SELECT id FROM users WHERE email = ?").get(ADMIN_EMAIL);
    if (!existing) {
      // Seeded admin is a designated principal (F-S3) so the review
      // queue is operable out of the box; self-review is still blocked.
      db.query(
        `INSERT INTO users
           (email, pw_hash, role_id, must_change_pw, is_principal, title, created_at, updated_at)
         VALUES (?, ?, ?, 1, 1, 'Administrator', ?, ?)`,
      ).run(ADMIN_EMAIL, pwHash, adminRoleId, now, now);
      appendAudit(db, {
        actor_id: null,
        action: "system.seed",
        entity_type: "user",
        entity_id: ADMIN_EMAIL,
        after: { role: "admin", must_change_pw: true },
      });
    }

    for (const [entityType, years] of Object.entries(RETENTION_SEED)) {
      db.query("INSERT OR IGNORE INTO retention_policies (entity_type, years) VALUES (?, ?)").run(
        entityType,
        years,
      );
    }
    for (const [docType, years] of Object.entries(DOC_RETENTION_SEED)) {
      db.query("INSERT OR IGNORE INTO doc_retention_years (doc_type, years) VALUES (?, ?)").run(
        docType,
        years,
      );
    }
    appendAudit(db, {
      actor_id: null,
      action: "system.seed",
      entity_type: "retention_policy",
      entity_id: "defaults",
      after: { policies: RETENTION_SEED, document_types: DOC_RETENTION_SEED },
    });

    // Phase 1: default chart of accounts + the current calendar-year period (open).
    for (const a of DEFAULT_ACCOUNTS) {
      db.query(
        "INSERT OR IGNORE INTO accounts (code, name, type, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
      ).run(a.code, a.name, a.type, now, now);
    }
    const year = new Date().getUTCFullYear();
    db.query(
      "INSERT OR IGNORE INTO fiscal_periods (name, starts_on, ends_on, created_at) VALUES (?, ?, ?, ?)",
    ).run(`FY ${year}`, `${year}-01-01`, `${year}-12-31`, now);
    appendAudit(db, {
      actor_id: null,
      action: "system.seed",
      entity_type: "ledger_defaults",
      entity_id: `FY ${year}`,
      after: { accounts: DEFAULT_ACCOUNTS.length, period: `FY ${year}` },
    });
  })();
}
