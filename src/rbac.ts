// Tally ERP — rbac.ts
// Role-based access control. Default-deny: anything not in role_permissions is
// forbidden. The `auditor` role is read-only everywhere (separation of duties).
// Permissions are data (seeded by seed.ts), this module only evaluates them.

import type { Database } from "bun:sqlite";

export const RESOURCES = [
  "ledger",
  "ar",
  "ap",
  "inventory",
  "procurement",
  "crm",
  "hr",
  "reports",
  "documents",
  "admin",
  "audit",
] as const;

export const ACTIONS = ["read", "write", "post", "approve", "admin"] as const;

export type Resource = (typeof RESOURCES)[number];
export type Action = (typeof ACTIONS)[number];

/** True iff the named role holds (resource, action). Unknown role/resource/action => false. */
export function can(db: Database, roleName: string, resource: string, action: string): boolean {
  const row = db
    .query(
      `SELECT 1 FROM role_permissions rp
       JOIN roles r ON r.id = rp.role_id
       WHERE r.name = ? AND rp.resource = ? AND rp.action = ?`,
    )
    .get(roleName, resource, action);
  return row !== null && row !== undefined;
}

/** All (resource, action) pairs held by a role, for matrix tests and debugging. */
export function permissionsFor(db: Database, roleName: string): Set<string> {
  const rows = db
    .query(
      `SELECT rp.resource, rp.action FROM role_permissions rp
       JOIN roles r ON r.id = rp.role_id WHERE r.name = ?`,
    )
    .all(roleName) as { resource: string; action: string }[];
  return new Set(rows.map((r) => `${r.resource}:${r.action}`));
}

export function roleNames(db: Database): string[] {
  return (db.query("SELECT name FROM roles ORDER BY name").all() as { name: string }[]).map(
    (r) => r.name,
  );
}
