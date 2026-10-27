// Phase 2 tests: WORM document store + retention engine + verify + export.
// Acceptance: delete retained doc -> trigger abort; corrupt byte in scratch
// copy -> verify flags it; export reproduces a record's full history;
// retention report lists per-type coverage.

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { Database } from "bun:sqlite";
import { copyFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  makeTestEnv,
  loginAs,
  authHeaders,
  createTestUser,
  ADMIN_EMAIL,
  ADMIN_PASSWORD,
  type TestEnv,
} from "./helpers";
import { sha256HexSync } from "../src/crypto";
import { verifyDocuments } from "../src/compliance";
import { retentionReport, addYearsIso, docRetentionYears, todayIsoDate } from "../src/retention";
import { checkpoint, openDb } from "../src/db";

let env: TestEnv;
let adminToken: string;
let accountantToken: string;
let salesToken: string;
let auditorToken: string;
let viewerToken: string;
let docId: number;
let docSha: string;
const DOC_BYTES = new TextEncoder().encode("tally-worm-acceptance-plaintext-marker-001");

beforeAll(async () => {
  env = await makeTestEnv();
  adminToken = (await loginAs(env.base, ADMIN_EMAIL, ADMIN_PASSWORD)).token;
  await createTestUser(env.db, "acct@example.local", "Accountant-123456", "accountant");
  await createTestUser(env.db, "sales@example.local", "Salesperson-123456", "sales");
  await createTestUser(env.db, "audit@example.local", "Auditor-12345678", "auditor");
  await createTestUser(env.db, "view@example.local", "Viewer-12345678", "viewer");
  accountantToken = (await loginAs(env.base, "acct@example.local", "Accountant-123456")).token;
  salesToken = (await loginAs(env.base, "sales@example.local", "Salesperson-123456")).token;
  auditorToken = (await loginAs(env.base, "audit@example.local", "Auditor-12345678")).token;
  viewerToken = (await loginAs(env.base, "view@example.local", "Viewer-12345678")).token;
});
afterAll(() => env.cleanup());

async function upload(
  token: string,
  body: Record<string, unknown>,
): Promise<{ status: number; json: any }> {
  const res = await fetch(`${env.base}/api/v1/documents`, {
    method: "POST",
    headers: { ...authHeaders(token), "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: res.status, json: await res.json().catch(() => ({})) };
}

const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64");

describe("document upload + content addressing", () => {
  test("JSON base64 upload -> 201 with content address + retain_until", async () => {
    const { status, json } = await upload(accountantToken, {
      title: "Q3 invoice pack",
      doc_type: "invoice",
      mime_type: "application/pdf",
      content_base64: b64(DOC_BYTES),
    });
    expect(status).toBe(201);
    const d = json.data;
    docId = d.id;
    docSha = d.content_sha256;
    expect(d.content_sha256).toBe(sha256HexSync(DOC_BYTES));
    expect(d.size_bytes).toBe(DOC_BYTES.length);
    expect(d.mime_type).toBe("application/pdf");
    expect(d.retain_until).toBe(addYearsIso(todayIsoDate(), 6));
    expect(typeof d.uuid).toBe("string");
  });

  test("stored bytes are ciphertext, not plaintext", () => {
    const row = env.db.query("SELECT content FROM documents WHERE id = ?").get(docId) as {
      content: Uint8Array;
    };
    const raw = Buffer.from(row.content).toString("latin1");
    expect(raw).not.toContain("tally-worm-acceptance-plaintext-marker-001");
  });

  test("multipart upload works", async () => {
    const form = new FormData();
    form.set("title", "scanned contract");
    form.set("doc_type", "contract");
    form.set("file", new File([new TextEncoder().encode("contract-bytes")], "c.pdf", {
      type: "application/pdf",
    }));
    const res = await fetch(`${env.base}/api/v1/documents`, {
      method: "POST",
      headers: authHeaders(accountantToken),
      body: form,
    });
    expect(res.status).toBe(201);
    const json = await res.json();
    expect(json.data.doc_type).toBe("contract");
    expect(json.data.title).toBe("scanned contract");
  });

  test("identical bytes dedupe to one row", async () => {
    const before = (
      env.db.query("SELECT COUNT(*) AS n FROM documents").get() as { n: number }
    ).n;
    const { status, json } = await upload(accountantToken, {
      title: "duplicate upload",
      doc_type: "invoice",
      content_base64: b64(DOC_BYTES),
    });
    expect(status).toBe(200);
    expect(json.data.deduped).toBe(true);
    expect(json.data.id).toBe(docId);
    expect((env.db.query("SELECT COUNT(*) AS n FROM documents").get() as { n: number }).n).toBe(
      before,
    );
  });

  test("empty content rejected", async () => {
    const { status, json } = await upload(accountantToken, {
      title: "empty",
      doc_type: "other",
      content_base64: b64(new Uint8Array(0)),
    });
    expect(status).toBe(400);
    expect(json.error.code).toBe("validation");
  });

  test("list + doc_type filter (metadata only, no bytes)", async () => {
    const res = await fetch(`${env.base}/api/v1/documents?doc_type=invoice`, {
      headers: authHeaders(accountantToken),
    });
    const json = await res.json();
    expect(res.status).toBe(200);
    expect(json.data.every((d: any) => d.doc_type === "invoice")).toBe(true);
    expect(json.data[0].content).toBeUndefined();
  });
});

describe("download", () => {
  test("download returns identical bytes + sha256 etag", async () => {
    const res = await fetch(`${env.base}/api/v1/documents/${docId}/content`, {
      headers: authHeaders(auditorToken),
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("etag")).toBe(`"${docSha}"`);
    const bytes = new Uint8Array(await res.arrayBuffer());
    expect(Buffer.from(bytes).toString()).toBe(Buffer.from(DOC_BYTES).toString());
  });

  test("unknown document -> 404", async () => {
    const res = await fetch(`${env.base}/api/v1/documents/999999`, {
      headers: authHeaders(accountantToken),
    });
    expect(res.status).toBe(404);
  });
});

describe("WORM enforcement", () => {
  test("DELETE retained document -> 405 retained (doc untouched)", async () => {
    const res = await fetch(`${env.base}/api/v1/documents/${docId}`, {
      method: "DELETE",
      headers: authHeaders(accountantToken),
    });
    const json = await res.json();
    expect(res.status).toBe(405);
    expect(json.error.code).toBe("retained");
    const get = await fetch(`${env.base}/api/v1/documents/${docId}`, {
      headers: authHeaders(accountantToken),
    });
    expect(get.status).toBe(200);
  });

  test("denied delete is audited", () => {
    const row = env.db
      .query(
        "SELECT id FROM audit_log WHERE action = 'document.delete_denied' AND entity_id = ?",
      )
      .get(String(docId));
    expect(row).not.toBeNull();
  });

  test("raw SQL DELETE of retained doc aborts at the trigger", () => {
    expect(() => env.db.exec(`DELETE FROM documents WHERE id = ${docId}`)).toThrow(
      /WORM while retained/,
    );
  });

  test("raw SQL UPDATE aborts at the trigger", () => {
    expect(() =>
      env.db.exec(`UPDATE documents SET title = 'evil' WHERE id = ${docId}`),
    ).toThrow(/WORM: UPDATE rejected/);
  });

  test("expired document can be deleted (audited)", async () => {
    const day = new Date(Date.now() - 86400000).toISOString().slice(0, 10); // yesterday
    const info = env.db
      .query(
        `INSERT INTO documents
           (uuid, title, doc_type, mime_type, size_bytes, content_sha256,
            content, retain_until, uploaded_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        "expired-uuid-0001",
        "old memo",
        "other",
        "text/plain",
        4,
        sha256HexSync(new TextEncoder().encode("old!")),
        crypto.getRandomValues(new Uint8Array(32)),
        day,
        null,
        new Date().toISOString(),
      );
    const id = Number(info.lastInsertRowid);
    const res = await fetch(`${env.base}/api/v1/documents/${id}`, {
      method: "DELETE",
      headers: authHeaders(adminToken),
    });
    expect(res.status).toBe(200);
    const get = await fetch(`${env.base}/api/v1/documents/${id}`, {
      headers: authHeaders(adminToken),
    });
    expect(get.status).toBe(404);
    const audit = env.db
      .query("SELECT id FROM audit_log WHERE action = 'document.delete' AND entity_id = ?")
      .get(String(id));
    expect(audit).not.toBeNull();
  });
});

describe("retention engine", () => {
  test("per-type override + fallback + floor", () => {
    expect(docRetentionYears(env.db, "invoice")).toBe(6);
    expect(docRetentionYears(env.db, "other")).toBe(3);
    expect(docRetentionYears(env.db, "unclassified-type")).toBe(6); // 'document' policy fallback
  });

  test("addYearsIso clamps Feb 29", () => {
    expect(addYearsIso("2024-02-29", 1)).toBe("2025-02-28");
    expect(addYearsIso("2026-10-24", 6)).toBe("2032-10-24");
  });

  test("retention report lists per-type coverage", async () => {
    const res = await fetch(`${env.base}/api/v1/compliance/retention-report`, {
      headers: authHeaders(adminToken),
    });
    expect(res.status).toBe(200);
    const json = await res.json();
    const byType = Object.fromEntries(json.data.policies.map((p: any) => [p.entity_type, p]));
    expect(byType.journal.years).toBe(6);
    expect(byType.journal.status).toBe("covered");
    expect(byType.document.years).toBe(6);
    expect(byType.audit.years).toBe(6);
    expect(byType.comms.status).toBe("covered"); // phase 7: activities table
    expect(byType.crm.status).toBe("covered"); // phase 7: companies table
    expect(byType.hr.status).toBe("covered"); // phase 8: employees table
    expect(byType.report.status).toBe("covered"); // phase 9: report_runs table
    const docTypes = Object.fromEntries(
      json.data.document_types.map((t: any) => [t.doc_type, t.years]),
    );
    expect(docTypes.invoice).toBe(6);
    expect(docTypes.other).toBe(3);
    expect(json.data.policies.every((p: any) => p.years >= 3)).toBe(true);
  });

  test("F-R7 schedule: policy table matches (journal/audit 6y, floor 3y)", () => {
    const rows = env.db.query("SELECT entity_type, years FROM retention_policies").all() as {
      entity_type: string;
      years: number;
    }[];
    const byType = Object.fromEntries(rows.map((r) => [r.entity_type, r.years]));
    expect(byType.journal).toBe(6);
    expect(byType.audit).toBe(6);
    for (const r of rows) expect(r.years).toBeGreaterThanOrEqual(3);
    const docRows = env.db.query("SELECT years FROM doc_retention_years").all() as {
      years: number;
    }[];
    for (const r of docRows) expect(r.years).toBeGreaterThanOrEqual(3);
  });
});

describe("verify", () => {
  test("verifyDocuments green on clean db", async () => {
    const check = await verifyDocuments(env.db);
    expect(check.checked).toBeGreaterThan(0);
    expect(check.corrupt).toBe(0);
  });

  test("corrupt byte in scratch copy -> verify flags it", async () => {
    checkpoint(env.db);
    const dir = mkdtempSync(join(tmpdir(), "tally-tamper-"));
    const copyPath = join(dir, "copy.db");
    copyFileSync(env.dbPath, copyPath);
    const copyDb: Database = openDb(copyPath);
    try {
      copyDb.exec("DROP TRIGGER documents_no_update"); // simulate file-level tamper
      const row = copyDb.query("SELECT id, content FROM documents LIMIT 1").get() as {
        id: number;
        content: Uint8Array;
      };
      const bytes = new Uint8Array(row.content);
      bytes[20] ^= 0xff;
      copyDb.query("UPDATE documents SET content = ? WHERE id = ?").run(bytes, row.id);
      const check = await verifyDocuments(copyDb);
      expect(check.corrupt_ids).toContain(row.id);
    } finally {
      copyDb.close();
    }
  });

  test("HTTP verify endpoint mirrors the CLI check", async () => {
    const res = await fetch(`${env.base}/api/v1/compliance/verify`, {
      headers: authHeaders(auditorToken),
    });
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.data.ok).toBe(true);
    expect(json.data.audit_chain.ok).toBe(true);
    expect(json.data.documents.corrupt).toBe(0);
  });

  test("tally verify CLI: exit 0 clean, exit 1 tampered", async () => {
    const cliPath = join(import.meta.dir, "..", "src", "cli.ts");
    async function runVerify(dbPath: string): Promise<{ code: number; out: string }> {
      const proc = Bun.spawn(["bun", cliPath, "verify"], {
        env: { ...process.env, TALLY_DB: dbPath },
        stdout: "pipe",
        stderr: "pipe",
      });
      const out = await new Response(proc.stdout).text();
      const code = await proc.exited;
      return { code, out };
    }
    const clean = await runVerify(env.dbPath);
    expect(clean.code).toBe(0);
    expect(clean.out).toContain("OK");

    checkpoint(env.db);
    const dir = mkdtempSync(join(tmpdir(), "tally-tamper-cli-"));
    const copyPath = join(dir, "copy.db");
    copyFileSync(env.dbPath, copyPath);
    const copyDb = openDb(copyPath);
    try {
      copyDb.exec("DROP TRIGGER documents_no_update");
      const row = copyDb.query("SELECT id, content FROM documents LIMIT 1").get() as {
        id: number;
        content: Uint8Array;
      };
      const bytes = new Uint8Array(row.content);
      bytes[20] ^= 0xff;
      copyDb.query("UPDATE documents SET content = ? WHERE id = ?").run(bytes, row.id);
    } finally {
      copyDb.close();
    }
    const tampered = await runVerify(copyPath);
    expect(tampered.code).toBe(1);
    expect(tampered.out).toContain("FAIL");
  });
});

describe("compliance export", () => {
  let entryId: number;

  test("setup: post a journal entry to export", async () => {
    const accRes = await fetch(`${env.base}/api/v1/ledger/accounts`, {
      headers: authHeaders(adminToken),
    });
    const accounts = (await accRes.json()).data as { id: number; code: string }[];
    const cash = accounts.find((a) => a.code === "1000")!;
    const revenue = accounts.find((a) => a.code === "4000")!;
    const res = await fetch(`${env.base}/api/v1/ledger/journal`, {
      method: "POST",
      headers: { ...authHeaders(adminToken), "content-type": "application/json" },
      body: JSON.stringify({
        memo: "export acceptance entry",
        posted_on: todayIsoDate(),
        lines: [
          { account_id: cash.id, debit_cents: 500 },
          { account_id: revenue.id, credit_cents: 500 },
        ],
      }),
    });
    expect(res.status).toBe(201);
    entryId = (await res.json()).data.id;
  });

  test("journal entry export reproduces record + full history (JSON)", async () => {
    const res = await fetch(
      `${env.base}/api/v1/compliance/export?entity_type=journal_entries&entity_id=${entryId}&format=json`,
      { headers: authHeaders(auditorToken) },
    );
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.data.record.memo).toBe("export acceptance entry");
    expect(json.data.record.lines).toHaveLength(2);
    expect(json.data.history.some((h: any) => h.action === "journal.post")).toBe(true);
  });

  test("journal entry CSV export: one row per line", async () => {
    const res = await fetch(
      `${env.base}/api/v1/compliance/export?entity_type=journal_entries&entity_id=${entryId}&format=csv`,
      { headers: authHeaders(auditorToken) },
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/csv");
    const text = await res.text();
    const lines = text.trim().split("\r\n");
    expect(lines[0]).toContain("entry_no");
    expect(lines[0]).toContain("debit_cents");
    expect(lines.length).toBe(3); // header + 2 lines
  });

  test("document export bundles metadata + upload history", async () => {
    const res = await fetch(
      `${env.base}/api/v1/compliance/export?entity_type=documents&entity_id=${docId}&format=json`,
      { headers: authHeaders(auditorToken) },
    );
    const json = await res.json();
    expect(res.status).toBe(200);
    expect(json.data.record.content_sha256).toBe(docSha);
    expect(json.data.record.content).toBeUndefined(); // bytes never in export
    expect(json.data.history.some((h: any) => h.action === "document.upload")).toBe(true);
  });

  test("audit_log CSV export", async () => {
    const res = await fetch(
      `${env.base}/api/v1/compliance/export?entity_type=audit_log&format=csv`,
      { headers: authHeaders(auditorToken) },
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/csv");
    const text = await res.text();
    expect(text.split("\r\n")[0]).toBe(
      "seq,ts,actor_id,action,entity_type,entity_id,before_json,after_json,prev_hash,hash",
    );
  });

  test("unknown entity_type -> 400", async () => {
    const res = await fetch(`${env.base}/api/v1/compliance/export?entity_type=teleport`, {
      headers: authHeaders(auditorToken),
    });
    expect(res.status).toBe(400);
  });
});

describe("documents RBAC", () => {
  test("sales (read-only) cannot upload -> 403", async () => {
    const { status, json } = await upload(salesToken, {
      title: "nope",
      doc_type: "other",
      content_base64: b64(new TextEncoder().encode("x")),
    });
    expect(status).toBe(403);
    expect(json.error.code).toBe("forbidden");
  });

  test("sales can read/download", async () => {
    const res = await fetch(`${env.base}/api/v1/documents/${docId}/content`, {
      headers: authHeaders(salesToken),
    });
    expect(res.status).toBe(200);
  });

  test("unauthenticated upload -> 401", async () => {
    const res = await fetch(`${env.base}/api/v1/documents`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ title: "x", doc_type: "other", content_base64: b64(new TextEncoder().encode("x")) }),
    });
    expect(res.status).toBe(401);
  });

  test("auditor can export; viewer (no audit:read) cannot", async () => {
    const a = await fetch(`${env.base}/api/v1/compliance/export?entity_type=audit_log`, {
      headers: authHeaders(auditorToken),
    });
    expect(a.status).toBe(200);
    const v = await fetch(`${env.base}/api/v1/compliance/export?entity_type=audit_log`, {
      headers: authHeaders(viewerToken),
    });
    expect(v.status).toBe(403);
  });
});
