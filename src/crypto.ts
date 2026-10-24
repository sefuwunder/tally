// Tally ERP — crypto.ts
// AES-256-GCM field encryption via WebCrypto (zero npm deps) + sha256 helpers.
//
// Data key comes from TALLY_DATA_KEY only: 32 raw bytes encoded as 64 hex chars
// or base64. The key is NEVER written to the repo, logs, or the audit log.
// Cached in memory after first import; call resetKeyCache() in tests after
// rotating the env var.

import { createHash } from "node:crypto";

const te = new TextEncoder();
const td = new TextDecoder();

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function parseDataKey(): Uint8Array {
  const raw = process.env.TALLY_DATA_KEY;
  if (!raw) throw new Error("TALLY_DATA_KEY is not set");
  const s = raw.trim();
  if (/^[0-9a-fA-F]{64}$/.test(s)) return hexToBytes(s);
  try {
    const b = Buffer.from(s, "base64");
    if (b.length === 32) return new Uint8Array(b);
  } catch { /* fall through */ }
  throw new Error("TALLY_DATA_KEY must be 32 bytes as 64-char hex or base64");
}

let keyPromise: Promise<CryptoKey> | null = null;

export function resetKeyCache(): void {
  keyPromise = null;
}

export async function dataKey(): Promise<CryptoKey> {
  if (!keyPromise) {
    keyPromise = crypto.subtle.importKey("raw", parseDataKey(), "AES-GCM", false, [
      "encrypt",
      "decrypt",
    ]);
  }
  return keyPromise;
}

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function unb64(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64"));
}

/**
 * Encrypt a UTF-8 string field. Returns "ivB64.ctB64" (fresh random 96-bit IV
 * per value). Never log or store the plaintext alongside the blob.
 */
export async function encryptField(plaintext: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    await dataKey(),
    te.encode(plaintext),
  );
  return `${b64(iv)}.${b64(new Uint8Array(ct))}`;
}

/**
 * Decrypt a blob produced by encryptField. Throws (OperationError) when the
 * blob was not produced with the current TALLY_DATA_KEY — authentication
 * failure is by design, never return partial plaintext.
 */
export async function decryptField(blob: string): Promise<string> {
  const [ivB64, ctB64] = blob.split(".");
  if (!ivB64 || !ctB64) throw new Error("malformed encrypted field");
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: unb64(ivB64) as BufferSource },
    await dataKey(),
    unb64(ctB64),
  );
  return td.decode(pt);
}

/**
 * Encrypt raw bytes with AES-256-GCM. Returns iv(12) || ciphertext.
 * Used by the WORM document store (ciphertext at rest, H-T4). Tampering is
 * detected on decrypt: GCM authentication fails and the byte is flagged by
 * `tally verify` (F-R4).
 */
export async function encryptBytes(plaintext: Uint8Array): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    await dataKey(),
    plaintext as BufferSource,
  );
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ct), 12);
  return out;
}

/**
 * Decrypt iv(12) || ciphertext produced by encryptBytes. Throws
 * (OperationError) on authentication failure — never return partial plaintext.
 */
export async function decryptBytes(blob: Uint8Array): Promise<Uint8Array> {
  if (blob.length < 13) throw new Error("malformed encrypted bytes");
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: blob.slice(0, 12) as BufferSource },
    await dataKey(),
    blob.slice(12) as BufferSource,
  );
  return new Uint8Array(pt);
}

/** Async WebCrypto sha256 (hex). */
export async function sha256Hex(input: string | Uint8Array): Promise<string> {
  const data = typeof input === "string" ? te.encode(input) : input;
  const digest = await crypto.subtle.digest("SHA-256", data as BufferSource);
  return Buffer.from(digest).toString("hex");
}

/**
 * Synchronous sha256 (hex) via node:crypto — zero deps, built in.
 * Used by the audit hash chain so appends stay fully synchronous inside
 * SQLite transactions (no await between seq assignment and INSERT).
 */
export function sha256HexSync(input: string | Uint8Array): string {
  const h = createHash("sha256");
  h.update(typeof input === "string" ? input : Buffer.from(input));
  return h.digest("hex");
}
