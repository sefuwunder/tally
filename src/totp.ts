// Tally ERP — totp.ts
// Zero-dep RFC 6238 TOTP (H-T2, H-T7 person authentication / MFA).
// HMAC-SHA1, 30s step, 6 digits, ±1 step verification window.
// No npm deps: node:crypto createHmac + timingSafeEqual only.
//
// Secrets are 160-bit (20 bytes) base32 (RFC 4648, no padding in the
// otpauth URI). Verification is constant-time over equal-length codes.
// TOTP secrets and codes are NEVER written to the audit log — callers
// record only flags (enabled/disabled) and hash prefixes.

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export const TOTP_STEP_SECONDS = 30;
export const TOTP_DIGITS = 6;
export const TOTP_WINDOW_STEPS = 1;

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** Generate a fresh 160-bit secret, base32-encoded (32 chars, no padding). */
export function generateTotpSecret(): string {
  return base32Encode(randomBytes(20));
}

/** RFC 4648 base32 encode (uppercase, padding stripped by caller choice). */
export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32_ALPHABET[(value >> bits) & 31];
    }
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return out;
}

/** RFC 4648 base32 decode. Accepts lowercase and trailing padding; rejects unknown chars. */
export function base32Decode(input: string): Uint8Array {
  const s = input.trim().replace(/=+$/, "").toUpperCase();
  if (!s) throw new Error("empty base32 secret");
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const ch of s) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error(`invalid base32 character: ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >> bits) & 0xff);
    }
  }
  return new Uint8Array(bytes);
}

function hotp(secret: string, counter: bigint): string {
  const key = base32Decode(secret);
  const msg = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    msg[i] = Number(c & 0xffn);
    c >>= 8n;
  }
  const hmac = createHmac("sha1", Buffer.from(key)).update(Buffer.from(msg)).digest();
  // Dynamic truncation (RFC 4226 §5.3).
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(code % 10 ** TOTP_DIGITS).padStart(TOTP_DIGITS, "0");
}

/** TOTP code for a given moment (default now), 6 digits, 30s step. */
export function totpCode(secret: string, atMs: number = Date.now()): string {
  const counter = BigInt(Math.floor(atMs / 1000 / TOTP_STEP_SECONDS));
  return hotp(secret, counter);
}

/**
 * Verify a 6-digit code within ±1 step of `atMs` (default now).
 * Constant-time compare; malformed codes (wrong length, non-digits)
 * are rejected without timing leakage into the secret.
 */
export function verifyTotp(
  secret: string,
  code: string,
  opts: { atMs?: number; windowSteps?: number } = {},
): boolean {
  if (typeof code !== "string" || !/^\d{6}$/.test(code)) return false;
  const atMs = opts.atMs ?? Date.now();
  const window = opts.windowSteps ?? TOTP_WINDOW_STEPS;
  const counter = BigInt(Math.floor(atMs / 1000 / TOTP_STEP_SECONDS));
  const codeBuf = Buffer.from(code);
  for (let step = -window; step <= window; step++) {
    let expected: string;
    try {
      expected = hotp(secret, counter + BigInt(step));
    } catch {
      return false;
    }
    if (timingSafeEqual(codeBuf, Buffer.from(expected))) return true;
  }
  return false;
}

/** otpauth:// URI for authenticator-app enrollment (account = user email). */
export function otpauthUri(secret: string, account: string, issuer = "Tally"): string {
  const label = `${issuer}:${account}`;
  return (
    `otpauth://totp/${encodeURIComponent(label)}` +
    `?secret=${secret}&issuer=${encodeURIComponent(issuer)}` +
    `&digits=${TOTP_DIGITS}&period=${TOTP_STEP_SECONDS}&algorithm=SHA1`
  );
}
