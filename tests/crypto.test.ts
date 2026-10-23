// Field encryption (H-T4): AES-256-GCM round-trip, ciphertext at rest,
// wrong-key authentication failure, key format validation.

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { makeTestEnv, type TestEnv, TEST_DATA_KEY } from "./helpers";
import { encryptField, decryptField, sha256Hex, sha256HexSync, resetKeyCache } from "../src/crypto";

let env: TestEnv;
beforeAll(async () => {
  env = await makeTestEnv();
  process.env.TALLY_DATA_KEY = TEST_DATA_KEY;
  resetKeyCache();
});
afterAll(() => env.cleanup());

describe("encrypt/decrypt", () => {
  test("round-trips plaintext", async () => {
    const blob = await encryptField("123-45-6789");
    expect(await decryptField(blob)).toBe("123-45-6789");
  });

  test("round-trips unicode and empty string", async () => {
    for (const s of ["", "héllo wörld ✓", "a".repeat(5000)]) {
      expect(await decryptField(await encryptField(s))).toBe(s);
    }
  });

  test("same plaintext encrypts to different ciphertext (random IV)", async () => {
    const a = await encryptField("same");
    const b = await encryptField("same");
    expect(a).not.toBe(b);
    expect(await decryptField(a)).toBe("same");
    expect(await decryptField(b)).toBe("same");
  });

  test("stored value is ciphertext: raw DB dump never contains plaintext", async () => {
    const secret = "SSN-998-11-2233-PLAINTEXT-MARKER";
    const blob = await encryptField(secret);
    env.db.exec("CREATE TABLE IF NOT EXISTS secret_notes (id INTEGER PRIMARY KEY, ssn_enc TEXT)");
    env.db.query("INSERT INTO secret_notes (ssn_enc) VALUES (?)").run(blob);
    const raw = (env.db.query("SELECT ssn_enc FROM secret_notes ORDER BY id DESC LIMIT 1").get() as {
      ssn_enc: string;
    }).ssn_enc;
    expect(raw).not.toContain(secret);
    expect(raw).not.toContain("998-11-2233");
    expect(await decryptField(raw)).toBe(secret); // but the app can read it back
  });

  test("wrong key -> authentication failure, no partial plaintext", async () => {
    const blob = await encryptField("top secret");
    process.env.TALLY_DATA_KEY =
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    resetKeyCache();
    let threw = false;
    try {
      await decryptField(blob);
    } catch {
      threw = true;
    }
    expect(threw).toBe(true);
    process.env.TALLY_DATA_KEY = TEST_DATA_KEY;
    resetKeyCache();
    expect(await decryptField(blob)).toBe("top secret"); // key restored
  });

  test("malformed blob rejected", async () => {
    await expect(decryptField("not-a-blob")).rejects.toThrow();
    await expect(decryptField("a.b.c")).rejects.toThrow();
  });

  test("missing TALLY_DATA_KEY -> clear error", async () => {
    const saved = process.env.TALLY_DATA_KEY;
    delete process.env.TALLY_DATA_KEY;
    resetKeyCache();
    await expect(encryptField("x")).rejects.toThrow(/TALLY_DATA_KEY is not set/);
    process.env.TALLY_DATA_KEY = saved;
    resetKeyCache();
  });

  test("bad key format -> clear error", async () => {
    const saved = process.env.TALLY_DATA_KEY;
    process.env.TALLY_DATA_KEY = "too-short";
    resetKeyCache();
    await expect(encryptField("x")).rejects.toThrow(/32 bytes/);
    process.env.TALLY_DATA_KEY = saved;
    resetKeyCache();
  });
});

describe("sha256 helpers", () => {
  test("sync and async agree, known vector", async () => {
    expect(sha256HexSync("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    expect(await sha256Hex("abc")).toBe(sha256HexSync("abc"));
  });
});
