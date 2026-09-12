/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Colophon
 * This file is the MIT-licensed subset of LicenseSmith.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Point, signAsync, verifyAsync } from "@noble/ed25519";
import { verifyLicense } from "./licensesmith";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(resolve(here, "../../spec/testvectors.json"), "utf8")) as {
  keypair: { seedB64Url: string; publicKeyB64Url: string };
  now: number;
  vectors: Array<{
    id: string;
    license: string;
    options: { productId?: string; now?: number; revokedIds?: string[] };
    expect: { ok: true; payload: unknown } | { ok: false; reason: string };
  }>;
};
const PK = vectors.keypair.publicKeyB64Url;
const SEED = new Uint8Array(Buffer.from(vectors.keypair.seedB64Url, "base64url"));

/** Sign an arbitrary payload string with the TEST-ONLY seed, exactly like the issuer does. */
async function signRaw(payloadJson: string, prefix = "LS1"): Promise<string> {
  const pb = Buffer.from(payloadJson, "utf8").toString("base64url");
  const sig = await signAsync(new TextEncoder().encode(`${prefix}.${pb}`), SEED);
  return `${prefix}.${pb}.${Buffer.from(sig).toString("base64url")}`;
}

const basePayload = {
  v: 1,
  pid: "demo-app",
  lid: "11111111-2222-4333-8444-555555555555",
  sub: "buyer@example.com",
  seats: 1,
  iat: vectors.now - 1000,
  exp: null,
  upd: null,
  feat: [],
  meta: {},
};

describe("spec/testvectors.json (all vectors)", () => {
  for (const v of vectors.vectors) {
    it(v.id, async () => {
      const result = await verifyLicense(v.license, PK, v.options);
      if (v.expect.ok) {
        expect(result).toEqual({ ok: true, payload: v.expect.payload });
      } else {
        expect(result).toEqual({ ok: false, reason: v.expect.reason });
      }
    });
  }

  it("still carries the groups that make the four verifiers agree", () => {
    // The claim this kit sells is that C#, TypeScript, Python and Rust return the same code for the
    // same license, and the shared file is the only thing that proves it. Until 2026-09-08 it had no
    // required-field case (spec §5 step 10) and no non-canonical base64url case (§8), so those two
    // rules were only ever checked by each language against itself. The file is append-only (§9),
    // so these bounds can only be raised; they catch a truncated or stale copy, which would still
    // parse and still "pass".
    const ids = vectors.vectors.map((v) => v.id);
    expect(ids.length).toBeGreaterThanOrEqual(38);
    for (const group of ["field-", "int-", "b64-", "struct-", "unicode-"]) {
      expect(ids.filter((id) => id.startsWith(group)).length, group).toBeGreaterThan(0);
    }
    const reasons = vectors.vectors.filter((v) => !v.expect.ok).map((v) => (v.expect as { reason: string }).reason);
    expect([...new Set(reasons)].sort()).toEqual([
      "bad_signature",
      "expired",
      "malformed",
      "product_mismatch",
      "revoked",
      "unsupported_version",
    ]);
  });
});

describe("API behaviour", () => {
  const perpetual = vectors.vectors.find((v) => v.id === "valid-perpetual")!;

  it("defaults `now` to the system clock (a perpetual license verifies today)", async () => {
    const result = await verifyLicense(perpetual.license, PK, { productId: "demo-app" });
    expect(result.ok).toBe(true);
  });

  it("throws (does not return a result) when the public key has the wrong length", async () => {
    await expect(verifyLicense(perpetual.license, "abc")).rejects.toThrow(/public key/);
  });

  it("throws when the public key is padded or contains foreign characters", async () => {
    await expect(verifyLicense(perpetual.license, PK + "=")).rejects.toThrow(/public key/);
    await expect(verifyLicense(perpetual.license, PK.slice(0, 42) + "+")).rejects.toThrow(/public key/);
  });

  it("preserves unknown extra payload fields (forward compatibility)", async () => {
    const lic = await signRaw(JSON.stringify({ ...basePayload, future: { x: 1 } }));
    const result = await verifyLicense(lic, PK, { now: vectors.now });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.payload.future).toEqual({ x: 1 });
  });

  it("reports malformed for a correctly signed payload that is not an object", async () => {
    expect(await verifyLicense(await signRaw("[1,2,3]"), PK)).toEqual({ ok: false, reason: "malformed" });
    expect(await verifyLicense(await signRaw('"just a string"'), PK)).toEqual({ ok: false, reason: "malformed" });
  });

  it("reports malformed for a correctly signed payload with a wrong field type", async () => {
    for (const bad of [
      { ...basePayload, seats: "1" },
      { ...basePayload, seats: -1 },
      { ...basePayload, feat: ["a", 1] },
      { ...basePayload, meta: [] },
      { ...basePayload, exp: "never" },
      { ...basePayload, v: "1" },
    ]) {
      expect(await verifyLicense(await signRaw(JSON.stringify(bad)), PK)).toEqual({ ok: false, reason: "malformed" });
    }
  });

  it("reports malformed when a required field is missing", async () => {
    const { upd: _dropped, ...missingUpd } = basePayload;
    expect(await verifyLicense(await signRaw(JSON.stringify(missingUpd)), PK)).toEqual({
      ok: false,
      reason: "malformed",
    });
  });

  it("reports malformed for invalid JSON and invalid UTF-8 even when correctly signed", async () => {
    expect(await verifyLicense(await signRaw("{not json"), PK)).toEqual({ ok: false, reason: "malformed" });
    const badUtf8 = Buffer.from([0xff, 0xfe, 0x7b, 0x7d]).toString("base64url");
    const sig = await signAsync(new TextEncoder().encode(`LS1.${badUtf8}`), SEED);
    const lic = `LS1.${badUtf8}.${Buffer.from(sig).toString("base64url")}`;
    expect(await verifyLicense(lic, PK)).toEqual({ ok: false, reason: "malformed" });
  });

  it("checks the signature before the product ID (tampered pid is bad_signature, not product_mismatch)", async () => {
    const [prefix, , sig] = perpetual.license.split(".");
    const tampered = Buffer.from(JSON.stringify({ ...basePayload, pid: "other-app" })).toString("base64url");
    expect(await verifyLicense(`${prefix}.${tampered}.${sig}`, PK, { productId: "demo-app" })).toEqual({
      ok: false,
      reason: "bad_signature",
    });
  });

  it("is valid one second before exp and expired at exp", async () => {
    const lic = await signRaw(JSON.stringify({ ...basePayload, exp: vectors.now }));
    expect((await verifyLicense(lic, PK, { now: vectors.now - 1 })).ok).toBe(true);
    expect(await verifyLicense(lic, PK, { now: vectors.now })).toEqual({ ok: false, reason: "expired" });
  });

  it("reports malformed for a correctly signed payload that starts with a UTF-8 BOM (spec §7: nothing is stripped)", async () => {
    // TextDecoder's default silently consumes EF BB BF; the verifier must not, or it would accept a
    // license that Python, Rust and C# reject. The same case is pinned in spec/testvectors.json
    // (extra-payload-utf8-bom); this test keeps the reason local to this file.
    const bytes = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify(basePayload), "utf8")]);
    const pb = bytes.toString("base64url");
    const sig = await signAsync(new TextEncoder().encode(`LS1.${pb}`), SEED);
    const lic = `LS1.${pb}.${Buffer.from(sig).toString("base64url")}`;
    expect(await verifyLicense(lic, PK, { now: vectors.now })).toEqual({ ok: false, reason: "malformed" });
  });

  it("compares pid byte for byte, with no Unicode normalisation (spec §3)", async () => {
    // NFC and NFD spellings of the same text are different product IDs. macOS stores file names
    // decomposed, so a pid taken from a path there can differ byte for byte from the same pid typed
    // on Windows. Normalising here would compare something other than what was signed.
    const nfc = "\u30A2\u30D7\u30EA\u30AC";
    const nfd = nfc.normalize("NFD");
    expect(nfd).not.toBe(nfc);
    const lic = await signRaw(JSON.stringify({ ...basePayload, pid: nfc }));
    expect((await verifyLicense(lic, PK, { productId: nfc, now: vectors.now })).ok).toBe(true);
    expect(await verifyLicense(lic, PK, { productId: nfd, now: vectors.now })).toEqual({
      ok: false,
      reason: "product_mismatch",
    });
  });

  it("rejects a signature that only verifies under ZIP-215 semantics (small-order public key)", async () => {
    // 32 zero bytes encode the curve point y = 0, whose order is 4. With R = B and S = 1 the
    // cofactored ZIP-215 equation [8][S]B = [8]R + [8][k]A holds for *any* message, so a license
    // nobody signed verifies under @noble/ed25519's default options. `ed25519-dalek`'s
    // `verify_strict` and BouncyCastle's `ValidatePublicKeyFull` reject such a key, so the
    // verifier must pass `{ zip215: false }` or the four references disagree (spec §11).
    const smallOrderKey = new Uint8Array(32);
    expect(Point.fromBytes(smallOrderKey).isSmallOrder()).toBe(true);
    const pb = Buffer.from(JSON.stringify(basePayload), "utf8").toString("base64url");
    const sig = new Uint8Array(64);
    sig.set(Point.BASE.toBytes(), 0);
    sig[32] = 1; // S = 1, little-endian
    const msg = new TextEncoder().encode(`LS1.${pb}`);
    expect(await verifyAsync(sig, msg, smallOrderKey)).toBe(true); // the library's ZIP-215 default
    expect(await verifyAsync(sig, msg, smallOrderKey, { zip215: false })).toBe(false);
    const key = Buffer.from(smallOrderKey).toString("base64url");
    const lic = `LS1.${pb}.${Buffer.from(sig).toString("base64url")}`;
    expect(await verifyLicense(lic, key, { now: vectors.now })).toEqual({ ok: false, reason: "bad_signature" });
  });

  it("throws (does not fail open) when `now` is not a finite number", async () => {
    // A NaN or a Date compares as "not expired" and would unlock an expired license.
    const expired = await signRaw(JSON.stringify({ ...basePayload, exp: vectors.now - 1 }));
    for (const now of [NaN, Infinity, -Infinity, new Date(), "1767225600", null]) {
      await expect(verifyLicense(expired, PK, { now: now as unknown as number })).rejects.toThrow(/opts\.now/);
    }
    // Control: a real number of seconds still rejects the license, and `undefined` means "system clock".
    expect(await verifyLicense(expired, PK, { now: vectors.now })).toEqual({ ok: false, reason: "expired" });
    expect(await verifyLicense(expired, PK, { now: undefined })).toEqual({ ok: false, reason: "expired" });
  });
});

describe("integers (spec §3: signed 64-bit, written without a fraction or exponent)", () => {
  /** The base payload with `seats` replaced by a raw JSON number literal, signed. */
  async function withSeats(literal: string): Promise<string> {
    return signRaw(JSON.stringify(basePayload).replace('"seats":1', `"seats":${literal}`));
  }

  it("accepts values above 2^53, up to 2^63-1 (Python, Rust and C# always did)", async () => {
    for (const literal of ["9007199254740992", "9007199254740993", "9223372036854775807"]) {
      const result = await verifyLicense(await withSeats(literal), PK, { now: vectors.now });
      expect(result, literal).toEqual({ ok: true, payload: expect.anything() });
    }
  });

  it("rejects values outside the signed 64-bit range", async () => {
    for (const literal of ["9223372036854775808", "18446744073709551616", "-9223372036854775809", "-1"]) {
      const result = await verifyLicense(await withSeats(literal), PK, { now: vectors.now });
      expect(result, literal).toEqual({ ok: false, reason: "malformed" });
    }
  });

  it("rejects non-canonical integer notation, like the other three verifiers", async () => {
    for (const literal of ["1.0", "1e0", "1.5", "1E2"]) {
      const result = await verifyLicense(await withSeats(literal), PK, { now: vectors.now });
      expect(result, literal).toEqual({ ok: false, reason: "malformed" });
    }
  });

  it("keeps the expiry comparison correct for an `exp` above 2^53", async () => {
    const far = await signRaw(JSON.stringify(basePayload).replace('"exp":null', '"exp":9223372036854775807'));
    expect((await verifyLicense(far, PK, { now: vectors.now })).ok).toBe(true);
    const past = await signRaw(JSON.stringify(basePayload).replace('"exp":null', '"exp":9007199254740992'));
    expect(await verifyLicense(past, PK, { now: 9007199254740993 })).toEqual({ ok: false, reason: "expired" });
  });

  it("does not let a quoted number pass as an integer", async () => {
    // The range check reads the source text, so a *string* field must still be rejected on type.
    for (const literal of ['"1"', '"9223372036854775807"']) {
      const result = await verifyLicense(await withSeats(literal), PK, { now: vectors.now });
      expect(result, literal).toEqual({ ok: false, reason: "malformed" });
    }
  });

  it("preserves numbers inside `meta` unchanged", async () => {
    // The number-quoting pass is only used for the range check; the payload handed back is the
    // ordinary JSON.parse result, so `meta` still holds numbers, not strings.
    const lic = await signRaw(JSON.stringify({ ...basePayload, meta: { order: 12345, ratio: 1.5 } }));
    const result = await verifyLicense(lic, PK, { now: vectors.now });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.payload.meta).toEqual({ order: 12345, ratio: 1.5 });
  });
});

describe("verify-cli.ts (the example checker)", () => {
  const cli = resolve(here, "dist/verify-cli.js");

  beforeAll(() => {
    // The example checker is a script, so it is exercised as a process. Compile it first when the
    // build output is missing or older than its sources, so `pnpm test` on a fresh checkout works
    // and never reports on a stale build.
    const sources = [resolve(here, "verify-cli.ts"), resolve(here, "licensesmith.ts")];
    const fresh = existsSync(cli) && sources.every((s) => statSync(s).mtimeMs <= statSync(cli).mtimeMs);
    if (fresh) return;
    const tsc = [resolve(here, "node_modules/typescript/bin/tsc"), resolve(here, "../../node_modules/typescript/bin/tsc")].find(
      (p) => existsSync(p),
    );
    if (tsc === undefined) throw new Error("cannot find typescript/bin/tsc; run `pnpm install` first");
    execFileSync(process.execPath, [tsc, "-p", resolve(here, "tsconfig.json")], { cwd: here, stdio: "inherit" });
  }, 120_000);

  /** Run the checker and return its exit code, stdout and stderr. */
  function run(args: string[]): { code: number; stdout: string; stderr: string } {
    const r = spawnSync(process.execPath, [cli, ...args], { encoding: "utf8" });
    return { code: r.status ?? -1, stdout: r.stdout, stderr: r.stderr };
  }

  const revoked = vectors.vectors.find((v) => v.id === "extra-revoked")!;
  let dir: string;
  let licenseFile: string;
  let listFile: string;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "licensesmith-cli-"));
    licenseFile = join(dir, "license.txt");
    listFile = join(dir, "revocations.json");
    writeFileSync(licenseFile, revoked.license);
    writeFileSync(listFile, JSON.stringify({ revoked: revoked.options.revokedIds }));
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  const base = () => [`--pub=${PK}`, "--license", licenseFile, "--product", "demo-app", "--now", String(vectors.now)];

  it("reports a revoked license when --revoked names the list file", () => {
    const r = run([...base(), "--revoked", listFile]);
    expect(r.code).toBe(1);
    expect(JSON.parse(r.stdout)).toEqual({ ok: false, reason: "revoked" });
  });

  it("exits 2 when --revoked names a file that does not exist", () => {
    // H1: `revocations.jsonn` used to be read as a one-element ID list, so the revocation check
    // was silently skipped and the revoked license above came back as ok.
    const r = run([...base(), "--revoked", join(dir, "revocations.jsonn")]);
    expect(r.code).toBe(2);
    expect(r.stdout).toBe("");
    expect(r.stderr).toMatch(/no such file/);

    const asDirectory = run([...base(), "--revoked", dir]);
    expect(asDirectory.code).toBe(2);
    expect(asDirectory.stderr).toMatch(/is a directory/);
  });

  it("still accepts an inline, comma-separated list of license IDs", () => {
    const r = run([...base(), "--revoked", revoked.options.revokedIds!.join(",")]);
    expect(r.code).toBe(1);
    expect(JSON.parse(r.stdout)).toEqual({ ok: false, reason: "revoked" });
  });

  it("warns when the revocation list turns out to be empty", () => {
    const empty = join(dir, "empty.json");
    writeFileSync(empty, JSON.stringify({ revoked: [] }));
    const r = run([...base(), "--revoked", empty]);
    expect(r.code).toBe(0);
    expect(r.stderr).toMatch(/holds no license IDs/);
  });

  it("warns when --pub is given a secret key file, without changing the verdict", () => {
    // M-7 / threat model N3: the result is correct, but "it worked" must not teach people that the
    // .key is what belongs in an application.
    const secret = join(dir, "demo.key");
    const pub = join(dir, "demo.pub");
    writeFileSync(secret, JSON.stringify({ kind: "licensesmith-secret-key", v: 1, alg: "Ed25519", publicKey: PK }));
    writeFileSync(pub, JSON.stringify({ kind: "licensesmith-public-key", v: 1, alg: "Ed25519", publicKey: PK }));

    const withSecret = run(["--pub", secret, "--license", licenseFile, "--product", "demo-app", "--now", String(vectors.now)]);
    expect(withSecret.code).toBe(0);
    expect(withSecret.stderr).toMatch(/SECRET key file/);
    expect(JSON.parse(withSecret.stdout).ok).toBe(true);

    const withPublic = run(["--pub", pub, "--license", licenseFile, "--product", "demo-app", "--now", String(vectors.now)]);
    expect(withPublic.code).toBe(0);
    expect(withPublic.stderr).toBe("");
  });

  it("exits 2 when --pub names a file that does not exist", () => {
    const r = run(["--pub", join(dir, "demo.pubb"), "--license", licenseFile]);
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/no such file/);
  });
});
