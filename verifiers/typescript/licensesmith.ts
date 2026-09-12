/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Colophon
 * This file is the MIT-licensed subset of LicenseSmith.
 */
/**
 * LicenseSmith — offline license verifier for the `LS1` key format (Ed25519).
 *
 * This is the whole verifier. Copy this one file into your application.
 *
 * Runtime:     Node.js >= 20, Bun, Deno, Electron (main or renderer), any modern browser.
 * Dependency:  @noble/ed25519 (v3) — `npm i @noble/ed25519` — nothing else.
 * Specification: spec/key-format.md (frozen). Test vectors: spec/testvectors.json.
 *
 * Usage:
 *   import { verifyLicense } from "./licensesmith";
 *   const result = await verifyLicense(licenseText, PUBLIC_KEY, { productId: "my-app" });
 *   if (result.ok) { unlockFeatures(result.payload.feat); } else { showError(result.reason); }
 *
 * What this proves when it says ok: the license was produced by the holder of your secret key
 * and has not been altered. What it cannot do: stop someone from patching your app so this
 * function is never called, or from sharing a genuine license. Read spec/threat-model.md.
 */

import { Point, verifyAsync } from "@noble/ed25519";

/** Error codes. Identical strings in the Python and Rust verifiers. See spec §6. */
export type VerifyError =
  | "malformed"
  | "unsupported_version"
  | "bad_signature"
  | "product_mismatch"
  | "expired"
  | "revoked";

/**
 * The decoded, signature-verified license contents (spec §3).
 *
 * The integer fields are JavaScript numbers. The format allows any signed 64-bit value, so a
 * payload written with more than 2^53 is returned as the nearest representable double; the
 * accept/reject decision is made on the exact digits, not on this value (spec §11).
 */
export interface LicensePayload {
  /** Payload format version, always 1 for LS1. */
  v: 1;
  /** Product ID you chose when issuing, e.g. "my-app". */
  pid: string;
  /** License ID, unique per license (UUID v4). Use it for revocation lists. */
  lid: string;
  /** Buyer e-mail, or "sha256:<hex>" when hashed at issue time. */
  sub: string;
  /** Seats the buyer paid for. Informational — enforcing it is your app's job. */
  seats: number;
  /** Issued-at, Unix seconds (UTC). */
  iat: number;
  /** Expiry, Unix seconds, or null for perpetual. Checked by verifyLicense. */
  exp: number | null;
  /** "Updates until", Unix seconds, or null for forever. Informational. */
  upd: number | null;
  /** Feature flags, e.g. ["pro", "export"]. */
  feat: string[];
  /** Free-form extra data set at issue time. */
  meta: Record<string, unknown>;
  /** Unknown extra fields are preserved (forward compatibility). */
  [extra: string]: unknown;
}

export type VerifyResult =
  | { ok: true; payload: LicensePayload }
  | { ok: false; reason: VerifyError };

export interface VerifyOptions {
  /** If given, licenses whose `pid` differs are rejected with "product_mismatch". Recommended. */
  productId?: string;
  /**
   * Current time in Unix seconds (a finite number). Defaults to the system clock.
   * Anything else — `NaN`, a `Date`, a string, `Infinity` — makes {@link verifyLicense} throw,
   * because a broken clock must never make an expired license pass.
   */
  now?: number;
  /** License IDs (`lid`) that you have revoked. */
  revokedIds?: readonly string[];
}

/**
 * Verify a LicenseSmith license.
 *
 * @param licenseText          The license as the user pasted it. Whitespace/line breaks are fine.
 * @param publicKeyBase64Url   Your 43-character public key (from `licensesmith keygen`).
 * @param opts                 See {@link VerifyOptions}.
 * @returns `{ ok: true, payload }` or `{ ok: false, reason }`. Never throws for bad licenses.
 * @throws Error only if `publicKeyBase64Url` is not a valid key, or `opts.now` is given and is not a
 *         finite number — either one is a bug in your app, not a property of the license.
 */
export async function verifyLicense(
  licenseText: string,
  publicKeyBase64Url: string,
  opts: VerifyOptions = {},
): Promise<VerifyResult> {
  // `now` is validated before anything else: a NaN (e.g. `parseInt(undefined)`) or a Date object
  // would compare as "not expired" at step 12 and silently unlock an expired license (fail-open).
  if (opts.now !== undefined && (typeof opts.now !== "number" || !Number.isFinite(opts.now))) {
    throw new Error(
      "licensesmith: opts.now must be a finite number of Unix seconds (use Math.floor(Date.now() / 1000), not a Date)",
    );
  }

  // §5 step 1: remove the six ASCII whitespace characters, nothing else.
  const text = licenseText.replace(/[ \t\n\v\f\r]/g, "");

  // Step 2: exactly three non-empty parts.
  const parts = text.split(".");
  if (parts.length !== 3 || parts.some((p) => p.length === 0)) return fail("malformed");
  const [prefix, payloadB64, sigB64] = parts;

  // Step 3: prefix.
  if (prefix !== PREFIX) {
    return fail(/^LS[0-9]+$/.test(prefix) ? "unsupported_version" : "malformed");
  }

  // Step 4: signature bytes.
  const sig = b64urlDecode(sigB64);
  if (sig === null || sig.length !== SIGNATURE_LENGTH) return fail("malformed");

  // Step 5: payload bytes (not parsed yet).
  const payloadBytes = b64urlDecode(payloadB64);
  if (payloadBytes === null) return fail("malformed");

  // Step 6: public key. Invalid here means the *application* is misconfigured.
  const publicKey = b64urlDecode(publicKeyBase64Url);
  if (publicKey === null || publicKey.length !== PUBLIC_KEY_LENGTH) {
    throw new Error(
      "licensesmith: invalid public key — expected the 43-character base64url string printed by `licensesmith keygen`",
    );
  }
  try {
    Point.fromBytes(publicKey); // rejects byte strings that are not a point on the curve
  } catch (cause) {
    throw new Error("licensesmith: invalid public key — not a valid Ed25519 key", { cause });
  }

  // Step 7: signature over the ASCII bytes of "LS1.<payload_b64url>", before parsing anything.
  // `zip215: false` is load-bearing, not a style choice: @noble/ed25519 defaults to ZIP-215
  // semantics, under which a small-order public key makes a hand-made signature verify for *any*
  // message. `ed25519-dalek`'s `verify_strict` and BouncyCastle's `ValidatePublicKeyFull` reject
  // those inputs, so this is what makes the four verifiers agree (spec §11). Keys and signatures
  // produced by `licensesmith keygen` / `issue` verify identically either way.
  const signingInput = new TextEncoder().encode(`${prefix}.${payloadB64}`);
  if (!(await verifyAsync(sig, signingInput, publicKey, { zip215: false }))) return fail("bad_signature");

  // Step 8: now the bytes are trusted; parse as strict UTF-8 JSON. `ignoreBOM: true` keeps a leading
  // U+FEFF in the text instead of consuming it (TextDecoder's default) — spec §7 strips nothing from
  // the payload bytes, and a BOM is not JSON, so JSON.parse then rejects it like the other verifiers do.
  let parsed: unknown;
  let literals: unknown;
  try {
    const json = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(payloadBytes);
    parsed = JSON.parse(json);
    // Second pass with every number literal quoted. JSON.parse turns 9223372036854775807 and
    // 9223372036854775808 into the same IEEE-754 double, so spec §3's "values must fit in a signed
    // 64-bit integer" cannot be decided from the parsed value — only from the digits the issuer
    // wrote. Python, Rust and C# read those digits natively; this is how JavaScript gets them.
    literals = JSON.parse(quoteJsonNumbers(json));
  } catch {
    return fail("malformed"); // invalid UTF-8 or invalid JSON is, by definition, malformed
  }
  if (!isPlainObject(parsed) || !isPlainObject(literals)) return fail("malformed");

  // Step 9: version.
  if (!isInt(parsed.v, literals.v)) return fail("malformed");
  if (parsed.v !== 1) return fail("unsupported_version");

  // Step 10: required fields and types.
  if (
    typeof parsed.pid !== "string" ||
    typeof parsed.lid !== "string" ||
    typeof parsed.sub !== "string" ||
    !isNonNegInt(parsed.seats, literals.seats) ||
    !isNonNegInt(parsed.iat, literals.iat) ||
    !isNonNegIntOrNull(parsed.exp, literals.exp) ||
    !isNonNegIntOrNull(parsed.upd, literals.upd) ||
    !isStringArray(parsed.feat) ||
    !isPlainObject(parsed.meta)
  ) {
    return fail("malformed");
  }
  const payload = parsed as unknown as LicensePayload;

  // Step 11: product.
  if (opts.productId !== undefined && payload.pid !== opts.productId) return fail("product_mismatch");

  // Step 12: expiry. Valid strictly before `exp`.
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  if (payload.exp !== null && now >= payload.exp) return fail("expired");

  // Step 13: revocation.
  if (opts.revokedIds !== undefined && opts.revokedIds.includes(payload.lid)) return fail("revoked");

  return { ok: true, payload };
}

// Internals. Kept in this file on purpose so the verifier stays a single copy-paste unit.

const PREFIX = "LS1";
const SIGNATURE_LENGTH = 64;
const PUBLIC_KEY_LENGTH = 32;
const B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64URL_LOOKUP: Int16Array = (() => {
  const t = new Int16Array(128).fill(-1);
  for (let i = 0; i < B64URL_ALPHABET.length; i++) t[B64URL_ALPHABET.charCodeAt(i)] = i;
  return t;
})();

function fail(reason: VerifyError): VerifyResult {
  return { ok: false, reason };
}

/** base64url without padding (RFC 4648 §5). */
function b64urlEncode(bytes: Uint8Array): string {
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out +=
      B64URL_ALPHABET[(n >>> 18) & 63] +
      B64URL_ALPHABET[(n >>> 12) & 63] +
      B64URL_ALPHABET[(n >>> 6) & 63] +
      B64URL_ALPHABET[n & 63];
  }
  const rem = bytes.length - i;
  if (rem === 1) {
    const n = bytes[i] << 16;
    out += B64URL_ALPHABET[(n >>> 18) & 63] + B64URL_ALPHABET[(n >>> 12) & 63];
  } else if (rem === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += B64URL_ALPHABET[(n >>> 18) & 63] + B64URL_ALPHABET[(n >>> 12) & 63] + B64URL_ALPHABET[(n >>> 6) & 63];
  }
  return out;
}

/**
 * Strict base64url decode (spec §8): alphabet only, no padding, length % 4 != 1, canonical.
 * Returns null for anything invalid, including the empty string.
 */
function b64urlDecode(s: string): Uint8Array | null {
  const len = s.length;
  if (len === 0 || len % 4 === 1) return null;
  const out = new Uint8Array(Math.floor((len * 3) / 4));
  let buffer = 0;
  let bits = 0;
  let o = 0;
  for (let i = 0; i < len; i++) {
    const c = s.charCodeAt(i);
    const v = c < 128 ? B64URL_LOOKUP[c] : -1;
    if (v < 0) return null;
    buffer = (buffer << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (buffer >>> bits) & 0xff;
    }
  }
  // Canonical check: re-encoding must reproduce the input exactly (rejects non-zero trailing bits).
  if (b64urlEncode(out) !== s) return null;
  return out;
}

function isPlainObject(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

/** Spec §3: written without a fraction or exponent. `1.0`, `1e0` and `01` are not integers here. */
const INTEGER_LITERAL = /^-?(?:0|[1-9][0-9]*)$/;
const I64_MIN = BigInt("-9223372036854775808");
const I64_MAX = BigInt("9223372036854775807");
/** Every character that can continue a JSON number token. Nothing else can follow one. */
const NUMBER_CHAR = /[-+.0-9eE]/;

/**
 * Return `json` with every number literal replaced by a JSON string holding its exact source text,
 * so that parsing the result yields the digits the issuer wrote instead of an IEEE-754 double.
 *
 * The input has already been accepted by `JSON.parse`, so the scanner only has to tell a string
 * literal from everything else: outside a string, `-` or a digit always starts a number, and a
 * number token ends at the first character that cannot continue it.
 */
function quoteJsonNumbers(json: string): string {
  let out = "";
  let i = 0;
  while (i < json.length) {
    const c = json[i];
    if (c === '"') {
      const start = i++;
      while (i < json.length) {
        const d = json[i++];
        if (d === "\\") i++;
        else if (d === '"') break;
      }
      out += json.slice(start, i);
    } else if (c === "-" || (c >= "0" && c <= "9")) {
      const start = i;
      while (i < json.length && NUMBER_CHAR.test(json[i])) i++;
      out += `"${json.slice(start, i)}"`;
    } else {
      out += c;
      i++;
    }
  }
  return out;
}

/**
 * `value` is what `JSON.parse` produced for the field; `literal` is the same field's source text
 * from the number-quoting pass. Both are needed: the literal alone cannot tell the number `5` from
 * the string `"5"`, and the value alone cannot tell 2^63-1 from 2^63 (the same double).
 */
function isInt(value: unknown, literal: unknown): value is number {
  if (typeof value !== "number" || typeof literal !== "string" || !INTEGER_LITERAL.test(literal)) return false;
  const n = BigInt(literal);
  return n >= I64_MIN && n <= I64_MAX;
}
function isNonNegInt(value: unknown, literal: unknown): value is number {
  return isInt(value, literal) && value >= 0;
}
function isNonNegIntOrNull(value: unknown, literal: unknown): value is number | null {
  return value === null || isNonNegInt(value, literal);
}
function isStringArray(x: unknown): x is string[] {
  return Array.isArray(x) && x.every((e) => typeof e === "string");
}
