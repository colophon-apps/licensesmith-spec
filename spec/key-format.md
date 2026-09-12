# LicenseSmith Key Format — `LS1` (version 1)

**Status: FROZEN on 2026-09-07.** Verifiers built against this document must keep accepting every
license issued under it, forever. Any incompatible change gets a new prefix (`LS2`, `LS3`, …); the
`LS1` rules below never change. See §10.

This document is normative. The four reference verifiers (`verifiers/typescript/licensesmith.ts`,
`verifiers/python/licensesmith.py`, `verifiers/rust/src/lib.rs`, `verifiers/csharp/LicenseSmith.cs`) implement
exactly this algorithm,
and `spec/testvectors.json` (§9) pins the behaviour so any other implementation can prove it agrees.

---

## 1. Overview

A LicenseSmith license is one ASCII string made of three parts separated by `.`:

```
LS1.<payload_b64url>.<sig_b64url>
```

| Part | Meaning |
|---|---|
| `LS1` | Format identifier. Literally the three characters `L`, `S`, `1`. |
| `<payload_b64url>` | The **payload** (a UTF-8 JSON object, §3) encoded as base64url without padding (§8). |
| `<sig_b64url>` | A 64-byte **Ed25519 signature** (RFC 8032) encoded as base64url without padding. |

**What is signed:** the ASCII bytes of the string `LS1.<payload_b64url>` — the first two parts and
the dot between them, exactly as they appear in the license. The verifier checks the signature over
those bytes *before* it ever parses the JSON. Because the signed object is the encoded text and not
the JSON, there is no canonicalisation step and no "key order / whitespace" mismatch between
languages: whatever bytes the issuer signed are the bytes the verifier checks.

**Display:** an issuer may insert line breaks (conventionally every 64 characters) so the license
pastes nicely into a text box. Verifiers remove ASCII whitespace before parsing (§7), so wrapped and
unwrapped forms are equivalent.

**Why it is long:** a raw Ed25519 signature is 64 bytes (86 base64url characters) and the payload
carries the licensee, the product and the terms. A license is typically 250–400 characters. It is
meant to be pasted or loaded from a file, not typed by hand. Making it short would require either
truncating the signature (breaking the security proof) or replacing the signature with a server
lookup (breaking "offline"). LicenseSmith does neither.

---

## 2. Keys

- Algorithm: **Ed25519** (RFC 8032), the only algorithm in `LS1`.
- **Secret key** = the 32-byte seed. Kept by the developer who issues licenses. Never ships in an app.
- **Public key** = 32 bytes, derived from the seed. Embedded in the application that verifies licenses.
- Wire form of the public key everywhere in LicenseSmith: **base64url without padding**, 43 characters.

Key files written by the issuer CLI are small JSON documents so they are self-describing:

```json
{ "kind": "licensesmith-secret-key", "v": 1, "alg": "Ed25519",
  "seed": "<base64url, 32 bytes>", "publicKey": "<base64url, 32 bytes>" }
```
```json
{ "kind": "licensesmith-public-key", "v": 1, "alg": "Ed25519",
  "publicKey": "<base64url, 32 bytes>" }
```

Verifiers do **not** read key files; they take the 43-character public-key string directly.

---

## 3. Payload

The payload is a JSON object. All ten fields below are **required**. Unknown extra fields are
allowed and must be ignored (forward compatibility within `LS1`).

| Key | JSON type | Meaning |
|---|---|---|
| `v` | integer | Payload format version. Always `1` in `LS1`. |
| `pid` | string | **Product ID.** An identifier the developer chooses for their product, e.g. `"my-app"`. The verifier can be told which product it belongs to and will reject licenses for other products. |
| `lid` | string | **License ID.** Unique per issued license (the CLI uses UUID v4). Referenced by revocation lists. |
| `sub` | string | **Subject** — who the license was issued to. Either the buyer's e-mail address as given, or, when the issuer chose to hash it, the string `sha256:` followed by the lowercase hex SHA-256 of the e-mail after trimming whitespace and lower-casing (`--hash-email` in the CLI). |
| `seats` | integer ≥ 0 | Number of seats/devices the buyer paid for. **Informational:** the verifier returns it; enforcing it is the application's job. |
| `iat` | integer | Issued-at time, Unix seconds (UTC). |
| `exp` | integer or `null` | Expiry time, Unix seconds. `null` = never expires (perpetual / buy-once). |
| `upd` | integer or `null` | "Updates until" time, Unix seconds. For "buy once, one year of updates" schemes: the application compares its own build date with `upd`. `null` = updates forever. Informational, like `seats`. |
| `feat` | array of strings | Feature flags, e.g. `["pro","export"]`. May be empty. |
| `meta` | object | Free-form extra data (order number, buyer name, …). May be empty. Not interpreted. |

Integers are JSON numbers written without a fraction or exponent (`42`, not `42.0` or `4.2e1`).
Values must fit in a signed 64-bit integer; times are non-negative. The reference issuer always
writes integers this way, and a verifier rejects anything else as `malformed` (§11). The ranges in
the table above are part of the rule, not advice: a value of the right JSON type but outside its
range is `malformed` too (§5 step 10).

**Duplicate keys: the last one wins (normative).** A conforming payload never repeats a key, but a
repeated key does not by itself make the license `malformed`: the last occurrence is the value, and
earlier ones are discarded. Measured, on a correctly signed payload: `"seats":1,"seats":7` verifies
as **ok** with `seats = 7` in all four reference verifiers, and the same "last wins" holds for a
repeated `pid` and a repeated `exp`. This is what the four JSON parsers already do; it is written
down here so a fifth implementation cannot choose "first wins" or "reject" and quietly disagree
about which product a license is for. The reference issuer writes each key exactly once (§4).

**Strings are compared byte for byte (normative).** `pid`, `lid` and `sub` are Unicode strings
carried as UTF-8. A verifier compares them **exactly, as UTF-8 byte sequences**: it must not apply
Unicode normalisation (NFC/NFD/NFKC/NFKD), case folding, whitespace trimming or any other
equivalence before comparing. This is forced by the format itself — the signature covers the payload
bytes, so a verifier that normalised the payload would be checking something other than what was
signed — and it is what makes the four reference implementations agree.

The practical consequence: `"アプリガ"` written as NFC and the same text written as NFD are
different product IDs, even though they look identical and most editors treat them as equal. macOS
stores file names in a decomposed form, so a `pid` copied out of a path on macOS can differ byte for
byte from the same `pid` typed on Windows or Linux. **Choose a product ID from an ASCII alphabet
(`my-app`) unless you have a reason not to**, and if you use non-ASCII, pass the same bytes at issue
time and at verification time (measured: all four verifiers return `product_mismatch` for an NFD
`product_id` against an NFC `pid`).

---

## 4. Canonical serialisation (issuer side, informative)

The reference issuer serialises the payload as compact JSON (no whitespace) with keys in exactly this
order: `v, pid, lid, sub, seats, iat, exp, upd, feat, meta`, then UTF-8 encodes it and base64url
encodes the bytes. This makes issuance **deterministic** (Ed25519 itself is deterministic), so the
same payload signed with the same key always yields the same license string — useful for tests and
for re-sending a lost license.

Verifiers must **not** depend on this ordering or compactness. They verify the bytes they were given.

---

## 5. Verification algorithm (normative)

Inputs: `license_text` (string), `public_key` (43-char base64url string), and options
`product_id` (string, optional), `now` (integer Unix seconds, default: current time),
`revoked_ids` (list of strings, default: empty).

Output: either **ok** with the decoded payload, or **not ok** with exactly one error code from §6.

Steps, in this order. The first failing step decides the error code.

1. **Normalise.** Remove every ASCII whitespace character (§7) from `license_text`.
2. **Split** on `.`. There must be exactly three parts, all non-empty. Otherwise → `malformed`.
3. **Prefix.** If part 1 is `LS1`, continue. If part 1 matches `LS` followed by one or more ASCII
   digits (e.g. `LS2`), → `unsupported_version`. Anything else → `malformed`.
4. **Decode the signature.** Part 3 must be valid strict base64url (§8) decoding to exactly 64 bytes.
   Otherwise → `malformed`.
5. **Decode the payload.** Part 2 must be valid strict base64url (§8) decoding to one or more bytes.
   Otherwise → `malformed`. (Do not parse it yet.)
6. **Decode the public key.** Must be valid strict base64url decoding to exactly 32 bytes. If not,
   this is a **programming error in the application**, not a license outcome: TypeScript throws,
   Python raises `ValueError`, Rust returns `Err(VerifyError::InvalidPublicKey)`, C# throws `ArgumentException`. Whether a
   well-formed 32-byte string that is not a point on the curve is rejected here or fails later as
   `bad_signature` depends on the Ed25519 library. Neither case happens with a key produced by the CLI.
7. **Verify the signature** over the ASCII bytes of `part1 + "." + part2` (i.e. `LS1.<payload_b64url>`
   using the normalised, un-decoded text). If verification fails → `bad_signature`.
8. **Parse the payload** bytes as UTF-8 JSON. It must be a JSON object → otherwise `malformed`.
9. **Version.** The object must have an integer `v` → otherwise `malformed`. If `v ≠ 1` →
   `unsupported_version`.
10. **Fields.** Every required field in §3 must be present, with the required type **and within the
    range §3 gives for it** → otherwise `malformed`. The range is as binding as the type: an integer
    outside signed 64-bit, a negative `seats`, `iat`, `exp` or `upd` (measured: `seats: -1`,
    `iat: -1`, `exp: -5` and `upd: -1` are `malformed` in all four verifiers) and a number written with a
    fraction or an exponent are all `malformed`, even though their JSON types are right. Extra
    fields are ignored. If a key appears more than once, the last occurrence is the value (§3).
11. **Product.** If `product_id` was given and `payload.pid ≠ product_id` → `product_mismatch`.
    The comparison is byte-exact, with no Unicode normalisation (§3).
12. **Expiry.** If `payload.exp` is not `null` and `now ≥ exp` → `expired`.
    (A license is valid strictly before its expiry instant, same convention as JWT `exp`.)
13. **Revocation.** If `payload.lid` is in `revoked_ids` → `revoked`.
14. Otherwise → **ok**, returning the payload.

**Why the signature is checked before the JSON is parsed (steps 7 → 8):** the verifier never feeds
untrusted bytes to a JSON parser and never branches on unverified data. A tampered `pid`, `exp` or
anything else fails at step 7 as `bad_signature`, not as a more specific error. Consequently the
test vector "payload tampered" expects `bad_signature`, and `malformed` can be reported either
before the signature check (structure) or after it (JSON contents).

**Informational fields:** `seats`, `upd`, `feat`, `meta` and `iat` are returned, never checked.
What to do with them is the application's decision.

---

## 6. Error codes

Identical strings in all four reference implementations.

| Code | Reported when |
|---|---|
| `malformed` | Structure is wrong: not three non-empty parts, unknown prefix, invalid or wrong-length base64url, payload not a JSON object, `v` missing/non-integer, a required field missing, of the wrong type, or outside the range §3 gives for it. |
| `unsupported_version` | Prefix is `LS<n>` with `n ≠ 1`, or payload `v ≠ 1`. The license may be valid for a newer verifier. |
| `bad_signature` | The Ed25519 signature does not verify over `LS1.<payload_b64url>` with the given public key. Any modification of the payload text ends up here. |
| `product_mismatch` | `product_id` was supplied and differs from `payload.pid`. |
| `expired` | `payload.exp` is set and `now ≥ exp`. |
| `revoked` | `payload.lid` is in `revoked_ids`. |

Precedence is the step order in §5. A license can only ever produce the first applicable code.

---

## 7. Whitespace

Before parsing, verifiers delete every occurrence of these six ASCII characters anywhere in the text:
space `0x20`, tab `0x09`, line feed `0x0A`, vertical tab `0x0B`, form feed `0x0C`, carriage return
`0x0D`. No other characters (in particular no Unicode whitespace) are removed. This set is fixed so
that every language filters exactly the same bytes.

---

## 8. Base64url, strict

"Strict base64url" in this document means RFC 4648 §5 with these rules:

- Alphabet `A–Z a–z 0–9 - _` only. Any other character → invalid.
- **No padding.** A trailing `=` → invalid.
- Length modulo 4 must not be 1 → otherwise invalid.
- **Canonical:** re-encoding the decoded bytes must reproduce the input exactly. Encodings with
  non-zero unused trailing bits are invalid. (Rust's `base64` crate enforces this natively; the
  TypeScript, Python and C# verifiers re-encode and compare.)

Strictness matters for the signature part: without the canonical rule, one signature would have
several textual spellings, and different libraries would disagree on which to accept.

---

## 9. Test vectors

`spec/testvectors.json` contains a **test-only** key pair (its seed is public; never issue real
licenses with it) and a set of licenses, each with the options to verify with and the expected
result. Every reference verifier runs the whole file in its test suite; the cross-language script
`scripts/test-all.*` additionally issues fresh licenses and checks all four verifiers agree.

**38 vectors: 6 accepted, 32 rejected** (23 `malformed`, 2 `bad_signature`, 2 `unsupported_version`,
2 `product_mismatch`, 2 `expired`, 1 `revoked`). What they pin:

| Group | # | Cases |
|---|---|---|
| Accepted | 6 | perpetual; expiring; five seats with feature flags and `meta`; the same license wrapped with CRLF, tab and spaces (§7); no `product_id` given; a non-ASCII `pid` matched byte for byte (§3) |
| Signature and outcome | 6 | flipped signature bit; edited payload with the original signature; `expired`; `now == exp` exactly; `product_mismatch`; `revoked` |
| Prefix and version (§5 steps 3, 9) | 2 | prefix `LS2`; payload `v = 2` — both `unsupported_version` |
| Structure (§5 steps 2–4, §7) | 5 | only two parts; an empty part; a lowercase `ls1` prefix; a signature that decodes to 63 bytes; an ideographic space (U+3000), which §7 does **not** remove |
| Strict base64url (§8) | 5 | padding; the standard `+ /` alphabet; a non-zero unused trailing bit in the signature and in the payload (the canonical rule — both decode to the same bytes, so a verifier without it accepts or misreports them); a part 1 mod 4 long |
| Payload bytes (§5 step 8) | 1 | a UTF-8 BOM in front of the JSON |
| Required fields (§5 steps 9–10) | 9 | `v`, `pid` and `upd` missing; `v`, `pid`, `seats`, `exp`, `feat` and `meta` of the wrong type |
| Integer form (§3, §11) | 3 | 2^63; `1.0`; `1e0` |
| Byte-exact strings (§3) | 1 | an NFD `pid` against an NFC `product_id` → `product_mismatch` |

Every vector but the encoding ones is correctly signed, so each fails at the step it is named after
and at no earlier one.

The file is frozen together with this document. New vectors may be appended; existing ones are never
edited. The first sixteen date from 2026-09-07; the rest were appended on 2026-09-08.

---

## 10. Compatibility policy

- `LS1` is stable. Verifiers shipped inside applications cannot be updated easily, so the issuer
  side carries the burden: the CLI will always be able to produce `LS1` licenses.
- New optional behaviour that older verifiers can safely ignore may be added as **extra payload
  fields** (verifiers ignore unknown fields).
- Anything an old verifier could not safely ignore (new signature algorithm, changed signing input,
  new required field) is a new prefix (`LS2`). An `LS1` verifier reports such a license as
  `unsupported_version`, which the application can turn into "please update".

---

## 11. Notes for implementers

- **Numbers.** An integer field must be a JSON number in the canonical form of §3 — no fraction, no
  exponent — whose value fits a signed 64-bit integer. Anything else (`1.0`, `1e0`, `9223372036854775808`)
  is `malformed`. The four references reach that rule by different routes: Python compares Python
  `int`s, Rust uses `serde_json`'s `as_i64`, C# parses with `long.TryParse` inside its own reader, and
  TypeScript reads the number's **source text**, because `JSON.parse` turns `9223372036854775807` and
  `9223372036854775808` into the same IEEE-754 double and the range cannot be decided afterwards.
  One consequence remains visible to callers: the TypeScript verifier hands the payload back with
  JavaScript numbers, so a field above 2^53 comes back rounded to the nearest double (the
  accept/reject decision still used the exact digits). If you need such values intact in a browser or
  in Electron, carry them as strings in `meta`. **The same ceiling applies to the reference issuer**,
  not only to the TypeScript verifier: the CLI holds the payload as JavaScript values and serialises
  it with `JSON.stringify` (§4), so it cannot *write* an integer above 2^53 exactly either — measured,
  `JSON.stringify(JSON.parse('{"seats":9223372036854775807}'))` yields `{"seats":9223372036854776000}`.
  `LS1` allows the whole signed-64-bit range and the Python, Rust and C# verifiers read all of it, but
  the reference tooling at both ends only reaches the exactly-representable part.
- **There is no maximum length, so impose one yourself.** §1 says a license is *typically* 250–400
  characters; the format sets no upper bound and the verifiers enforce none. Measured: a
  266,931-character license (a 200 KB string in `meta`) is decoded, parsed and returned as **ok** by
  all four. Signature verification is linear in the input, so this is not a cryptographic hazard, but
  a paste box or a "load licence file" button will hand a verifier whatever it is given, and the
  decoded payload then sits in memory — on a phone or in a game engine that is a real cost, and a
  200 KB "licence key" is a support ticket rather than a customer. **Cap the input length in the
  calling code** before you call the verifier; a few kilobytes is generous for a genuine license.
- **Strings are not normalised.** `pid`, `lid` and `sub` are compared as exact UTF-8 byte sequences
  (§3). No implementation may apply Unicode normalisation, case folding or trimming first: the
  signature covers the payload bytes, so normalising would compare something other than what was
  signed. NFC and NFD spellings of the same text are therefore different values.
- **Timing.** Compare `now ≥ exp`, both integers. Do not use floating-point seconds.
- **Do not "fix up" input** beyond §7. Do not add padding for the user, do not lowercase, do not
  trim only the ends. Either the text verifies as-is (after whitespace removal) or it is rejected.
- **Constant-time comparison** of the signature is handled inside the Ed25519 library; the verifier
  only compares public strings (`pid`, `lid`) which are not secret.
- **Signature malleability and non-canonical points.** Ed25519 libraries differ on *non-canonical*
  encodings (an `S` component ≥ the group order, a non-canonical `R` or `A`, a small-order public
  key), and several offer both a permissive "ZIP-215" branch and a strict RFC 8032 branch. **All four
  reference verifiers are on the strict side, and one of them needs to be told so:** `ed25519-dalek`
  is used through `verify_strict`, BouncyCastle through `Ed25519.ValidatePublicKeyFull`, Python's
  `cryptography` is strict by default, and `@noble/ed25519` **defaults to ZIP-215** and is therefore
  called with `{ zip215: false }`. Left at its default it accepts a signature that no one produced:
  with a small-order public key, `R` = the base point and `S` = 1, the cofactored equation holds for
  *any* message. A key from `licensesmith keygen` is never small-order and the issuer only ever
  writes canonical signatures, so conforming licenses are unaffected either way; this case is not
  covered by test vectors, because `spec/testvectors.json` holds a single key pair at the top of the
  file and a vector cannot name a public key of its own — a small-order key is unexpressible in that
  schema, and the schema is frozen (§9). The TypeScript suite pins the behaviour directly instead.
- **An invalid public key is not a license outcome**, and the four references report it slightly
  differently (§5 step 6). Given 32 bytes that decode but are not a usable key, TypeScript, Python and
  Rust report `bad_signature`, while C# raises `ArgumentException` because BouncyCastle validates the
  key fully before use (the sample C# checker turns that into exit code 2). Both are correct: a bad
  public key is a bug in the application, not a property of the license.
- **Threat model.** Signature verification proves *the developer's secret key produced this
  license* and *nothing in it changed*. It does not stop someone from editing the application so it
  never calls the verifier, nor from sharing a genuine license. `spec/threat-model.md` spells out
  what this format can and cannot do; please read it before advertising your protection.

---

### 日本語要約

ライセンスは `LS1.<payload_b64url>.<sig_b64url>` の1行の ASCII 文字列。署名対象は
`LS1.<payload_b64url>` の ASCII バイト列そのもので、JSON を再直列化しない。検証は
「空白除去 → 3分割 → 接頭辞 → base64url 厳密デコード → **署名検証 → JSON パース** →
`v` → 必須フィールド → 製品ID → 期限（`now ≥ exp` で失効）→ 失効リスト」の順で、
最初に失敗した段の 1 コード（`malformed` / `unsupported_version` / `bad_signature` /
`product_mismatch` / `expired` / `revoked`）だけを返す。4言語（TypeScript・Python・Rust・C#）の参照実装は同じ文字列コードを返し、
`spec/testvectors.json` で一致を検証する。`LS1` は凍結済みで、非互換の変更は `LS2` になる。

文字列フィールド（`pid` / `lid` / `sub`）は **Unicode 正規化せず、UTF-8 のバイト列として厳密に比較する**
（§3）。署名対象はペイロードのバイト列そのものなので、検証器が正規化してしまうと署名されたものとは
別のものを比べることになるためである。したがって NFC の `アプリガ` と NFD の `アプリガ` は
**別の製品 ID** になる。macOS はファイル名を分解形で保持するので、製品 ID をパスから取ると
環境によってバイト列が変わりうる。**製品 ID は ASCII（`my-app` など）にしておくのが安全**で、
非 ASCII を使うなら発行時と検証時に同じバイト列を渡すこと。
整数フィールドは小数点も指数も付かない表記で、符号付き 64 ビットに収まる値だけが有効
（`1.0` や `9223372036854775808` は 4 実装とも `malformed`）。型が合っていても §3 の値域を外れるもの
（`seats: -1` など）は同じく `malformed`（4 実装で実測）。同じキーが 2 回現れたときは
**最後の値が有効**（4 実装で実測）。ライセンス文字列の長さに上限は無く、巨大なペイロードも
そのままデコード・パースされるので、**呼び出し側で長さを制限すること**（§11）。
