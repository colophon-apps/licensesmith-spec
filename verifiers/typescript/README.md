# @licensesmith/verifier

Single-file, offline license-key verifier for the LicenseSmith **`LS1`** key format (Ed25519).
No server, no account, no network call — a license is accepted because its signature checks out on the
user's own machine.

MIT licensed. One dependency: [`@noble/ed25519`](https://www.npmjs.com/package/@noble/ed25519).

## Install

```
npm i @licensesmith/verifier
```

Or skip the dependency on this package entirely and **copy `licensesmith.ts` into your project** — it is
one self-contained file, and that is the intended way to use it.

Runtime: Node ≥20, Bun, Deno, Electron, or a browser. Running this package's own test suite
(`vitest run`) needs Node ≥22.12/≥24/≥26 — that floor is vitest 5's, not the verifier's.

## Use

```ts
import { verifyLicense } from "@licensesmith/verifier";

const PUBLIC_KEY = "..."; // base64url, 43 chars — your Ed25519 public key

const result = await verifyLicense(userPastedText, PUBLIC_KEY, { productId: "my-app" });
if (result.ok) {
  unlock(result.payload.feat);
} else {
  showError(result.reason);
}
```

`verifyLicense` never throws for a bad license. It returns `{ ok: false, reason }` with exactly one of
six codes, decided in this order:

| `reason` | Meaning |
|---|---|
| `malformed` | Not a well-formed `LS1.<payload>.<signature>` string, or the payload is not valid JSON |
| `unsupported_version` | A key format this verifier does not implement |
| `bad_signature` | The signature does not match the payload bytes under your public key |
| `product_mismatch` | The signed `pid` is not the `productId` you asked for |
| `expired` | The clock it read is past the signed `exp` |
| `revoked` | The signed `lid` is in the `revokedIds` you passed |

Options: `productId`, `now` (Unix **seconds**, for testing; defaults to the system clock), `revokedIds`
(a list of revoked license IDs you ship with your app).

`verifyLicense` throws only for a bug in the calling code — a public key that is not a valid
43-character base64url Ed25519 key, or a `now` that is not a finite number (`NaN`, a `Date`,
`Infinity`) — never for the contents of a license.

## What it does and does not do

A signature check proves a key was issued by whoever holds the private key, and that nobody edited it
afterwards. It does **not** stop someone patching the check out of your binary, and it does **not**
detect a paying customer sharing their key — offline, there is nothing to compare against. The full
threat model is written down rather than left implied, and it is in the same free, MIT-licensed
repository as this file: `spec/threat-model.md`.

## Spec and test vectors

The key format is frozen and published: the exact byte layout, the signed bytes, the payload fields and
the error-code decision order are in `spec/key-format.md`, and `spec/testvectors.json` holds 38 fixed
licenses (6 accepted, 32 rejected) that every reference verifier is checked against. Both are in the
free, MIT-licensed repository alongside this file, so you can confirm this implementation matches the
spec instead of trusting it.

## Issuing keys

This package **verifies** licenses; it does not issue them. Issuing (keypair generation, signing,
batch-issuing from a sales CSV, an issuance ledger and revocation) is part of the full LicenseSmith
kit, together with Python, Rust and C# verifiers of the same format and a commercial license for use in
your own products. It is a one-time purchase — see the LicenseSmith product pages linked from the
repository README.

## License

MIT — see [`LICENSE`](LICENSE).
