# LicenseSmith — key-format spec & reference verifier

**Offline license-key verification for indie software.** Ed25519 signatures checked inside your app —
no server, no account, no per-check latency or bill. Version 1.1.0.

This is LicenseSmith's published key-format spec and TypeScript and C# reference implementations, under
the MIT License: the frozen key-format spec, the fixed test vectors, the complete single-file TypeScript
and C# verifiers, and the full threat model.

Issuing licenses is a separate, one-time-purchase kit — the issuing CLI, Python/Rust verifiers of the
same format, the issuance ledger and revocation tooling, and Japanese-language documentation — sold on
Gumroad and BOOTH; see [the full kit](#the-full-kit).

```
pnpm install && pnpm test
```

Before you buy anything you can read the exact algorithm, run the real tests, and read the full
account of what this scheme does **not** prevent — nothing about the limits is held back for buyers.

## Verify a real, signed license right now

`spec/testvectors.json` ships a test-only Ed25519 key pair and 38 already-signed licenses. Pick one and
run it through the verifier from the command line — no license file, no key file, nothing to create:

```bash
pnpm install && pnpm build
printf '%s' "LS1.eyJ2IjoxLCJwaWQiOiJkZW1vLWFwcCIsImxpZCI6IjBmNmEyYjFjLTlkNGUtNGE3Yi04YzNkLTFlMmYzYTRiNWM2ZCIsInN1YiI6ImJ1eWVyQGV4YW1wbGUuY29tIiwic2VhdHMiOjEsImlhdCI6MTc2NDYzMzYwMCwiZXhwIjpudWxsLCJ1cGQiOm51bGwsImZlYXQiOltdLCJtZXRhIjp7fX0.7ANTOuefBNYyZ_FReXdEOVVvSN613FEFyCbPS-tSbtQnXR9ZX9kHKS45GZAvYXXGBV_ur1NuPjwrhrvxNx2aDA" \
  | node verifiers/typescript/dist/verify-cli.js \
      --pub nl0U9R690IJl7QdRkzRnK7l5YB1oNjx-CJPLBEw9wh4 \
      --license - --product demo-app --now 1767225600
```

```
{"ok":true,"payload":{"v":1,"pid":"demo-app","lid":"0f6a2b1c-9d4e-4a7b-8c3d-1e2f3a4b5c6d","sub":"buyer@example.com","seats":1,"iat":1764633600,"exp":null,"upd":null,"feat":[],"meta":{}}}
```

That public key and that license string are copied verbatim from
[`spec/testvectors.json`](spec/testvectors.json) (vector `valid-perpetual`) — the same file the test
suite above (`pnpm test`; 38 vectors, 6 accepted, 32 rejected) checks the verifier against. What it
doesn't show you is how to make one of your own: the seed behind that public key is published,
test-only, and never meant to sign anything real — the file says so. Generating a real key pair and
signing a real license is the issuing side of LicenseSmith, and it isn't in this repository — see
[the full kit](#the-full-kit).

## What's in this repository

| Path | What it is |
|---|---|
| [`spec/key-format.md`](spec/key-format.md) | The `LS1` key-format spec: string layout, signed bytes, payload fields, the six error codes and their decision order. Frozen. |
| [`spec/testvectors.json`](spec/testvectors.json) | 38 fixed licenses (6 accepted, 32 rejected), signed with a public test-only key. Check any verifier — including your own — against this file; it's also what the copy-paste demo above runs. |
| [`spec/threat-model.md`](spec/threat-model.md) | What the scheme prevents (P1–P4) and what it does not (N1–N5) — binary patching, key sharing, a leaked private key, public-key substitution, a rewound clock — each with its mitigation and the limit of that mitigation. English and Japanese. The same file the paid kit ships. |
| [`verifiers/typescript/licensesmith.ts`](verifiers/typescript/licensesmith.ts) | The complete verifier. One file, one dependency (`@noble/ed25519`). Copy it into your project, or `npm i @licensesmith/verifier` — see [`verifiers/typescript/README.md`](verifiers/typescript/README.md). |
| `verifiers/typescript/{licensesmith.test.ts, verify-cli.ts, package.json, tsconfig.json, LICENSE}` | The verifier's own test suite, a CLI wrapper, and its npm package metadata. |
| [`verifiers/csharp/LicenseSmith.cs`](verifiers/csharp/LicenseSmith.cs) | The complete verifier. One file, one dependency (`BouncyCastle.Cryptography`). Copy it into your project — see [`verifiers/csharp/README.md`](verifiers/csharp/README.md). Also the file to drop into Unity. |
| `verifiers/csharp/{LicenseSmith.csproj, tests/, examples/VerifyCli/}` | The verifier's own test suite (`dotnet test`, xUnit) and an example CLI wrapper. |

## Using the verifier

```ts
import { verifyLicense } from "./licensesmith";

const PUBLIC_KEY = "..."; // 43-char base64url public key
```

`PUBLIC_KEY` is what `licensesmith keygen` prints. This repository verifies against a public key; it
doesn't generate one — keygen, and signing a license with the matching secret, is the issuing side, in
[the full kit](#the-full-kit). To see the verifier run today without one, use the copy-paste demo
above: it hands you a real signed license and the public key that goes with it.

```ts
const result = await verifyLicense(userPastedText, PUBLIC_KEY, { productId: "my-app" });
if (result.ok) unlock(result.payload.feat);
else showError(result.reason);
```

`verifyLicense` never throws for a bad license — it returns `{ ok: false, reason }` with one of six
codes: `malformed`, `unsupported_version`, `bad_signature`, `product_mismatch`, `expired`, `revoked`.
Decision order is normative — see [`spec/key-format.md`](spec/key-format.md).

## Try the C# verifier in Unity

Drop [`verifiers/csharp/LicenseSmith.cs`](verifiers/csharp/LicenseSmith.cs) and BouncyCastle's
`netstandard2.0` DLL into your project's `Assets/` folder (API Compatibility Level ".NET Standard 2.1"),
then call `LicenseVerifier.VerifyLicense(...)` with the public key and one signed license from
[`spec/testvectors.json`](spec/testvectors.json) — see [`verifiers/csharp/README.md`](verifiers/csharp/README.md)
for the exact call.

## What it doesn't do

A signature proves who issued a key and that nobody edited it. It can't stop someone patching the
check out of your binary, and offline there's nothing to compare a shared key against — it can't
count how many machines use one key. The whole list, with the mitigation for each and the limit of
that mitigation, is [`spec/threat-model.md`](spec/threat-model.md) — in this repository, not behind
the purchase.

## Requirements

Runtime: Node ≥20, Bun, Deno, Electron, or a browser. Running `pnpm test` needs Node ≥22.12 (or ≥24,
or ≥26) — that floor comes from vitest 5, not from the verifier itself.

## The full kit

The material above is enough to write your own issuing script if you only ever need to issue a handful
of licenses by hand — `spec/key-format.md` is normative, and `spec/testvectors.json` pins the correct
answer for every field it defines.

Signing a license is the easy part. What the full kit sells is the work that comes after signing:
keeping the private key somewhere safe, issuing a batch of licenses from a sales CSV in one pass instead
of one at a time, keeping a ledger of which license went to which buyer, and producing a revocation list
when a refund comes in. None of that is in the spec, because none of it is part of the key format — it's
the operational side of issuing, and it's what costs more to build yourself than the kit costs to buy,
once you're selling to more than a handful of people.

What's in the full kit:

- The issuing CLI — 7 subcommands, including `keygen`, batch-issuing from a sales CSV, and
  `ledger export-revocations`
- Python and Rust verifiers of the same `LS1` format
- The issuance ledger and revocation tooling
- Sample data and example programs
- A commercial EULA for use in your own paid product
- Japanese-language documentation

One-time purchase, no subscription:

- Gumroad (international, USD) — **$29**: https://colophonapps.gumroad.com/l/licensesmith
- BOOTH (Japan, JPY) — **¥4,500**: https://colophon.booth.pm/items/8836509

This repository is also distributed as a ZIP on BOOTH, free of charge: https://colophon.booth.pm/items/8843410

## License

MIT, for this repository only — all of `spec/` (the key-format spec, the test vectors and the threat
model) and all of `verifiers/typescript/` and `verifiers/csharp/`; see [`LICENSE`](LICENSE). The rest of
the LicenseSmith kit — the issuing CLI, the Python/Rust verifiers, the ledger and revocation tooling, the
sample data and example programs — is under a separate commercial license.

## Security

See [`SECURITY.md`](SECURITY.md).
