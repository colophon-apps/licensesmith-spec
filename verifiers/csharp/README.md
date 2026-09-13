# LicenseSmith — C# verifier

Single-file, offline license-key verifier for the LicenseSmith **`LS1`** key format (Ed25519).
No server, no account, no network call — a license is accepted because its signature checks out on the
user's own machine.

MIT licensed. One dependency: [`BouncyCastle.Cryptography`](https://www.nuget.org/packages/BouncyCastle.Cryptography)
(NuGet, MIT).

## Use

Copy [`LicenseSmith.cs`](LicenseSmith.cs) into your project (namespace `LicenseSmith`) and add the
dependency: `dotnet add package BouncyCastle.Cryptography`.

```csharp
using LicenseSmith;

const string PublicKey = "..."; // base64url, 43 chars — your Ed25519 public key

var result = LicenseVerifier.VerifyLicense(userPastedText, PublicKey,
    new VerifyOptions { ProductId = "my-app" });

if (result.Ok) Unlock(result.Payload.Feat);
else ShowError(result.ReasonCode);
```

`VerifyLicense` never throws for a bad license. It returns a `VerifyResult` whose `ReasonCode` is one of
six strings, decided in this order: `malformed`, `unsupported_version`, `bad_signature`,
`product_mismatch`, `expired`, `revoked`. Options: `ProductId`, `Now` (Unix seconds, for testing;
defaults to the system clock), `RevokedIds`. It throws only for a bug in the calling code — a public key
that is not a valid 43-character base64url Ed25519 key — never for the contents of a license.

**Which TargetFramework?** Any `net8.0` or newer, or `netstandard2.1` (`net48` / `netstandard2.0` compile
too). This is also the file to drop into Unity 2021.3 LTS or newer at the ".NET Standard 2.1" API
compatibility level.

## What it does and does not do

A signature check proves a key was issued by whoever holds the private key, and that nobody edited it
afterwards. It does **not** stop someone patching the check out of your binary, and it does **not**
detect a paying customer sharing their key — offline, there is nothing to compare against. The full
threat model is written down rather than left implied, and it is in the same free, MIT-licensed
repository as this file: [`spec/threat-model.md`](../../spec/threat-model.md).

## Spec and test vectors

The key format is frozen and published: the exact byte layout, the signed bytes, the payload fields and
the error-code decision order are in [`spec/key-format.md`](../../spec/key-format.md), and
[`spec/testvectors.json`](../../spec/testvectors.json) holds 38 fixed licenses (6 accepted, 32 rejected)
that every reference verifier is checked against.

## Tests

```
dotnet test verifiers/csharp/tests
```

(Or, from inside `verifiers/csharp/tests`, just `dotnet test`.) The suite runs every vector in
`spec/testvectors.json` plus API behaviour the vectors don't pin — public-key errors, malformed shapes,
whitespace and prefix handling, error precedence — mirroring `verifiers/typescript/licensesmith.test.ts`.

## Try the example CLI

[`examples/VerifyCli`](examples/VerifyCli) is a minimal command-line checker built on this file:

```
dotnet run --project verifiers/csharp/examples/VerifyCli -- \
  --pub nl0U9R690IJl7QdRkzRnK7l5YB1oNjx-CJPLBEw9wh4 \
  --license - --product demo-app --now 1767225600
```

(paste one of `spec/testvectors.json`'s already-signed licenses on stdin). It prints one JSON line and
exits 0 (ok), 1 (rejected) or 2 (usage error) — the same convention as the TypeScript and other
reference verifiers.

## Try it in Unity

1. Get `BouncyCastle.Cryptography`'s `netstandard2.0` DLL (e.g. from the NuGet package's `lib/netstandard2.0`
   folder) and drop it, along with [`LicenseSmith.cs`](LicenseSmith.cs), into your project's `Assets/` folder.
2. Set the API Compatibility Level to ".NET Standard 2.1" (Player Settings) if it isn't already.
3. Call `LicenseVerifier.VerifyLicense` with the public key and a signed license from
   `spec/testvectors.json` — from an `EditorWindow`, a test, or any `MonoBehaviour` — the same call shown
   above under "Use".

## Issuing keys

This file **verifies** licenses; it does not issue them. Issuing (keypair generation, signing,
batch-issuing from a sales CSV, an issuance ledger and revocation) is part of the full LicenseSmith kit,
together with Python and Rust verifiers of the same format and a commercial license for use in your own
products — see the LicenseSmith product pages linked from the repository README.

## License

MIT — see [`LICENSE`](../../LICENSE) at the repository root.
