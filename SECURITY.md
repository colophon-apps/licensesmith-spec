# Security policy

Covers this repository: the `LS1` key-format spec, the test vectors, and the TypeScript and C# verifiers
(version 1.1.0). The same crypto scheme underlies the paid kit's Python/Rust verifiers and issuing CLI,
so a report here may apply to those too.

## Reporting a vulnerability

Email **colophon.apps@gmail.com** with a description and, if you have one, a
minimal reproduction (e.g. a crafted license string against `spec/testvectors.json`'s format).
Please don't open a public issue for an unpatched signature-verification or key-forgery bug.

Best-effort response within 5 business days; no guaranteed fix timeline.

## Scope

In scope: the verifier's signature/decision logic, and the key-format spec itself.
Out of scope: your own key-management practices, and anything already documented as a known
limitation in [`spec/threat-model.md`](spec/threat-model.md) (e.g. offline license sharing is not
detectable — that's by design, not a vulnerability).
