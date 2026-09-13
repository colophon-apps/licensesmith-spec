// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Colophon. Licensed under the MIT License — see LICENSE at the repository root.

// This file is nullable-oblivious (C# 7.3 style, no annotations). The directive below keeps it
// warning-free inside projects that enable nullable reference types — the default of every
// `dotnet new` template. It is guarded because `#nullable` is a C# 8 directive: the symbols are
// defined only by SDK-style targets whose default language version is 8 or newer, so a C# 7.3
// compiler (Unity releases before 2020.2, or net48 / netstandard2.0 at their default LangVersion)
// never sees a directive it cannot parse. If you pin LangVersion below 8 on such a target, delete these three lines.
#if NETCOREAPP3_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#nullable disable
#endif
/*
 * LicenseSmith — offline license verifier for the `LS1` key format (Ed25519).
 *
 * This is the whole verifier. Copy this one file into your application.
 *
 * Runtime:       .NET Standard 2.1 or later — .NET 8 / 9 / 10, .NET Core 3.x, Mono, and Unity 2021.3+
 *                with the ".NET Standard 2.1" API compatibility level. Also compiles for .NET Framework
 *                4.6.2+ / .NET Standard 2.0. Exercised on .NET 8, .NET Framework 4.8, the compiler,
 *                Mono runtime and linker bundled with Unity 2022.3, and inside the Unity 2022.3 Editor
 *                and Mono / IL2CPP Windows players. Android, iOS and macOS are untested: see
 *                verifiers/csharp/README.md before relying on it.
 * Language:      C# 7.3 or later. No nullable annotations, records or init-only setters, so the file
 *                compiles under the older compilers that Unity LTS releases ship with.
 * Dependency:    BouncyCastle.Cryptography (NuGet, MIT licence) — nothing else.
 *                  dotnet add package BouncyCastle.Cryptography
 *                The payload JSON parser lives in this file on purpose: .NET Standard 2.1 has no
 *                built-in JSON reader, Unity does not ship System.Text.Json, and plain .NET does not
 *                ship Newtonsoft.Json. One file, one dependency — same rule as the other verifiers.
 * Specification: spec/key-format.md (frozen). Test vectors: spec/testvectors.json.
 *
 * Usage:
 *   using LicenseSmith;
 *
 *   var result = LicenseVerifier.VerifyLicense(licenseText, PUBLIC_KEY, new VerifyOptions { ProductId = "my-app" });
 *   if (result.Ok) UnlockFeatures(result.Payload.Feat);   // e.g. ["pro"]
 *   else ShowError(result.ReasonCode);                     // "expired", "bad_signature", ...
 *
 * What this proves when it says Ok: the license was produced by the holder of your secret key
 * and has not been altered. What it cannot do: stop someone from patching your app so this
 * method is never called, or from sharing a genuine license. Read spec/threat-model.md.
 */

using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace LicenseSmith
{
    /// <summary>
    /// Why a license was rejected. <see cref="VerifyErrorExtensions.Code"/> turns a value into the
    /// same string the TypeScript, Python and Rust verifiers report. See spec §6.
    /// </summary>
    public enum VerifyError
    {
        /// <summary>Structure is wrong: parts, prefix, base64url, JSON shape, required fields.</summary>
        Malformed,
        /// <summary>Prefix is <c>LS&lt;n&gt;</c> with n ≠ 1, or payload <c>v</c> ≠ 1. A newer verifier may accept it.</summary>
        UnsupportedVersion,
        /// <summary>The Ed25519 signature does not verify. Any change to the payload text ends up here.</summary>
        BadSignature,
        /// <summary><see cref="VerifyOptions.ProductId"/> was given and differs from the payload's <c>pid</c>.</summary>
        ProductMismatch,
        /// <summary>The payload has an <c>exp</c> and <c>now ≥ exp</c>.</summary>
        Expired,
        /// <summary>The payload's <c>lid</c> is in <see cref="VerifyOptions.RevokedIds"/>.</summary>
        Revoked,
    }

    public static class VerifyErrorExtensions
    {
        /// <summary>The wire-level error code: "malformed", "unsupported_version", "bad_signature",
        /// "product_mismatch", "expired" or "revoked". Identical strings in every LicenseSmith verifier.</summary>
        public static string Code(this VerifyError error)
        {
            switch (error)
            {
                case VerifyError.Malformed: return "malformed";
                case VerifyError.UnsupportedVersion: return "unsupported_version";
                case VerifyError.BadSignature: return "bad_signature";
                case VerifyError.ProductMismatch: return "product_mismatch";
                case VerifyError.Expired: return "expired";
                case VerifyError.Revoked: return "revoked";
                default: throw new ArgumentOutOfRangeException(nameof(error), error, "unknown VerifyError");
            }
        }
    }

    /// <summary>The decoded, signature-checked payload of a license. See spec §3.</summary>
    public sealed class LicensePayload
    {
        /// <summary>Payload format version, always 1 for LS1.</summary>
        public long V { get; }
        /// <summary>Product ID you chose when issuing, e.g. "my-app".</summary>
        public string Pid { get; }
        /// <summary>License ID, unique per license (UUID v4). Use it for revocation lists.</summary>
        public string Lid { get; }
        /// <summary>Buyer e-mail, or "sha256:&lt;hex&gt;" when hashed at issue time.</summary>
        public string Sub { get; }
        /// <summary>Seats the buyer paid for. Informational — enforcing it is your app's job.</summary>
        public long Seats { get; }
        /// <summary>Issued-at, Unix seconds (UTC).</summary>
        public long Iat { get; }
        /// <summary>Expiry, Unix seconds, or null for perpetual. Checked by <see cref="LicenseVerifier.VerifyLicense"/>.</summary>
        public long? Exp { get; }
        /// <summary>"Updates until", Unix seconds, or null for forever. Informational.</summary>
        public long? Upd { get; }
        /// <summary>Feature flags, e.g. ["pro", "export"].</summary>
        public IReadOnlyList<string> Feat { get; }
        /// <summary>Free-form extra data set at issue time. Values are string, long, double, bool, null,
        /// <see cref="LicenseJsonObject"/> or <c>IReadOnlyList&lt;object&gt;</c>.</summary>
        public LicenseJsonObject Meta { get; }
        /// <summary>Unknown top-level fields, preserved for forward compatibility (spec §3, §10).</summary>
        public LicenseJsonObject Extra { get; }

        internal LicensePayload(long v, string pid, string lid, string sub, long seats, long iat, long? exp, long? upd,
            IReadOnlyList<string> feat, LicenseJsonObject meta, LicenseJsonObject extra)
        {
            V = v; Pid = pid; Lid = lid; Sub = sub; Seats = seats; Iat = iat; Exp = exp; Upd = upd;
            Feat = feat; Meta = meta; Extra = extra;
        }

        /// <summary>
        /// The payload as compact JSON, fields in the issuer's canonical order followed by any extra
        /// fields. Handy for logging and for the example CLI; not needed for verification.
        /// </summary>
        public string ToJson()
        {
            var obj = new LicenseJsonObject();
            obj.Set("v", V);
            obj.Set("pid", Pid);
            obj.Set("lid", Lid);
            obj.Set("sub", Sub);
            obj.Set("seats", Seats);
            obj.Set("iat", Iat);
            obj.Set("exp", Exp.HasValue ? (object)Exp.Value : null);
            obj.Set("upd", Upd.HasValue ? (object)Upd.Value : null);
            var feat = new List<object>(Feat.Count);
            foreach (var f in Feat) feat.Add(f);
            obj.Set("feat", feat);
            obj.Set("meta", Meta);
            foreach (var kv in Extra) obj.Set(kv.Key, kv.Value);
            return LicenseJson.Write(obj);
        }
    }

    /// <summary>Options for <see cref="LicenseVerifier.VerifyLicense"/>. All optional.</summary>
    public sealed class VerifyOptions
    {
        /// <summary>If set, licenses whose <c>pid</c> differs are rejected with <see cref="VerifyError.ProductMismatch"/>. Recommended.</summary>
        public string ProductId { get; set; }
        /// <summary>Current time in Unix seconds. Defaults to the system clock (UTC).</summary>
        public long? Now { get; set; }
        /// <summary>License IDs (<c>lid</c>) that you have revoked.</summary>
        public IEnumerable<string> RevokedIds { get; set; }
    }

    /// <summary>Outcome of a verification: either <see cref="Ok"/> with a <see cref="Payload"/>, or a <see cref="Reason"/>.</summary>
    public sealed class VerifyResult
    {
        public bool Ok { get; }
        /// <summary>The verified payload when <see cref="Ok"/> is true; otherwise null.</summary>
        public LicensePayload Payload { get; }
        /// <summary>
        /// The rejection reason when <see cref="Ok"/> is false; null when Ok is true, so
        /// <c>result.Reason == VerifyError.Malformed</c> is never true for a verified license.
        /// (A <c>Nullable&lt;VerifyError&gt;</c>, available on every supported compiler; comparisons such as
        /// <c>result.Reason == VerifyError.Expired</c> work unchanged.)
        /// </summary>
        public VerifyError? Reason { get; }
        /// <summary>The rejection reason as a string ("expired", ...), or null when <see cref="Ok"/> is true.</summary>
        public string ReasonCode { get { return Reason.HasValue ? Reason.Value.Code() : null; } }

        private VerifyResult(bool ok, LicensePayload payload, VerifyError? reason)
        {
            Ok = ok; Payload = payload; Reason = reason;
        }

        internal static VerifyResult Success(LicensePayload payload) { return new VerifyResult(true, payload, null); }
        internal static VerifyResult Failure(VerifyError reason) { return new VerifyResult(false, null, reason); }
    }

    public static class LicenseVerifier
    {
        public const string Prefix = "LS1";
        private const int SignatureLength = 64;
        private const int PublicKeyLength = 32;
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

        /// <summary>
        /// Verify a LicenseSmith license. Never throws for a bad <em>license</em>; every rejection is a
        /// <see cref="VerifyResult"/> with <c>Ok == false</c>.
        /// </summary>
        /// <param name="licenseText">The license as the user pasted it. Whitespace and line breaks are fine.</param>
        /// <param name="publicKeyBase64Url">Your 43-character public key (from <c>licensesmith keygen</c>).</param>
        /// <param name="options">See <see cref="VerifyOptions"/>. May be null.</param>
        /// <exception cref="ArgumentException">Only if <paramref name="publicKeyBase64Url"/> is not a valid
        /// key — that is a bug in your app, not a property of the license.</exception>
        public static VerifyResult VerifyLicense(string licenseText, string publicKeyBase64Url, VerifyOptions options = null)
        {
            if (licenseText == null) throw new ArgumentNullException(nameof(licenseText));
            if (publicKeyBase64Url == null) throw new ArgumentNullException(nameof(publicKeyBase64Url));
            if (options == null) options = new VerifyOptions();

            // §5 step 1: remove the six ASCII whitespace characters, nothing else.
            string text = StripAsciiWhitespace(licenseText);

            // Step 2: exactly three non-empty parts.
            string[] parts = text.Split('.');
            if (parts.Length != 3 || parts[0].Length == 0 || parts[1].Length == 0 || parts[2].Length == 0)
                return VerifyResult.Failure(VerifyError.Malformed);
            string prefix = parts[0], payloadB64 = parts[1], sigB64 = parts[2];

            // Step 3: prefix.
            if (!string.Equals(prefix, Prefix, StringComparison.Ordinal))
                return VerifyResult.Failure(IsVersionedPrefix(prefix) ? VerifyError.UnsupportedVersion : VerifyError.Malformed);

            // Step 4: signature bytes.
            byte[] sig = Base64Url.Decode(sigB64);
            if (sig == null || sig.Length != SignatureLength) return VerifyResult.Failure(VerifyError.Malformed);

            // Step 5: payload bytes (not parsed yet).
            byte[] payloadBytes = Base64Url.Decode(payloadB64);
            if (payloadBytes == null) return VerifyResult.Failure(VerifyError.Malformed);

            // Step 6: public key. Invalid here means the *application* is misconfigured.
            byte[] publicKey = Base64Url.Decode(publicKeyBase64Url);
            if (publicKey == null || publicKey.Length != PublicKeyLength)
                throw new ArgumentException(
                    "licensesmith: invalid public key - expected the 43-character base64url string printed by `licensesmith keygen`",
                    nameof(publicKeyBase64Url));
            if (!Ed25519.ValidatePublicKeyFull(publicKey, 0)) // rejects byte strings that are not a point on the curve
                throw new ArgumentException("licensesmith: invalid public key - not a valid Ed25519 key", nameof(publicKeyBase64Url));

            // Step 7: signature over the ASCII bytes of "LS1.<payload_b64url>", before parsing anything.
            byte[] signingInput = Encoding.ASCII.GetBytes(prefix + "." + payloadB64); // both parts are validated ASCII
            var signer = new Ed25519Signer();
            signer.Init(false, new Ed25519PublicKeyParameters(publicKey, 0));
            signer.BlockUpdate(signingInput, 0, signingInput.Length);
            if (!signer.VerifySignature(sig)) return VerifyResult.Failure(VerifyError.BadSignature);

            // Step 8: now the bytes are trusted; parse as strict UTF-8 JSON.
            object parsed;
            try
            {
                parsed = LicenseJson.Parse(StrictUtf8.GetString(payloadBytes));
            }
            catch (DecoderFallbackException) { return VerifyResult.Failure(VerifyError.Malformed); }
            catch (LicenseJsonException) { return VerifyResult.Failure(VerifyError.Malformed); }
            var obj = parsed as LicenseJsonObject;
            if (obj == null) return VerifyResult.Failure(VerifyError.Malformed);

            // Step 9: version.
            object vRaw;
            if (!obj.TryGetValue("v", out vRaw) || !(vRaw is long)) return VerifyResult.Failure(VerifyError.Malformed);
            long v = (long)vRaw;
            if (v != 1) return VerifyResult.Failure(VerifyError.UnsupportedVersion);

            // Step 10: required fields and types.
            string pid = GetString(obj, "pid");
            string lid = GetString(obj, "lid");
            string sub = GetString(obj, "sub");
            long seats, iat;
            long? exp, upd;
            IReadOnlyList<string> feat = GetStringArray(obj, "feat");
            LicenseJsonObject meta = GetObject(obj, "meta");
            if (pid == null || lid == null || sub == null ||
                !TryGetNonNegInt(obj, "seats", out seats) ||
                !TryGetNonNegInt(obj, "iat", out iat) ||
                !TryGetNonNegIntOrNull(obj, "exp", out exp) ||
                !TryGetNonNegIntOrNull(obj, "upd", out upd) ||
                feat == null || meta == null)
            {
                return VerifyResult.Failure(VerifyError.Malformed);
            }
            var extra = new LicenseJsonObject();
            foreach (var kv in obj)
            {
                if (!IsKnownField(kv.Key)) extra.Set(kv.Key, kv.Value);
            }
            var payload = new LicensePayload(v, pid, lid, sub, seats, iat, exp, upd, feat, meta, extra);

            // Step 11: product.
            if (options.ProductId != null && !string.Equals(payload.Pid, options.ProductId, StringComparison.Ordinal))
                return VerifyResult.Failure(VerifyError.ProductMismatch);

            // Step 12: expiry. Valid strictly before `exp`.
            long now = options.Now.HasValue ? options.Now.Value : DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (payload.Exp.HasValue && now >= payload.Exp.Value) return VerifyResult.Failure(VerifyError.Expired);

            // Step 13: revocation.
            if (options.RevokedIds != null)
            {
                foreach (var id in options.RevokedIds)
                {
                    if (string.Equals(id, payload.Lid, StringComparison.Ordinal)) return VerifyResult.Failure(VerifyError.Revoked);
                }
            }

            return VerifyResult.Success(payload);
        }

        // Internals. Kept in this file on purpose so the verifier stays a single copy-paste unit.

        private static readonly string[] KnownFields = { "v", "pid", "lid", "sub", "seats", "iat", "exp", "upd", "feat", "meta" };

        private static bool IsKnownField(string key)
        {
            foreach (var k in KnownFields) if (string.Equals(k, key, StringComparison.Ordinal)) return true;
            return false;
        }

        /// <summary>Spec §7: delete exactly space, tab, LF, VT, FF, CR. No other characters.</summary>
        private static string StripAsciiWhitespace(string s)
        {
            var sb = new StringBuilder(s.Length);
            foreach (char c in s)
            {
                if (c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r') continue;
                sb.Append(c);
            }
            return sb.ToString();
        }

        /// <summary>"LS" followed by one or more ASCII digits (spec §5 step 3).</summary>
        private static bool IsVersionedPrefix(string prefix)
        {
            if (prefix.Length < 3 || prefix[0] != 'L' || prefix[1] != 'S') return false;
            for (int i = 2; i < prefix.Length; i++)
            {
                if (prefix[i] < '0' || prefix[i] > '9') return false;
            }
            return true;
        }

        private static string GetString(LicenseJsonObject obj, string key)
        {
            object value;
            return obj.TryGetValue(key, out value) ? value as string : null;
        }

        private static LicenseJsonObject GetObject(LicenseJsonObject obj, string key)
        {
            object value;
            return obj.TryGetValue(key, out value) ? value as LicenseJsonObject : null;
        }

        private static IReadOnlyList<string> GetStringArray(LicenseJsonObject obj, string key)
        {
            object value;
            if (!obj.TryGetValue(key, out value)) return null;
            var list = value as IReadOnlyList<object>;
            if (list == null) return null;
            var result = new List<string>(list.Count);
            foreach (var item in list)
            {
                var s = item as string;
                if (s == null) return null;
                result.Add(s);
            }
            return result;
        }

        private static bool TryGetNonNegInt(LicenseJsonObject obj, string key, out long value)
        {
            value = 0;
            object raw;
            if (!obj.TryGetValue(key, out raw) || !(raw is long)) return false;
            value = (long)raw;
            return value >= 0;
        }

        private static bool TryGetNonNegIntOrNull(LicenseJsonObject obj, string key, out long? value)
        {
            value = null;
            object raw;
            if (!obj.TryGetValue(key, out raw)) return false;
            if (raw == null) return true;
            if (!(raw is long) || (long)raw < 0) return false;
            value = (long)raw;
            return true;
        }
    }

    /// <summary>base64url without padding (RFC 4648 §5), strict as defined in spec §8.</summary>
    public static class Base64Url
    {
        private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        private static readonly sbyte[] Lookup = BuildLookup();

        private static sbyte[] BuildLookup()
        {
            var t = new sbyte[128];
            for (int i = 0; i < t.Length; i++) t[i] = -1;
            for (int i = 0; i < Alphabet.Length; i++) t[Alphabet[i]] = (sbyte)i;
            return t;
        }

        public static string Encode(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            var sb = new StringBuilder((bytes.Length * 4 + 2) / 3);
            int i = 0;
            for (; i + 2 < bytes.Length; i += 3)
            {
                int n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
                sb.Append(Alphabet[(n >> 18) & 63]).Append(Alphabet[(n >> 12) & 63]).Append(Alphabet[(n >> 6) & 63]).Append(Alphabet[n & 63]);
            }
            int rem = bytes.Length - i;
            if (rem == 1)
            {
                int n = bytes[i] << 16;
                sb.Append(Alphabet[(n >> 18) & 63]).Append(Alphabet[(n >> 12) & 63]);
            }
            else if (rem == 2)
            {
                int n = (bytes[i] << 16) | (bytes[i + 1] << 8);
                sb.Append(Alphabet[(n >> 18) & 63]).Append(Alphabet[(n >> 12) & 63]).Append(Alphabet[(n >> 6) & 63]);
            }
            return sb.ToString();
        }

        /// <summary>
        /// Strict decode: alphabet only, no padding, length % 4 != 1, canonical (re-encoding must reproduce
        /// the input). Returns null for anything invalid, including the empty string.
        /// </summary>
        public static byte[] Decode(string s)
        {
            if (s == null) throw new ArgumentNullException(nameof(s));
            int len = s.Length;
            if (len == 0 || len % 4 == 1) return null;
            var output = new byte[(len * 3) / 4];
            int buffer = 0, bits = 0, o = 0;
            for (int i = 0; i < len; i++)
            {
                char c = s[i];
                int v = c < 128 ? Lookup[c] : -1;
                if (v < 0) return null;
                buffer = (buffer << 6) | v;
                bits += 6;
                if (bits >= 8)
                {
                    bits -= 8;
                    output[o++] = (byte)((buffer >> bits) & 0xff);
                }
            }
            // Canonical check: re-encoding must reproduce the input exactly (rejects non-zero trailing bits).
            if (!string.Equals(Encode(output), s, StringComparison.Ordinal)) return null;
            return output;
        }
    }

    /// <summary>Thrown by <see cref="LicenseJson.Parse"/> for text that is not valid JSON. Caught inside the verifier.</summary>
    public sealed class LicenseJsonException : Exception
    {
        public LicenseJsonException(string message) : base(message) { }
    }

    /// <summary>
    /// A JSON object that remembers key order. Values are null, bool, long, double, string,
    /// <see cref="LicenseJsonObject"/> or <c>IReadOnlyList&lt;object&gt;</c>.
    /// </summary>
    public sealed class LicenseJsonObject : IReadOnlyDictionary<string, object>
    {
        private readonly List<string> _keys = new List<string>();
        private readonly Dictionary<string, object> _values = new Dictionary<string, object>(StringComparer.Ordinal);

        public int Count { get { return _keys.Count; } }
        public IEnumerable<string> Keys { get { return _keys; } }
        public IEnumerable<object> Values { get { foreach (var k in _keys) yield return _values[k]; } }
        public object this[string key] { get { return _values[key]; } }
        public bool ContainsKey(string key) { return _values.ContainsKey(key); }
        public bool TryGetValue(string key, out object value) { return _values.TryGetValue(key, out value); }

        /// <summary>Insert or replace. A replaced key keeps its original position (JSON duplicate keys: last value wins).</summary>
        public void Set(string key, object value)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (!_values.ContainsKey(key)) _keys.Add(key);
            _values[key] = value;
        }

        public IEnumerator<KeyValuePair<string, object>> GetEnumerator()
        {
            foreach (var k in _keys) yield return new KeyValuePair<string, object>(k, _values[k]);
        }

        IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
    }

    /// <summary>
    /// Minimal strict JSON reader/writer (RFC 8259) for the license payload. Not a general-purpose
    /// JSON library: it exists so the verifier has no dependency beyond BouncyCastle.
    /// Numbers without a fraction or exponent that fit in Int64 become <c>long</c>; every other number
    /// becomes <c>double</c> (and therefore fails the verifier's integer checks — spec §11).
    /// </summary>
    public static class LicenseJson
    {
        /// <summary>Nesting deeper than this is rejected (a license payload is a few levels deep at most).</summary>
        public const int MaxDepth = 64;

        public static object Parse(string text)
        {
            if (text == null) throw new ArgumentNullException(nameof(text));
            var p = new Parser(text);
            p.SkipWhitespace();
            object value = p.ParseValue(0);
            p.SkipWhitespace();
            if (!p.AtEnd) throw p.Error("unexpected characters after the JSON value");
            return value;
        }

        public static string Write(object value)
        {
            var sb = new StringBuilder();
            WriteValue(sb, value);
            return sb.ToString();
        }

        private static void WriteValue(StringBuilder sb, object value)
        {
            if (value == null) { sb.Append("null"); return; }
            if (value is bool) { sb.Append((bool)value ? "true" : "false"); return; }
            if (value is long) { sb.Append(((long)value).ToString(CultureInfo.InvariantCulture)); return; }
            if (value is int) { sb.Append(((int)value).ToString(CultureInfo.InvariantCulture)); return; }
            if (value is double)
            {
                double d = (double)value;
                // JSON has no NaN/Infinity. The reader turns an out-of-range literal such as 1e400 into
                // Infinity, and a correctly signed license may carry one in `meta`; write it as null —
                // what JSON.stringify does in the other verifiers — instead of throwing from ToJson().
                if (double.IsNaN(d) || double.IsInfinity(d)) { sb.Append("null"); return; }
                sb.Append(d.ToString("R", CultureInfo.InvariantCulture));
                return;
            }
            var s = value as string;
            if (s != null) { WriteString(sb, s); return; }
            var dict = value as IReadOnlyDictionary<string, object>;
            if (dict != null)
            {
                sb.Append('{');
                bool first = true;
                foreach (var kv in dict)
                {
                    if (!first) sb.Append(',');
                    first = false;
                    WriteString(sb, kv.Key);
                    sb.Append(':');
                    WriteValue(sb, kv.Value);
                }
                sb.Append('}');
                return;
            }
            var seq = value as IEnumerable;
            if (seq != null)
            {
                sb.Append('[');
                bool first = true;
                foreach (var item in seq)
                {
                    if (!first) sb.Append(',');
                    first = false;
                    WriteValue(sb, item);
                }
                sb.Append(']');
                return;
            }
            throw new LicenseJsonException("cannot write a value of type " + value.GetType().FullName + " as JSON");
        }

        private static void WriteString(StringBuilder sb, string s)
        {
            sb.Append('"');
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                        else sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
        }

        private sealed class Parser
        {
            private readonly string _s;
            private int _i;

            public Parser(string s) { _s = s; _i = 0; }

            public bool AtEnd { get { return _i >= _s.Length; } }

            public LicenseJsonException Error(string message)
            {
                return new LicenseJsonException(message + " at offset " + _i.ToString(CultureInfo.InvariantCulture));
            }

            public void SkipWhitespace()
            {
                while (_i < _s.Length)
                {
                    char c = _s[_i];
                    if (c == ' ' || c == '\t' || c == '\n' || c == '\r') _i++;
                    else break;
                }
            }

            private char Peek()
            {
                if (_i >= _s.Length) throw Error("unexpected end of JSON");
                return _s[_i];
            }

            private void Expect(char c)
            {
                if (Peek() != c) throw Error("expected '" + c + "'");
                _i++;
            }

            public object ParseValue(int depth)
            {
                if (depth > MaxDepth) throw Error("JSON nested too deeply");
                char c = Peek();
                switch (c)
                {
                    case '{': return ParseObject(depth + 1);
                    case '[': return ParseArray(depth + 1);
                    case '"': return ParseString();
                    case 't': ExpectLiteral("true"); return true;
                    case 'f': ExpectLiteral("false"); return false;
                    case 'n': ExpectLiteral("null"); return null;
                    default:
                        if (c == '-' || (c >= '0' && c <= '9')) return ParseNumber();
                        throw Error("unexpected character '" + c + "'");
                }
            }

            private void ExpectLiteral(string literal)
            {
                if (string.CompareOrdinal(_s, _i, literal, 0, literal.Length) != 0) throw Error("invalid literal");
                _i += literal.Length;
            }

            private LicenseJsonObject ParseObject(int depth)
            {
                Expect('{');
                var obj = new LicenseJsonObject();
                SkipWhitespace();
                if (Peek() == '}') { _i++; return obj; }
                while (true)
                {
                    SkipWhitespace();
                    if (Peek() != '"') throw Error("expected a string key");
                    string key = ParseString();
                    SkipWhitespace();
                    Expect(':');
                    SkipWhitespace();
                    object value = ParseValue(depth);
                    obj.Set(key, value);
                    SkipWhitespace();
                    char c = Peek();
                    if (c == ',') { _i++; continue; }
                    if (c == '}') { _i++; return obj; }
                    throw Error("expected ',' or '}'");
                }
            }

            private IReadOnlyList<object> ParseArray(int depth)
            {
                Expect('[');
                var list = new List<object>();
                SkipWhitespace();
                if (Peek() == ']') { _i++; return list; }
                while (true)
                {
                    SkipWhitespace();
                    list.Add(ParseValue(depth));
                    SkipWhitespace();
                    char c = Peek();
                    if (c == ',') { _i++; continue; }
                    if (c == ']') { _i++; return list; }
                    throw Error("expected ',' or ']'");
                }
            }

            private string ParseString()
            {
                Expect('"');
                var sb = new StringBuilder();
                while (true)
                {
                    char c = Peek();
                    _i++;
                    if (c == '"') return sb.ToString();
                    if (c < 0x20) throw Error("control character in string");
                    if (c != '\\') { sb.Append(c); continue; }
                    char e = Peek();
                    _i++;
                    switch (e)
                    {
                        case '"': sb.Append('"'); break;
                        case '\\': sb.Append('\\'); break;
                        case '/': sb.Append('/'); break;
                        case 'b': sb.Append('\b'); break;
                        case 'f': sb.Append('\f'); break;
                        case 'n': sb.Append('\n'); break;
                        case 'r': sb.Append('\r'); break;
                        case 't': sb.Append('\t'); break;
                        case 'u':
                            if (_i + 4 > _s.Length) throw Error("truncated \\u escape");
                            int code = 0;
                            for (int k = 0; k < 4; k++)
                            {
                                int h = HexValue(_s[_i + k]);
                                if (h < 0) throw Error("invalid \\u escape");
                                code = (code << 4) | h;
                            }
                            _i += 4;
                            sb.Append((char)code); // UTF-16 code unit; surrogate pairs arrive as two escapes and combine naturally
                            break;
                        default: throw Error("invalid escape sequence");
                    }
                }
            }

            private static int HexValue(char c)
            {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            }

            private object ParseNumber()
            {
                int start = _i;
                bool isInteger = true;
                if (Peek() == '-') _i++;
                char c = Peek();
                if (c == '0') { _i++; }
                else if (c >= '1' && c <= '9') { while (_i < _s.Length && _s[_i] >= '0' && _s[_i] <= '9') _i++; }
                else throw Error("invalid number");
                if (_i < _s.Length && _s[_i] == '.')
                {
                    isInteger = false;
                    _i++;
                    if (_i >= _s.Length || _s[_i] < '0' || _s[_i] > '9') throw Error("invalid number: digits expected after '.'");
                    while (_i < _s.Length && _s[_i] >= '0' && _s[_i] <= '9') _i++;
                }
                if (_i < _s.Length && (_s[_i] == 'e' || _s[_i] == 'E'))
                {
                    isInteger = false;
                    _i++;
                    if (_i < _s.Length && (_s[_i] == '+' || _s[_i] == '-')) _i++;
                    if (_i >= _s.Length || _s[_i] < '0' || _s[_i] > '9') throw Error("invalid number: digits expected in exponent");
                    while (_i < _s.Length && _s[_i] >= '0' && _s[_i] <= '9') _i++;
                }
                string token = _s.Substring(start, _i - start);
                if (isInteger)
                {
                    long l;
                    if (long.TryParse(token, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out l)) return l;
                    // Does not fit in Int64: keep it as a double so it fails the verifier's integer checks (spec §3).
                }
                double d;
                if (!double.TryParse(token, NumberStyles.Float, CultureInfo.InvariantCulture, out d)) throw Error("invalid number");
                return d;
            }
        }
    }
}
