// Copyright (c) 2026 Colophon. Licensed under the MIT License — see LICENSE at the repository root.

// Tests for verifiers/csharp/LicenseSmith.cs.
//
//   1. Every vector in spec/testvectors.json (the file is linked into the test output directory).
//   2. API behaviour that the vectors do not pin, mirroring verifiers/typescript/licensesmith.test.ts:
//      public-key errors throw, unknown fields survive, wrong shapes are `malformed`, the signature is
//      checked before the product ID, whitespace handling, prefix/version handling, error precedence.
//   3. The embedded JSON reader, because the other verifiers get theirs from a library and this one
//      does not.
//
// Licenses for the "API behaviour" tests are signed here with the TEST-ONLY seed from the vector file,
// exactly the way the issuing CLI signs (Ed25519 over the ASCII bytes of "LS1.<payload_b64url>").

using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using LicenseSmith;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Xunit;

namespace LicenseSmith.Tests;

public static class Vectors
{
    public static readonly JsonDocument Doc = JsonDocument.Parse(
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "testvectors.json")));

    public static string PublicKey => Doc.RootElement.GetProperty("keypair").GetProperty("publicKeyB64Url").GetString()!;
    public static byte[] Seed => Base64Url.Decode(Doc.RootElement.GetProperty("keypair").GetProperty("seedB64Url").GetString()!)!;
    public static long Now => Doc.RootElement.GetProperty("now").GetInt64();

    public static JsonElement Vector(string id)
    {
        foreach (var v in Doc.RootElement.GetProperty("vectors").EnumerateArray())
            if (v.GetProperty("id").GetString() == id) return v;
        throw new InvalidOperationException("no vector " + id);
    }

    /// <summary>Sign an arbitrary payload string with the TEST-ONLY seed, exactly like the issuer does.</summary>
    public static string SignRaw(string payloadJson, string prefix = "LS1") =>
        SignBytes(Encoding.UTF8.GetBytes(payloadJson), prefix);

    public static string SignBytes(byte[] payloadBytes, string prefix = "LS1")
    {
        string pb = Base64Url.Encode(payloadBytes);
        byte[] msg = Encoding.ASCII.GetBytes(prefix + "." + pb);
        var signer = new Ed25519Signer();
        signer.Init(true, new Ed25519PrivateKeyParameters(Seed, 0));
        signer.BlockUpdate(msg, 0, msg.Length);
        return prefix + "." + pb + "." + Base64Url.Encode(signer.GenerateSignature());
    }

    /// <summary>A valid payload as a mutable JSON node (System.Text.Json.Nodes keeps number text verbatim,
    /// so a test can write "1.0" and get "1.0" on the wire).</summary>
    public static JsonObject BasePayload() => new()
    {
        ["v"] = 1,
        ["pid"] = "demo-app",
        ["lid"] = "11111111-2222-4333-8444-555555555555",
        ["sub"] = "buyer@example.com",
        ["seats"] = 1,
        ["iat"] = Now - 1000,
        ["exp"] = null,
        ["upd"] = null,
        ["feat"] = new JsonArray(),
        ["meta"] = new JsonObject(),
    };

    /// <summary>Canonical text (sorted keys, compact) so payloads from different sources can be compared.</summary>
    public static string Canon(JsonElement e)
    {
        switch (e.ValueKind)
        {
            case JsonValueKind.Object:
                var props = e.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal)
                    .Select(p => JsonSerializer.Serialize(p.Name) + ":" + Canon(p.Value));
                return "{" + string.Join(",", props) + "}";
            case JsonValueKind.Array:
                return "[" + string.Join(",", e.EnumerateArray().Select(Canon)) + "]";
            case JsonValueKind.String:
                return JsonSerializer.Serialize(e.GetString());
            default:
                return e.GetRawText();
        }
    }

    public static string Canon(string json) => Canon(JsonDocument.Parse(json).RootElement);
}

public class SpecVectorTests
{
    public static IEnumerable<object[]> Ids() =>
        Vectors.Doc.RootElement.GetProperty("vectors").EnumerateArray().Select(v => new object[] { v.GetProperty("id").GetString()! });

    [Theory]
    [MemberData(nameof(Ids))]
    public void Vector(string id)
    {
        var v = Vectors.Vector(id);
        var o = v.GetProperty("options");
        var opts = new VerifyOptions();
        if (o.TryGetProperty("productId", out var pid)) opts.ProductId = pid.GetString();
        if (o.TryGetProperty("now", out var now)) opts.Now = now.GetInt64();
        if (o.TryGetProperty("revokedIds", out var rev)) opts.RevokedIds = rev.EnumerateArray().Select(x => x.GetString()!).ToList();

        var result = LicenseVerifier.VerifyLicense(v.GetProperty("license").GetString()!, Vectors.PublicKey, opts);
        var expect = v.GetProperty("expect");
        if (expect.GetProperty("ok").GetBoolean())
        {
            Assert.True(result.Ok, $"{id}: expected ok, got {result.ReasonCode}");
            Assert.Null(result.ReasonCode);
            Assert.Equal(Vectors.Canon(expect.GetProperty("payload")), Vectors.Canon(result.Payload.ToJson()));
        }
        else
        {
            Assert.False(result.Ok, $"{id}: expected {expect.GetProperty("reason").GetString()}, got ok");
            Assert.Null(result.Payload);
            Assert.Equal(expect.GetProperty("reason").GetString(), result.ReasonCode);
        }
    }

    [Fact]
    public void AllSixErrorCodesAreCoveredByTheVectorFile()
    {
        var reasons = Vectors.Doc.RootElement.GetProperty("vectors").EnumerateArray()
            .Select(v => v.GetProperty("expect"))
            .Where(e => !e.GetProperty("ok").GetBoolean())
            .Select(e => e.GetProperty("reason").GetString())
            .ToHashSet();
        foreach (VerifyError err in Enum.GetValues(typeof(VerifyError)))
            Assert.Contains(err.Code(), reasons);
    }
}

public class ApiBehaviourTests
{
    private static readonly string PK = Vectors.PublicKey;
    private static readonly string Perpetual = Vectors.Vector("valid-perpetual").GetProperty("license").GetString()!;

    [Fact]
    public void DefaultsNowToTheSystemClock()
    {
        var result = LicenseVerifier.VerifyLicense(Perpetual, PK, new VerifyOptions { ProductId = "demo-app" });
        Assert.True(result.Ok);
        Assert.True(LicenseVerifier.VerifyLicense(Perpetual, PK).Ok); // options may be omitted entirely
    }

    [Fact]
    public void ThrowsWhenThePublicKeyHasTheWrongLength()
    {
        var ex = Assert.Throws<ArgumentException>(() => LicenseVerifier.VerifyLicense(Perpetual, "abc"));
        Assert.Contains("public key", ex.Message);
    }

    [Fact]
    public void ThrowsWhenThePublicKeyIsPaddedOrContainsForeignCharacters()
    {
        Assert.Throws<ArgumentException>(() => LicenseVerifier.VerifyLicense(Perpetual, PK + "="));
        Assert.Throws<ArgumentException>(() => LicenseVerifier.VerifyLicense(Perpetual, PK.Substring(0, 42) + "+"));
    }

    [Fact]
    public void ThrowsWhenThePublicKeyIsNotAPointOnTheCurve()
    {
        var bytes = new byte[32];
        for (int i = 0; i < bytes.Length; i++) bytes[i] = 0xff; // y >= p: not a canonical point encoding
        var ex = Assert.Throws<ArgumentException>(() => LicenseVerifier.VerifyLicense(Perpetual, Base64Url.Encode(bytes)));
        Assert.Contains("Ed25519", ex.Message);
    }

    [Fact]
    public void ThrowsForNullArguments()
    {
        Assert.Throws<ArgumentNullException>(() => LicenseVerifier.VerifyLicense(null!, PK));
        Assert.Throws<ArgumentNullException>(() => LicenseVerifier.VerifyLicense(Perpetual, null!));
    }

    [Fact]
    public void PreservesUnknownExtraPayloadFields()
    {
        var p = Vectors.BasePayload();
        p["future"] = new JsonObject { ["x"] = 1 };
        var result = LicenseVerifier.VerifyLicense(Vectors.SignRaw(p.ToJsonString()), PK, new VerifyOptions { Now = Vectors.Now });
        Assert.True(result.Ok);
        var future = Assert.IsType<LicenseJsonObject>(result.Payload.Extra["future"]);
        Assert.Equal(1L, future["x"]);
        Assert.Equal(Vectors.Canon(p.ToJsonString()), Vectors.Canon(result.Payload.ToJson()));
    }

    [Fact]
    public void MalformedForACorrectlySignedPayloadThatIsNotAnObject()
    {
        Assert.Equal("malformed", LicenseVerifier.VerifyLicense(Vectors.SignRaw("[1,2,3]"), PK).ReasonCode);
        Assert.Equal("malformed", LicenseVerifier.VerifyLicense(Vectors.SignRaw("\"just a string\""), PK).ReasonCode);
        Assert.Equal("malformed", LicenseVerifier.VerifyLicense(Vectors.SignRaw("null"), PK).ReasonCode);
    }

    [Theory]
    [InlineData("seats", "\"1\"")]
    [InlineData("seats", "-1")]
    [InlineData("seats", "1.0")]      // spec §3: an integer has no fraction; all four verifiers agree
    [InlineData("iat", "1e3")]
    [InlineData("feat", "[\"a\",1]")]
    [InlineData("meta", "[]")]
    [InlineData("exp", "\"never\"")]
    [InlineData("exp", "-5")]
    [InlineData("v", "\"1\"")]
    [InlineData("v", "1.0")]
    [InlineData("pid", "42")]
    [InlineData("sub", "null")]
    public void MalformedForACorrectlySignedPayloadWithAWrongFieldType(string field, string rawJsonValue)
    {
        var p = Vectors.BasePayload();
        p[field] = JsonNode.Parse(rawJsonValue);
        string json = p.ToJsonString();
        Assert.Contains(rawJsonValue, json); // the wire text really carries the odd spelling
        Assert.Equal("malformed", LicenseVerifier.VerifyLicense(Vectors.SignRaw(json), PK).ReasonCode);
    }

    [Theory]
    [InlineData("v")]
    [InlineData("pid")]
    [InlineData("lid")]
    [InlineData("sub")]
    [InlineData("seats")]
    [InlineData("iat")]
    [InlineData("exp")]
    [InlineData("upd")]
    [InlineData("feat")]
    [InlineData("meta")]
    public void MalformedWhenARequiredFieldIsMissing(string field)
    {
        var p = Vectors.BasePayload();
        Assert.True(p.Remove(field));
        Assert.Equal("malformed", LicenseVerifier.VerifyLicense(Vectors.SignRaw(p.ToJsonString()), PK).ReasonCode);
    }

    [Fact]
    public void MalformedForInvalidJsonAndInvalidUtf8EvenWhenCorrectlySigned()
    {
        Assert.Equal("malformed", LicenseVerifier.VerifyLicense(Vectors.SignRaw("{not json"), PK).ReasonCode);
        Assert.Equal("malformed", LicenseVerifier.VerifyLicense(Vectors.SignBytes(new byte[] { 0xff, 0xfe, 0x7b, 0x7d }), PK).ReasonCode);
        // A UTF-8 BOM in front of the JSON is rejected, like the Python and Rust verifiers do.
        var bom = new byte[] { 0xef, 0xbb, 0xbf }.Concat(Encoding.UTF8.GetBytes(Vectors.BasePayload().ToJsonString())).ToArray();
        Assert.Equal("malformed", LicenseVerifier.VerifyLicense(Vectors.SignBytes(bom), PK).ReasonCode);
    }

    [Fact]
    public void ReasonIsNullOnSuccessAndTheEnumValueOnFailure()
    {
        // A non-nullable Reason defaulted to Malformed on success, so `result.Reason == VerifyError.Malformed`
        // misreported a verified license (A2-16).
        var ok = LicenseVerifier.VerifyLicense(Perpetual, PK, new VerifyOptions { Now = Vectors.Now });
        Assert.True(ok.Ok);
        Assert.Null(ok.Reason);
        Assert.Null(ok.ReasonCode);
        Assert.False(ok.Reason == VerifyError.Malformed);

        var p = Vectors.BasePayload();
        p["exp"] = Vectors.Now - 1;
        var expired = LicenseVerifier.VerifyLicense(Vectors.SignRaw(p.ToJsonString()), PK, new VerifyOptions { Now = Vectors.Now });
        Assert.False(expired.Ok);
        Assert.Equal((VerifyError?)VerifyError.Expired, expired.Reason);
        Assert.True(expired.Reason == VerifyError.Expired);
        Assert.Equal("expired", expired.ReasonCode);
    }

    [Fact]
    public void ToJsonDoesNotThrowForANonFiniteNumberInMeta()
    {
        // 1e400 parses as Infinity; the license is still correctly signed and valid (A2-05). The other
        // verifiers serialise it as null (JSON.stringify), and so does ToJson().
        string json = Vectors.BasePayload().ToJsonString().Replace("\"meta\":{}", "\"meta\":{\"x\":1e400,\"y\":-1e400,\"z\":1.5}");
        var result = LicenseVerifier.VerifyLicense(Vectors.SignRaw(json), PK, new VerifyOptions { Now = Vectors.Now });
        Assert.True(result.Ok, result.ReasonCode);
        Assert.Equal(double.PositiveInfinity, (double)result.Payload.Meta["x"]);
        string written = result.Payload.ToJson();
        Assert.Contains("\"meta\":{\"x\":null,\"y\":null,\"z\":1.5}", written);
        Assert.NotNull(LicenseJson.Parse(written));
    }

    [Fact]
    public void ChecksTheSignatureBeforeTheProductId()
    {
        var parts = Perpetual.Split('.');
        var p = Vectors.BasePayload();
        p["pid"] = "other-app";
        string tampered = Base64Url.Encode(Encoding.UTF8.GetBytes(p.ToJsonString()));
        var result = LicenseVerifier.VerifyLicense(parts[0] + "." + tampered + "." + parts[2], PK, new VerifyOptions { ProductId = "demo-app" });
        Assert.Equal("bad_signature", result.ReasonCode);
    }

    [Fact]
    public void RemovesExactlyTheSixAsciiWhitespaceCharacters()
    {
        string spaced = " \t" + Perpetual.Substring(0, 10) + "\r\n" + Perpetual.Substring(10, 50) + "\v\f" + Perpetual.Substring(60) + "\n";
        Assert.True(LicenseVerifier.VerifyLicense(spaced, PK, new VerifyOptions { Now = Vectors.Now }).Ok);
        // Unicode whitespace is not removed, so it lands in the base64url alphabet check.
        Assert.Equal("malformed", LicenseVerifier.VerifyLicense(Perpetual.Substring(0, 10) + "\u00a0" + Perpetual.Substring(10), PK).ReasonCode);
    }

    [Theory]
    [InlineData("LS2", "unsupported_version")]
    [InlineData("LS10", "unsupported_version")]
    [InlineData("LS0", "unsupported_version")]
    [InlineData("ls1", "malformed")]
    [InlineData("LS", "malformed")]
    [InlineData("LS1x", "malformed")]
    [InlineData("XS1", "malformed")]
    public void PrefixHandling(string prefix, string expected)
    {
        var parts = Perpetual.Split('.');
        Assert.Equal(expected, LicenseVerifier.VerifyLicense(prefix + "." + parts[1] + "." + parts[2], PK).ReasonCode);
    }

    [Fact]
    public void PayloadVersionOtherThanOneIsUnsupported()
    {
        var p = Vectors.BasePayload();
        p["v"] = 2;
        Assert.Equal("unsupported_version", LicenseVerifier.VerifyLicense(Vectors.SignRaw(p.ToJsonString()), PK).ReasonCode);
    }

    [Theory]
    [InlineData("LS1.abc")]                    // two parts
    [InlineData("LS1.abc.def.ghi")]            // four parts
    [InlineData("LS1..def")]                   // empty payload
    [InlineData("LS1.abc.")]                   // empty signature
    [InlineData("")]                           // nothing
    public void MalformedStructure(string text)
    {
        Assert.Equal("malformed", LicenseVerifier.VerifyLicense(text, PK).ReasonCode);
    }

    [Fact]
    public void MalformedForNonStrictBase64UrlInEitherPart()
    {
        var parts = Perpetual.Split('.');
        // 63-byte signature (well-formed base64url, wrong length)
        Assert.Equal("malformed", LicenseVerifier.VerifyLicense(parts[0] + "." + parts[1] + "." + Base64Url.Encode(new byte[63]), PK).ReasonCode);
        // standard base64 alphabet
        Assert.Equal("malformed", LicenseVerifier.VerifyLicense(parts[0] + "." + parts[1] + "." + parts[2].Substring(0, 85) + "+", PK).ReasonCode);
        // non-canonical trailing bits in the payload: rejected as malformed, not bad_signature, because
        // strict base64url is checked before the signature. Needs a payload whose base64url length is not a
        // multiple of 4, i.e. whose last character has unused low bits; pad the JSON with spaces until so.
        string json = Vectors.BasePayload().ToJsonString();
        while (Encoding.UTF8.GetByteCount(json) % 3 == 0) json += " ";
        string lic = Vectors.SignRaw(json);
        var lp = lic.Split('.');
        Assert.True(LicenseVerifier.VerifyLicense(lic, PK).Ok);
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        string payload = lp[1];
        char last = payload[payload.Length - 1];
        char bumpedLast = alphabet[alphabet.IndexOf(last) | 1]; // sets an unused trailing bit; decoded bytes are unchanged
        string bumped = payload.Substring(0, payload.Length - 1) + bumpedLast;
        Assert.NotEqual(payload, bumped);
        Assert.Equal("malformed", LicenseVerifier.VerifyLicense(lp[0] + "." + bumped + "." + lp[2], PK).ReasonCode);
    }

    [Fact]
    public void ExpiryIsExclusiveAndRevocationComesAfterIt()
    {
        var p = Vectors.BasePayload();
        p["exp"] = Vectors.Now + 100;
        string lic = Vectors.SignRaw(p.ToJsonString());
        Assert.True(LicenseVerifier.VerifyLicense(lic, PK, new VerifyOptions { Now = Vectors.Now + 99 }).Ok);
        Assert.Equal("expired", LicenseVerifier.VerifyLicense(lic, PK, new VerifyOptions { Now = Vectors.Now + 100 }).ReasonCode);
        var revoked = new VerifyOptions { Now = Vectors.Now + 100, RevokedIds = new[] { p["lid"]!.GetValue<string>() } };
        Assert.Equal("expired", LicenseVerifier.VerifyLicense(lic, PK, revoked).ReasonCode);
        revoked.Now = Vectors.Now;
        Assert.Equal("revoked", LicenseVerifier.VerifyLicense(lic, PK, revoked).ReasonCode);
    }

    [Fact]
    public void ProductMismatchComesBeforeExpiry()
    {
        var p = Vectors.BasePayload();
        p["exp"] = Vectors.Now - 1;
        string lic = Vectors.SignRaw(p.ToJsonString());
        Assert.Equal("product_mismatch", LicenseVerifier.VerifyLicense(lic, PK, new VerifyOptions { ProductId = "x", Now = Vectors.Now }).ReasonCode);
        Assert.Equal("expired", LicenseVerifier.VerifyLicense(lic, PK, new VerifyOptions { Now = Vectors.Now }).ReasonCode);
    }

    [Fact]
    public void DuplicateKeysLastValueWinsLikeTheOtherVerifiers()
    {
        string json = "{\"v\":1,\"pid\":\"demo-app\",\"lid\":\"L\",\"sub\":\"s\",\"seats\":1,\"seats\":7,\"iat\":1,\"exp\":null,\"upd\":null,\"feat\":[],\"meta\":{}}";
        var result = LicenseVerifier.VerifyLicense(Vectors.SignRaw(json), PK);
        Assert.True(result.Ok);
        Assert.Equal(7L, result.Payload.Seats);
    }

    [Fact]
    public void Rfc8032TestVector1VerifiesThroughTheSameLibraryCall()
    {
        // RFC 8032 §7.1 TEST 1: empty message. Proves the dependency implements Ed25519 as specified.
        byte[] pk = Convert.FromHexString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        byte[] sig = Convert.FromHexString("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        var signer = new Ed25519Signer();
        signer.Init(false, new Ed25519PublicKeyParameters(pk, 0));
        Assert.True(signer.VerifySignature(sig));
        sig[0] ^= 1;
        signer.Reset();
        Assert.False(signer.VerifySignature(sig));
    }
}

public class JsonReaderTests
{
    [Theory]
    [InlineData("01")]
    [InlineData("1.")]
    [InlineData(".5")]
    [InlineData("1e")]
    [InlineData("+1")]
    [InlineData("-")]
    [InlineData("[1,]")]
    [InlineData("{\"a\":1,}")]
    [InlineData("{a:1}")]
    [InlineData("{\"a\" 1}")]
    [InlineData("\"unterminated")]
    [InlineData("\"tab\there\"")]
    [InlineData("\"\\x41\"")]
    [InlineData("\"\\u12\"")]
    [InlineData("tru")]
    [InlineData("nul")]
    [InlineData("1 2")]
    [InlineData("")]
    [InlineData("\ufeff{}")]
    [InlineData("{\"a\":1}\n// comment")]
    public void RejectsInvalidJson(string text)
    {
        Assert.Throws<LicenseJsonException>(() => LicenseJson.Parse(text));
    }

    [Fact]
    public void ParsesNumbersAsLongOrDouble()
    {
        Assert.Equal(0L, LicenseJson.Parse("0"));
        Assert.Equal(0L, LicenseJson.Parse("-0"));
        Assert.Equal(-42L, LicenseJson.Parse("-42"));
        Assert.Equal(long.MaxValue, LicenseJson.Parse(long.MaxValue.ToString()));
        Assert.IsType<double>(LicenseJson.Parse("9223372036854775808")); // one past Int64.MaxValue
        Assert.Equal(1.5, LicenseJson.Parse("1.5"));
        Assert.Equal(100.0, LicenseJson.Parse("1e2"));
        Assert.Equal(1.0, LicenseJson.Parse("1.0"));
    }

    [Fact]
    public void ParsesStringsWithEscapesAndSurrogatePairs()
    {
        Assert.Equal("a\"b\\c/d\b\f\n\r\t", LicenseJson.Parse("\"a\\\"b\\\\c\\/d\\b\\f\\n\\r\\t\""));
        Assert.Equal("é😀", LicenseJson.Parse("\"\\u00e9\\ud83d\\ude00\""));
        Assert.Equal("日本語", LicenseJson.Parse("\"日本語\"")); // raw non-ASCII passes through
    }

    [Fact]
    public void ParsesNestedStructuresAndKeepsKeyOrder()
    {
        var obj = Assert.IsType<LicenseJsonObject>(LicenseJson.Parse(" { \"b\" : [ 1 , true , null , { } ] , \"a\" : \"x\" } "));
        Assert.Equal(new[] { "b", "a" }, obj.Keys.ToArray());
        var arr = Assert.IsAssignableFrom<IReadOnlyList<object>>(obj["b"]);
        Assert.Equal(4, arr.Count);
        Assert.Equal(1L, arr[0]);
        Assert.True((bool)arr[1]);
        Assert.Null(arr[2]);
        Assert.IsType<LicenseJsonObject>(arr[3]);
    }

    [Fact]
    public void RejectsExcessiveNesting()
    {
        string deep = new string('[', LicenseJson.MaxDepth + 2) + new string(']', LicenseJson.MaxDepth + 2);
        Assert.Throws<LicenseJsonException>(() => LicenseJson.Parse(deep));
        string ok = new string('[', LicenseJson.MaxDepth) + new string(']', LicenseJson.MaxDepth);
        Assert.NotNull(LicenseJson.Parse(ok));
    }

    [Fact]
    public void WritesNonFiniteDoublesAsNull()
    {
        Assert.Equal("null", LicenseJson.Write(double.PositiveInfinity));
        Assert.Equal("null", LicenseJson.Write(double.NegativeInfinity));
        Assert.Equal("null", LicenseJson.Write(double.NaN));
        Assert.Equal("[1E+308,null]", LicenseJson.Write(new object[] { 1e308, double.PositiveInfinity }));
    }

    [Fact]
    public void WriteRoundTripsAndEscapesControlCharacters()
    {
        string text = "{\"s\":\"q\\\"b\\\\\\n\\u0001é\",\"n\":[1,-2,2.5,true,false,null],\"o\":{}}";
        Assert.Equal(text, LicenseJson.Write(LicenseJson.Parse(text)));
    }
}

/// <summary>
/// Integers as spec §3 defines them: a signed 64-bit value written without a fraction or exponent.
/// These cases are the ones where the four reference verifiers used to disagree (spec §11).
/// </summary>
public class IntegerRangeTests
{
    private static readonly string PK = Vectors.PublicKey;

    private static string SignWithSeats(string literal)
    {
        var p = Vectors.BasePayload();
        p["seats"] = JsonNode.Parse(literal);
        return Vectors.SignRaw(p.ToJsonString());
    }

    [Theory]
    [InlineData("9007199254740992")]     // 2^53
    [InlineData("9007199254740993")]     // 2^53 + 1, not representable as a double
    [InlineData("9223372036854775807")]  // 2^63 - 1
    public void AcceptsIntegersUpToTheSigned64BitMaximum(string literal)
    {
        var result = LicenseVerifier.VerifyLicense(SignWithSeats(literal), PK, new VerifyOptions { Now = Vectors.Now });
        Assert.True(result.Ok, result.ReasonCode);
        Assert.Equal(long.Parse(literal), result.Payload.Seats);
    }

    [Theory]
    [InlineData("9223372036854775808")]   // 2^63
    [InlineData("18446744073709551616")]  // 2^64
    [InlineData("-9223372036854775809")]  // -2^63 - 1
    [InlineData("-1")]
    public void MalformedForIntegersOutsideTheSigned64BitRange(string literal)
    {
        var result = LicenseVerifier.VerifyLicense(SignWithSeats(literal), PK, new VerifyOptions { Now = Vectors.Now });
        Assert.Equal("malformed", result.ReasonCode);
    }

    [Theory]
    [InlineData("1.0")]
    [InlineData("1e0")]
    [InlineData("1.5")]
    [InlineData("1E2")]
    public void MalformedForNonCanonicalIntegerNotation(string literal)
    {
        var result = LicenseVerifier.VerifyLicense(SignWithSeats(literal), PK, new VerifyOptions { Now = Vectors.Now });
        Assert.Equal("malformed", result.ReasonCode);
    }

    [Fact]
    public void ComparesAnExpAboveTwoToThe53Correctly()
    {
        var far = Vectors.BasePayload();
        far["exp"] = JsonNode.Parse("9223372036854775807");
        Assert.True(LicenseVerifier.VerifyLicense(Vectors.SignRaw(far.ToJsonString()), PK,
            new VerifyOptions { Now = Vectors.Now }).Ok);

        var near = Vectors.BasePayload();
        near["exp"] = JsonNode.Parse("9007199254740992");
        Assert.Equal("expired", LicenseVerifier.VerifyLicense(Vectors.SignRaw(near.ToJsonString()), PK,
            new VerifyOptions { Now = 9007199254740993 }).ReasonCode);
    }
}

public class StringComparisonTests
{
    [Fact]
    public void PidIsComparedByteForByteWithoutUnicodeNormalisation()
    {
        // NFC and NFD spellings of the same text are different product IDs (spec §3). macOS stores
        // file names decomposed, so a pid taken from a path there can differ from the same pid typed
        // on Windows. Normalising in the verifier would compare something other than what was signed.
        const string nfc = "\u30A2\u30D7\u30EA\u30AC";
        const string nfd = "\u30A2\u30D5\u309A\u30EA\u30AB\u3099";
        Assert.NotEqual(nfc, nfd);
        var p = Vectors.BasePayload();
        p["pid"] = nfc;
        string lic = Vectors.SignRaw(p.ToJsonString());
        Assert.True(LicenseVerifier.VerifyLicense(lic, Vectors.PublicKey,
            new VerifyOptions { ProductId = nfc, Now = Vectors.Now }).Ok);
        Assert.Equal("product_mismatch", LicenseVerifier.VerifyLicense(lic, Vectors.PublicKey,
            new VerifyOptions { ProductId = nfd, Now = Vectors.Now }).ReasonCode);
    }
}

/// <summary>
/// The example checker's argument rules (verifiers/csharp/examples/VerifyCli/CliArgs.cs), which have
/// to match `licensesmith verify` and the TypeScript, Python and Rust checkers.
/// </summary>
public class CliArgsTests
{
    [Theory]
    [InlineData("revocations.json")]
    [InlineData("revocations.jsonn")]
    [InlineData("a/b")]
    [InlineData(@"a\b")]
    [InlineData("./x")]
    public void RecognisesPathLikeArguments(string arg) => Assert.True(Examples.CliArgs.LooksLikePath(arg));

    [Theory]
    [InlineData("0f6a2b1c-9d4e-4a7b-8c3d-1e2f3a4b5c6d")]
    [InlineData("a,b")]
    [InlineData("-UXJi")]
    [InlineData("")]
    public void LeavesInlineValuesAlone(string arg) => Assert.False(Examples.CliArgs.LooksLikePath(arg));

    [Fact]
    public void AMistypedRevocationFileIsAnErrorNotAOneElementIdList()
    {
        // H1: `--revoked revocations.jsonn` used to become the ID list ["revocations.jsonn"], which
        // silently turned the revocation check off and returned ok for a revoked license.
        string dir = Path.Combine(Path.GetTempPath(), "licensesmith-csharp-revoked-test");
        Directory.CreateDirectory(dir);
        string missing = Path.Combine(dir, "revocations.jsonn");
        if (File.Exists(missing)) File.Delete(missing);

        var e = Assert.Throws<FormatException>(() => Examples.CliArgs.ReadRevoked(missing));
        Assert.Contains("no such file", e.Message);
        Assert.Contains("is a directory", Assert.Throws<FormatException>(() => Examples.CliArgs.ReadRevoked(dir)).Message);

        // A value that does not look like a path is still taken as an inline list.
        Assert.Equal(new[] { "a", "b" }, Examples.CliArgs.ReadRevoked("a, b"));

        string list = Path.Combine(dir, "revocations.json");
        File.WriteAllText(list, "{\"revoked\":[\"one\",\"two\"]}");
        Assert.Equal(new[] { "one", "two" }, Examples.CliArgs.ReadRevoked(list));
        File.Delete(list);
    }

    [Fact]
    public void RecognisesASecretKeyFile()
    {
        // M-7 / threat model N3: `--pub my.key` must say so, even though the result is correct.
        using var secret = JsonDocument.Parse("{\"kind\":\"licensesmith-secret-key\",\"publicKey\":\"x\"}");
        using var pub = JsonDocument.Parse("{\"kind\":\"licensesmith-public-key\",\"publicKey\":\"x\"}");
        using var plain = JsonDocument.Parse("{\"publicKey\":\"x\"}");
        using var array = JsonDocument.Parse("[]");
        Assert.True(Examples.CliArgs.IsSecretKeyDocument(secret.RootElement));
        Assert.False(Examples.CliArgs.IsSecretKeyDocument(pub.RootElement));
        Assert.False(Examples.CliArgs.IsSecretKeyDocument(plain.RootElement));
        Assert.False(Examples.CliArgs.IsSecretKeyDocument(array.RootElement));
    }
}
