// Copyright (c) 2026 Colophon. Licensed under the MIT License — see LICENSE at the repository root.

// Minimal command-line checker built on verifiers/csharp/LicenseSmith.cs. Used by scripts/test-all.* for
// the cross-language check; also a small example of calling LicenseVerifier.VerifyLicense from C#.
//
//   dotnet run --project verifiers/csharp/examples/VerifyCli -- --pub <43-char key | path/to/.pub> --license <file | -> [--product ID] [--now N] [--revoked <file | a,b>]
//
// `--revoked` takes either a comma-separated list of license IDs or a file: the JSON that
// `licensesmith ledger export-revocations` writes ({"revoked":[...]} or a bare array), or one ID per line
// with `#` comments — the same forms `licensesmith verify --revoked` accepts. `--revoked-ids` is an alias
// kept for older scripts.
//
// Prints one JSON line. Exit code 0 = ok, 1 = license rejected, 2 = usage error.

using System.Text;
using System.Text.Json;
using LicenseSmith;
using LicenseSmith.Examples; // CliArgs.cs, next to this file: --revoked / --pub argument rules

static int Usage()
{
    Console.Error.WriteLine("usage: verify_cli --pub <key|file.pub> --license <file|-> [--product ID] [--now UNIX_SECONDS] [--revoked <file|a,b>]");
    return 2;
}

string? pubArg = null;
string? licenseArg = null;
string? revokedArg = null;
var opts = new VerifyOptions();

for (int i = 0; i < args.Length; i++)
{
    string flag = args[i];
    if (flag == "-h" || flag == "--help") return Usage();
    // `--pub=KEY` and `--pub KEY` are both accepted, like the other example checkers; the first form is
    // the one to reach for when the key itself starts with "-" (one public key in 64 does).
    string value;
    int eq = flag.StartsWith("--", StringComparison.Ordinal) ? flag.IndexOf('=') : -1;
    if (eq > 0)
    {
        value = flag.Substring(eq + 1);
        flag = flag.Substring(0, eq);
    }
    else
    {
        if (i + 1 >= args.Length) return Usage();
        value = args[++i];
    }
    switch (flag)
    {
        case "--pub": pubArg = value; break;
        case "--license": licenseArg = value; break;
        case "--product": opts.ProductId = value; break;
        case "--now":
            if (!long.TryParse(value, out long now)) return Usage();
            opts.Now = now;
            break;
        case "--revoked":
        case "--revoked-ids": revokedArg = value; break;
        default: return Usage();
    }
}
if (pubArg == null || licenseArg == null) return Usage();

string publicKey = pubArg;
if (File.Exists(pubArg))
{
    try
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(pubArg));
        if (CliArgs.IsSecretKeyDocument(doc.RootElement))
        {
            Console.Error.WriteLine(
                $"WARNING: {pubArg} is your SECRET key file. Only the public half was used, so the result below is correct,\n" +
                "  but what belongs in your app is the public key: the .pub file, or the 43 characters keygen printed.\n" +
                "  Never ship the .key inside your app, and never send it to anyone.");
        }
        publicKey = doc.RootElement.GetProperty("publicKey").GetString() ?? "";
    }
    catch (Exception e) when (e is JsonException || e is KeyNotFoundException || e is InvalidOperationException)
    {
        Console.Error.WriteLine($"{pubArg} is not a LicenseSmith .pub file: {e.Message}");
        return 2;
    }
}
else if (CliArgs.LooksLikePath(pubArg))
{
    Console.Error.WriteLine(
        $"--pub: no such file: {pubArg}\n--pub takes the .pub file written by `licensesmith keygen`, " +
        "or the 43-character public key itself.");
    return 2;
}

string licenseText;
try
{
    licenseText = licenseArg == "-" ? Console.In.ReadToEnd() : File.ReadAllText(licenseArg);
}
catch (IOException e)
{
    Console.Error.WriteLine($"cannot read {licenseArg}: {e.Message}");
    return 2;
}

if (revokedArg != null)
{
    string[] revokedIds;
    try { revokedIds = CliArgs.ReadRevoked(revokedArg); }
    catch (Exception e) when (e is FormatException || e is IOException)
    {
        Console.Error.WriteLine(e.Message);
        return 2;
    }
    if (revokedIds.Length == 0)
    {
        Console.Error.WriteLine(
            $"WARNING: --revoked {revokedArg} holds no license IDs, so nothing was checked against a revocation list.");
    }
    opts.RevokedIds = revokedIds;
}

VerifyResult result;
try
{
    result = LicenseVerifier.VerifyLicense(licenseText, publicKey, opts);
}
catch (ArgumentException e)
{
    Console.Error.WriteLine(e.Message);
    return 2;
}

var stdout = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false)) { AutoFlush = true };
if (result.Ok)
{
    stdout.Write("{\"ok\":true,\"payload\":" + result.Payload.ToJson() + "}\n");
    return 0;
}
stdout.Write("{\"ok\":false,\"reason\":\"" + result.ReasonCode + "\"}\n");
return 1;
