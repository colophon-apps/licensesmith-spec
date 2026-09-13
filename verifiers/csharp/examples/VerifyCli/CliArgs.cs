// Copyright (c) 2026 Colophon. Licensed under the MIT License — see LICENSE at the repository root.

// The argument rules the example checker shares with `licensesmith verify` and with the TypeScript,
// Python and Rust checkers. They live in their own class so the C# test suite can exercise them:
// Program.cs is a top-level-statements file and cannot be compiled into a test project.

using System.Text.Json;
using System.Text.RegularExpressions;

namespace LicenseSmith.Examples
{
    public static class CliArgs
    {
        /// <summary>
        /// True if <paramref name="arg"/> reads as a file path rather than an inline value.
        /// <para>
        /// Several options take <em>either</em> a path <em>or</em> the value itself (<c>--pub</c> a
        /// .pub file or the 43-character key, <c>--revoked</c> a list file or <c>a,b,c</c>). When the
        /// file does not exist, treating the argument as the inline value is right for
        /// <c>-UXJi...</c> and silently wrong for <c>revocations.jsonn</c>: a mistyped path must be
        /// reported as a missing file, not used as one-element data.
        /// </para>
        /// </summary>
        public static bool LooksLikePath(string arg) =>
            Regex.IsMatch(arg, @"[\\/]|\.[A-Za-z0-9]{1,8}\z");

        /// <summary>
        /// Resolve <c>--revoked</c>: a file (the JSON that <c>licensesmith ledger
        /// export-revocations</c> writes, or one license ID per line with <c>#</c> comments) or a
        /// comma-separated list of IDs.
        /// </summary>
        /// <exception cref="FormatException">The argument names a file that does not exist, a
        /// directory, or a file whose contents are not a revocation list.</exception>
        public static string[] ReadRevoked(string arg)
        {
            if (!File.Exists(arg))
            {
                if (Directory.Exists(arg))
                    throw new FormatException($"--revoked: {arg} is a directory, not a revocation list");
                if (LooksLikePath(arg))
                    throw new FormatException(
                        $"--revoked: no such file: {arg}\n--revoked takes the revocations.json written by " +
                        "`licensesmith ledger export-revocations`, a text file with one license ID per line, " +
                        "or the IDs themselves separated by commas.");
                return arg.Split(',').Select(s => s.Trim()).Where(s => s.Length > 0).ToArray();
            }

            string text = File.ReadAllText(arg); // honours a UTF-8/UTF-16 BOM
            if (!Regex.IsMatch(text, @"^\s*[\[{]"))
            {
                return text.Split('\n')
                    .Select(line => { int hash = line.IndexOf('#'); return (hash >= 0 ? line.Substring(0, hash) : line).Trim(); })
                    .Where(line => line.Length > 0)
                    .ToArray();
            }

            JsonDocument doc;
            try { doc = JsonDocument.Parse(text); }
            catch (JsonException) { throw new FormatException($"--revoked: {arg} starts like JSON but is not valid JSON"); }
            using (doc)
            {
                JsonElement root = doc.RootElement;
                JsonElement list = root;
                if (root.ValueKind == JsonValueKind.Object) root.TryGetProperty("revoked", out list); // Undefined when absent
                if (list.ValueKind != JsonValueKind.Array || list.EnumerateArray().Any(e => e.ValueKind != JsonValueKind.String))
                    throw new FormatException($"--revoked: {arg} must be a JSON array of license IDs, or an object with a \"revoked\" array");
                return list.EnumerateArray().Select(e => e.GetString()!).ToArray();
            }
        }

        /// <summary>
        /// True when the JSON document at <paramref name="path"/> is a LicenseSmith <em>secret</em>
        /// key file. Reading the public half out of a .key is fine; doing it silently is not. A check
        /// that just worked teaches "--pub takes the .key", and the next step is the secret key
        /// shipped inside an application: the one failure this kit cannot cap afterwards
        /// (spec/threat-model.md N3). Same warning as `licensesmith verify` (cli/src/core/keys.ts).
        /// </summary>
        public static bool IsSecretKeyDocument(JsonElement root) =>
            root.ValueKind == JsonValueKind.Object &&
            root.TryGetProperty("kind", out JsonElement kind) &&
            kind.ValueKind == JsonValueKind.String &&
            kind.GetString() == "licensesmith-secret-key";
    }
}
