#!/usr/bin/env node
/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Colophon
 * This file is the MIT-licensed subset of LicenseSmith.
 */
/**
 * Minimal command-line checker built on licensesmith.ts. Used by scripts/test-all.* for the
 * cross-language check; also a small example of calling verifyLicense from Node.
 *
 *   node dist/verify-cli.js --pub <43-char key | path/to/.pub> --license <file | -> [--product ID] [--now N] [--revoked <file | a,b>]
 *
 * `--revoked` takes either a comma-separated list of license IDs or a file: the JSON that
 * `licensesmith ledger export-revocations` writes ({"revoked":[...]} or a bare array), or one ID per
 * line with `#` comments — the same forms `licensesmith verify --revoked` accepts. `--revoked-ids` is
 * an alias kept for older scripts.
 *
 * Prints one JSON line. Exit code 0 = ok, 1 = license rejected, 2 = usage error.
 */
import { existsSync, readFileSync, statSync } from "node:fs";
import { parseArgs } from "node:util";
import { verifyLicense } from "./licensesmith.js";

/**
 * Node's parseArgs refuses `--pub -abc` ("argument is ambiguous") because the value looks like a flag,
 * and about one base64url public key in 64 starts with "-" (a license ID passed to --revoked may too).
 * For the options whose values are opaque strings, join the token after them into `--opt=value` first.
 * A lone `-` (stdin) and the command's own option names are left alone.
 */
function joinLeadingDashValues(args: readonly string[], valueOptions: readonly string[], knownOptions: readonly string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const next = args[i + 1];
    if (valueOptions.includes(arg) && next !== undefined && /^-[A-Za-z0-9_,-]+$/.test(next) && !knownOptions.includes(next)) {
      out.push(`${arg}=${next}`);
      i++;
    } else {
      out.push(arg);
    }
  }
  return out;
}

const { values } = parseArgs({
  args: joinLeadingDashValues(
    process.argv.slice(2),
    ["--pub", "--license", "--revoked", "--revoked-ids"],
    ["--pub", "--license", "--product", "--now", "--revoked", "--revoked-ids", "--help", "-h"],
  ),
  options: {
    pub: { type: "string" },
    license: { type: "string" },
    product: { type: "string" },
    now: { type: "string" },
    revoked: { type: "string" },
    "revoked-ids": { type: "string" },
    help: { type: "boolean", short: "h" },
  },
});

if (values.help || !values.pub || !values.license) {
  process.stderr.write(
    "usage: verify-cli --pub <key|file.pub> --license <file|-> [--product ID] [--now UNIX_SECONDS] [--revoked <file|a,b>]\n" +
      "       (--pub=KEY also works; a key that starts with \"-\" is accepted either way)\n",
  );
  process.exit(values.help ? 0 : 2);
}

let publicKey = values.pub;
if (existsSync(publicKey) && statSync(publicKey).isFile()) {
  publicKey = readPublicKeyFile(publicKey);
} else if (looksLikePath(publicKey)) {
  die(
    `--pub: no such file: ${publicKey}\n` +
      "--pub takes the .pub file written by `licensesmith keygen`, or the 43-character public key itself.\n",
  );
}
const licenseText = values.license === "-" ? readFileSync(0, "utf8") : readFileSync(values.license, "utf8");

const now = values.now === undefined ? undefined : Number(values.now);
if (now !== undefined && !Number.isSafeInteger(now)) {
  process.stderr.write("--now must be an integer number of Unix seconds\n");
  process.exit(2);
}

const revokedArg = values.revoked ?? values["revoked-ids"];
let revokedIds: string[] | undefined;
try {
  revokedIds = revokedArg === undefined ? undefined : readRevoked(revokedArg);
} catch (err) {
  process.stderr.write(`${(err as Error).message}\n`);
  process.exit(2);
}
if (revokedIds !== undefined && revokedIds.length === 0) {
  process.stderr.write(`WARNING: --revoked ${revokedArg} holds no license IDs, so nothing was checked against a revocation list.\n`);
}

const result = await verifyLicense(licenseText, publicKey, { productId: values.product, now, revokedIds });
process.stdout.write(JSON.stringify(result) + "\n");
process.exit(result.ok ? 0 : 1);

/** Write `message` to stderr and exit with the usage-error code. */
function die(message: string): never {
  process.stderr.write(message);
  process.exit(2);
}

/**
 * Several options take *either* a file path *or* the value itself (`--pub` a .pub file or the
 * 43-character key, `--revoked` a list file or `a,b,c`). When the file does not exist, treating the
 * argument as the inline value is right for `-UXJi...` and silently wrong for `revocations.jsonn`:
 * a mistyped path must be reported as a missing file, not used as one-element data. Same rule as
 * `licensesmith verify` (cli/src/core/paths.ts) and the Python, Rust and C# checkers.
 */
function looksLikePath(arg: string): boolean {
  return /[\\/]/.test(arg) || /\.[A-Za-z0-9]{1,8}$/.test(arg);
}

/** Read the `.pub` (or `.key`) file written by `licensesmith keygen` and return its public key. */
function readPublicKeyFile(path: string): string {
  let doc: { kind?: unknown; publicKey?: unknown };
  try {
    doc = JSON.parse(readFileSync(path, "utf8")) as { kind?: unknown; publicKey?: unknown };
  } catch {
    return die(`${path} is not a LicenseSmith .pub file (expected JSON with a "publicKey" field)\n`);
  }
  if (typeof doc.publicKey !== "string") return die(`${path} has no "publicKey" field\n`);
  // Reading the public half out of a .key is fine; doing it silently is not. A check that just
  // worked teaches "--pub takes the .key", and the next step is the secret key shipped inside an
  // application: the one failure this kit cannot cap afterwards (spec/threat-model.md N3).
  // Same warning as `licensesmith verify` (cli/src/core/keys.ts).
  if (doc.kind === "licensesmith-secret-key") {
    process.stderr.write(
      `WARNING: ${path} is your SECRET key file. Only the public half was used, so the result below is correct,\n` +
        "  but what belongs in your app is the public key: the .pub file, or the 43 characters keygen printed.\n" +
        "  Never ship the .key inside your app, and never send it to anyone.\n",
    );
  }
  return doc.publicKey;
}

/** A file (JSON revocation list or one ID per line) or a comma-separated list of IDs. */
function readRevoked(arg: string): string[] {
  if (existsSync(arg)) {
    if (!statSync(arg).isFile()) throw new Error(`--revoked: ${arg} is a directory, not a revocation list`);
    const text = readFileSync(arg, "utf8").replace(/^\uFEFF/, "");
    if (/^\s*[[{]/.test(text)) return parseRevocationJson(text, arg);
    return text
      .split(/\r?\n/)
      .map((l) => l.replace(/#.*$/, "").trim())
      .filter((l) => l !== "");
  }
  if (looksLikePath(arg)) {
    throw new Error(
      `--revoked: no such file: ${arg}\n` +
        "--revoked takes the revocations.json written by `licensesmith ledger export-revocations`, a text file with " +
        "one license ID per line, or the IDs themselves separated by commas.",
    );
  }
  return arg
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s !== "");
}

function parseRevocationJson(text: string, path: string): string[] {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    throw new Error(`--revoked: ${path} starts like JSON but is not valid JSON`);
  }
  const list = Array.isArray(doc) ? doc : (doc as { revoked?: unknown } | null)?.revoked;
  if (!Array.isArray(list) || list.some((id) => typeof id !== "string")) {
    throw new Error(`--revoked: ${path} must be a JSON array of license IDs, or an object with a "revoked" array`);
  }
  return list as string[];
}
