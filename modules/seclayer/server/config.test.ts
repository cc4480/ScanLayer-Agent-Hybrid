import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { buildId, parseRole } from "./config.js";

test("parseRole defaults to 'all' (single-node, backwards-compatible) when unset or unrecognized", () => {
  assert.equal(parseRole(undefined), "all");
  assert.equal(parseRole(""), "all");
  assert.equal(parseRole("   "), "all");
  assert.equal(parseRole("nonsense"), "all");
  assert.equal(parseRole("primary"), "all"); // not one of the two explicit roles
});

test("parseRole recognizes the explicit web/worker roles, case- and whitespace-insensitively", () => {
  assert.equal(parseRole("web"), "web");
  assert.equal(parseRole("worker"), "worker");
  assert.equal(parseRole("WEB"), "web");
  assert.equal(parseRole("  Worker  "), "worker");
  assert.equal(parseRole("all"), "all");
});

// --- buildId(): operator-only build identity -------------------------------
// The split this pins: buildId() names the exact commit and goes to the boot
// LOG; config.appVersion is served by the unauthenticated health endpoint and
// rendered in the public navbar. This repository is public, so a live commit
// hash in a response body tells anyone which fixes are not yet deployed.

test("buildId falls back to 'local' when no platform supplied build metadata", () => {
  assert.equal(buildId({}), "local");
  assert.equal(buildId({ RAILWAY_GIT_COMMIT_SHA: "" }), "local");
  assert.equal(buildId({ RAILWAY_GIT_COMMIT_SHA: "   " }), "local");
});

test("buildId shortens a full 40-char SHA to the 7 chars git log prints", () => {
  const sha = "d2890d7037cb681d6cccdfbcb25e02e59d6f7784";
  assert.equal(buildId({ RAILWAY_GIT_COMMIT_SHA: sha }), "d2890d7");
  assert.equal(buildId({ VERCEL_GIT_COMMIT_SHA: sha }), "d2890d7");
  assert.equal(buildId({ SOURCE_COMMIT: sha }), "d2890d7");
  assert.equal(buildId({ GIT_COMMIT: sha }), "d2890d7");
});

test("buildId leaves a non-SHA build label (e.g. a release tag) intact", () => {
  assert.equal(buildId({ APP_BUILD_SHA: "v2.1.0" }), "v2.1.0");
});

test("an explicit APP_BUILD_SHA wins over the platform's own variable", () => {
  assert.equal(
    buildId({ APP_BUILD_SHA: "pinned", RAILWAY_GIT_COMMIT_SHA: "d2890d7037cb681d6cccdfbcb25e02e59d6f7784" }),
    "pinned",
  );
});

test("the PUBLIC appVersion never picks up a commit SHA from the platform", () => {
  // Asserted against the source rather than the value, because `config` is
  // evaluated once at import: with no commit variable set in the test process,
  // checking config.appVersion would pass no matter what the fallback chain
  // says, and prove nothing. The regression to catch is someone "helpfully"
  // adding RAILWAY_GIT_COMMIT_SHA to that chain, which would start publishing
  // the live commit of a public repo in the navbar.
  const src = fs.readFileSync(path.join(process.cwd(), "server", "config.ts"), "utf-8");
  const line = src.split(/\r?\n/).find((l) => /^\s*appVersion:/.test(l));
  assert.ok(line, "expected an appVersion line in server/config.ts");
  assert.doesNotMatch(line, /COMMIT|SHA|buildId/i, `appVersion is public surface: ${line.trim()}`);
});

// --- DISABLE_RATE_LIMITS is hard-disabled in production --------------------
// This flag turns off EVERY limit, including the sign-in code gate that bounds
// brute force against a six-digit code. It exists so a load test can measure
// real scan capacity instead of measuring the limiter. Its entire safety rests
// on the NODE_ENV guard, so that guard is pinned here rather than trusted.
//
// config reads process.env once at module load, so each case runs in its own
// process — mutating process.env in-test would prove nothing about the value
// the real server computes at boot.
import { execFileSync } from "node:child_process";

function configFlagUnder(env: Record<string, string>): boolean {
  const out = execFileSync(
    process.execPath,
    // JSON.stringify, not the raw boolean: console.log colourises a boolean
    // when FORCE_COLOR is set (it is in some terminals and CI), printing
    // "[33mtrue[39m". A suffix check on that read every value as
    // false — failing the development case, and passing the production case
    // VACUOUSLY, so the one assertion guarding this flag proved nothing.
    ["--import", "tsx", "--eval", "import('./server/config.ts').then(m => console.log('FLAG=' + JSON.stringify(m.config.disableRateLimits)))"],
    { env: { ...process.env, ...env }, encoding: "utf8", cwd: process.cwd() },
  );
  const match = /FLAG=(true|false)/.exec(out);
  // No match is a broken harness, not a "false" — fail loudly rather than let
  // an unreadable answer satisfy the production assertion.
  if (!match) throw new Error(`could not read the flag from child output: ${JSON.stringify(out)}`);
  return match[1] === "true";
}

test("DISABLE_RATE_LIMITS is ignored in production, however it is set", () => {
  assert.equal(configFlagUnder({ NODE_ENV: "production", DISABLE_RATE_LIMITS: "true" }), false);
});

test("DISABLE_RATE_LIMITS applies in development only when explicitly 'true'", () => {
  assert.equal(configFlagUnder({ NODE_ENV: "development", DISABLE_RATE_LIMITS: "true" }), true);
  assert.equal(configFlagUnder({ NODE_ENV: "development", DISABLE_RATE_LIMITS: "1" }), false);
  assert.equal(configFlagUnder({ NODE_ENV: "development", DISABLE_RATE_LIMITS: "" }), false);
});

import crypto from 'node:crypto';
import { productionSecretProblems } from './config.js';

const goodKey = crypto.randomBytes(32).toString('base64');

test('production refuses to boot without a usable ENCRYPTION_KEY', () => {
  const missing = productionSecretProblems({ ORIGIN_AUTH_SECRET: 'x' });
  assert.equal(missing.critical, true);
  assert.match(missing.warnings.join('\n'), /ENCRYPTION_KEY is required/);

  const short = productionSecretProblems({ ENCRYPTION_KEY: Buffer.from('too short').toString('base64'), ORIGIN_AUTH_SECRET: 'x' });
  assert.equal(short.critical, true);
  assert.match(short.warnings.join('\n'), /32 bytes/);

  const blank = productionSecretProblems({ ENCRYPTION_KEY: '   ', ORIGIN_AUTH_SECRET: 'x' });
  assert.equal(blank.critical, true);
});

test('a missing ORIGIN_AUTH_SECRET is a loud warning, not a refusal', () => {
  const r = productionSecretProblems({ ENCRYPTION_KEY: goodKey });
  assert.equal(r.critical, false);
  assert.match(r.warnings.join('\n'), /origin lock is OFF/);
});

test('a fully configured production environment has nothing to report', () => {
  assert.deepEqual(productionSecretProblems({ ENCRYPTION_KEY: goodKey, ORIGIN_AUTH_SECRET: 'secret' }), { warnings: [], critical: false });
});
