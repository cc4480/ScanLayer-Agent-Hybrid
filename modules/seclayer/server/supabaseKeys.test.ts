import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  findServiceRoleToken, findMinifiedSupabasePairs, extractTableNames, extractStorageBucketNames, jwtClaims, jwtRole, isServiceRoleToken,
} from "./supabaseKeys.js";
import { extractUrlKeyPairs } from "./credentialChainProbe.js";

// Reading a Supabase project's URL and keys out of MINIFIED client code, where every variable name is gone.
// The layout below is what a built Vite bundle of the Lovable-style test app contains:
//   const sM="https://<ref>.supabase.co",aM="eyJ…",Tn=cO(sM,aM,{auth:{…}})
// Nothing here is a working credential: the tokens carry real-looking claims and a hash for a signature.

const REF = "abcdefghijklmnopqrst";
const OTHER = "zyxwvutsrqponmlkjihg";
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (claims: Record<string, unknown>) => {
  const head = `${b64({ alg: "HS256", typ: "JWT" })}.${b64(claims)}`;
  return `${head}.${createHash("sha256").update(head).digest("base64url")}`;
};
const ANON = jwt({ iss: "supabase", ref: REF, role: "anon", iat: 1700000000, exp: 2000000000 });
const ANON_NO_REF = jwt({ role: "anon", iss: "supabase", iat: 1600000000, exp: 1960000000 });
const SERVICE = jwt({ iss: "supabase", ref: REF, role: "service_role", iat: 1700000000, exp: 2000000000 });
const SIGNED_IN = jwt({ iss: "supabase", ref: REF, sub: "u-1", role: "authenticated", iat: 1700000000, exp: 2000000000 });
const FOREIGN = jwt({ iss: "supabase", ref: OTHER, role: "anon", iat: 1700000000, exp: 2000000000 });
const VENDOR = 'function Ee(e){return e}class Xt{constructor(e){this.opts=e}}const Q=e=>typeof e=="boolean"?`${e}`:e;'.repeat(300);

test("token claims are read without verifying a signature", () => {
  assert.equal(jwtRole(ANON), "anon");
  assert.equal(jwtClaims(SERVICE)?.["ref"], REF);
  assert.ok(isServiceRoleToken(SERVICE));
  assert.equal(isServiceRoleToken(ANON), false);
  assert.equal(jwtClaims("not.a.token"), null);
  assert.equal(jwtRole("eyJ" + "a".repeat(60)), null);
});

test("findServiceRoleToken recognises the key by its role claim, whatever it is called", () => {
  assert.equal(findServiceRoleToken(`const fI=cO(sM,"${SERVICE}");`), SERVICE);
  assert.equal(findServiceRoleToken(`const a="${ANON}",b="${SERVICE}"`), SERVICE);
  assert.equal(findServiceRoleToken(`const a="${ANON}"`), null);
  assert.equal(findServiceRoleToken(`const t="${SIGNED_IN}"`), null);
  assert.equal(findServiceRoleToken(""), null);
});

test("a URL and key renamed to short constants are paired", () => {
  const bundle = `${VENDOR}const sM="https://${REF}.supabase.co",aM="${ANON}",Tn=cO(sM,aM,{auth:{persistSession:!0}});${VENDOR}`;
  assert.deepEqual(findMinifiedSupabasePairs(bundle), [{ url: `https://${REF}.supabase.co`, key: ANON }]);
});

test("a key written before the URL, with no project claim, is paired by distance", () => {
  const bundle = `${VENDOR}const aM="${ANON_NO_REF}",sM="https://${REF}.supabase.co";${VENDOR}`;
  assert.equal(findMinifiedSupabasePairs(bundle)[0]?.key, ANON_NO_REF);
});

test("a key far from the URL is paired by the project it names, and not when it names none", () => {
  const far = (key: string) => `const sM="https://${REF}.supabase.co";${VENDOR}${VENDOR}const aM="${key}";`;
  assert.equal(findMinifiedSupabasePairs(far(ANON))[0]?.key, ANON);
  assert.deepEqual(findMinifiedSupabasePairs(far(ANON_NO_REF)), []);
});

test("a publishable key is paired", () => {
  const key = "sb_publishable_ACJWlzQHlZjBrEguHvfOxg_3BJgxAaH";
  assert.equal(findMinifiedSupabasePairs(`const sM="https://${REF}.supabase.co",aM="${key}";`)[0]?.key, key);
});

test("the service_role key, a signed-in user's token and another project's key are never paired", () => {
  assert.equal(findMinifiedSupabasePairs(`const sM="https://${REF}.supabase.co",sr="${SERVICE}",aM="${ANON}";`)[0]?.key, ANON);
  assert.deepEqual(findMinifiedSupabasePairs(`const sM="https://${REF}.supabase.co",sr="${SERVICE}";`), []);
  assert.deepEqual(findMinifiedSupabasePairs(`const sM="https://${REF}.supabase.co",t="${SIGNED_IN}";`), []);
  assert.deepEqual(findMinifiedSupabasePairs(`const sM="https://${REF}.supabase.co",k="${FOREIGN}";`), []);
});

test("extractUrlKeyPairs finds the minified pair, so the probes get a target", () => {
  const bundle = `${VENDOR}const sM="https://${REF}.supabase.co",aM="${ANON}",Tn=cO(sM,aM,{});${VENDOR}`;
  const pairs = extractUrlKeyPairs(bundle);
  assert.equal(pairs.length, 1);
  assert.equal(pairs[0]!.prefix, "SUPABASE");
  assert.equal(pairs[0]!.url, `https://${REF}.supabase.co`);
  assert.equal(pairs[0]!.key, ANON);
});

test("extractUrlKeyPairs never pairs a service_role key, even when createClient names it", () => {
  assert.deepEqual(extractUrlKeyPairs(`createClient("https://${REF}.supabase.co","${SERVICE}")`), []);
  assert.deepEqual(extractUrlKeyPairs(`window.SUPABASE_URL="https://${REF}.supabase.co";window.SUPABASE_ANON_KEY="${SERVICE}";`), []);
});

test("extractUrlKeyPairs ignores a documentation host and a bare token elsewhere in the bundle", () => {
  const docs = `/** createClient("https://xyzcompany.supabase.co", "${ANON_NO_REF}") */`;
  assert.deepEqual(extractUrlKeyPairs(docs), []);
  const sample = jwt({ sub: "1234567890", name: "John Doe", iat: 1516239022 });
  assert.deepEqual(extractUrlKeyPairs(`const u="https://${REF}.supabase.co";${VENDOR}${VENDOR}const d="${sample}";`), []);
});

test("table names come from .from() calls, not from storage buckets or built-ins", () => {
  const code = `${VENDOR}const t=Array.from("abc"),u=Buffer.from("hex");Tn.from("tasks").select("*");Tn.from("orders");Tn.storage.from("avatars").list();`;
  assert.deepEqual(extractTableNames(code).sort(), ["orders", "tasks"]);
  assert.deepEqual(extractTableNames(`supabase\n  .storage\n  .from("avatars")\n  .upload(p, f); supabase\n  .from("profiles")\n  .select()`), ["profiles"]);
});

test("bucket names come from .storage.from() calls", () => {
  assert.deepEqual(extractStorageBucketNames(`${VENDOR}Tn.storage.from("avatars").list();Tn.from("tasks")`), ["avatars"]);
  assert.deepEqual(extractStorageBucketNames(`x.storage.from(bucketName)`), []);
});

// Text a hostile site can serve must not make a scan wait for minutes. The JWT scan starts at every `eyJ`; without the
// lookbehind a script that is only `eyJeyJeyJ…` costs the square of its length (another scanner of ours took 6.7 s for 80 KB).
test("hostile text is read in bounded time", () => {
  const MB = 1024 * 1024;
  const hostile = ["eyJ".repeat(MB / 3), "eyJ.eyJ.".repeat(MB / 8), "aB3-_".repeat(MB / 5)];
  for (const text of hostile) {
    for (const fn of [findServiceRoleToken, (t: string) => findMinifiedSupabasePairs(`"https://${REF}.supabase.co" ${t}`), (t: string) => extractUrlKeyPairs(`"https://${REF}.supabase.co" ${t}`)]) {
      const t0 = performance.now();
      fn(text);
      assert.ok(performance.now() - t0 < 3000, "took too long");
    }
  }
});
