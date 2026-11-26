import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { classifyExposure, rowColumns } from "./exposureClass.js";
import { probeCredentialUrlPairs } from "./credentialChainProbe.js";
import { probeSupabaseStorage } from "./supabaseStorageProbe.js";
import { analyzeSecrets } from "./staticAnalysis.js";
import { createHash } from "node:crypto";

// A table that is public by design must not be rated critical, Supabase Storage is covered, and the
// OpenAI and service_role keys are recognised. Found with a Lovable-style test app (React + Vite, Supabase).

async function withServer(handler: http.RequestListener, fn: (port: number) => Promise<void>) {
  const server = http.createServer(handler);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as AddressInfo).port;
  const prevEnv = process.env.NODE_ENV;
  const prevAllow = process.env.SCAN_DEV_ALLOW_HOSTS;
  try {
    process.env.NODE_ENV = "development";
    process.env.SCAN_DEV_ALLOW_HOSTS = `127.0.0.1:${port}`;
    await fn(port);
  } finally {
    if (prevEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = prevEnv;
    if (prevAllow === undefined) delete process.env.SCAN_DEV_ALLOW_HOSTS; else process.env.SCAN_DEV_ALLOW_HOSTS = prevAllow;
    await new Promise((r) => server.close(r));
  }
}

const KEY = "fake-anon-key-value-1234567890";
const json = (res: http.ServerResponse, body: unknown, status = 200) => { res.writeHead(status, { "Content-Type": "application/json" }); res.end(JSON.stringify(body)); };
const ANNOUNCEMENTS = [{ id: 1, title: "We moved", body: "Our new address is on the About page.", created_at: "2026-10-01T00:00:00Z" }];

// ── classification ──────────────────────────────────────────────────────────

test("a table named like published content is public", () => {
  assert.equal(classifyExposure("announcements", ANNOUNCEMENTS), "public");
  assert.equal(classifyExposure("changelog", [{ version: "1.2" }]), "public");
});

test("an unfamiliar name with nothing personal in it is unclassified, not sensitive", () => {
  assert.equal(classifyExposure("bulletin", [{ id: 1, title: "x", body: "y" }]), "unclassified");
});

test("rows that say whose they are make an unfamiliar table sensitive; an author is not an owner", () => {
  for (const col of ["user_id", "owner_id", "customer_id", "account_id", "tenant_id", "org_id", "device_id", "session_id", "created_by", "uid", "userId"]) {
    assert.equal(classifyExposure("notes", [{ id: 1, body: "x", [col]: "u-1" }]), "sensitive", col);
  }
  assert.equal(classifyExposure("posts", [{ id: 1, title: "x", author_id: "u-1" }]), "public");
  assert.equal(classifyExposure("reviews", [{ id: 1, stars: 5, user_id: "u-1" }]), "public");
});

test("a sensitive name or a personal column wins over everything", () => {
  assert.equal(classifyExposure("profiles", ANNOUNCEMENTS), "sensitive");
  assert.equal(classifyExposure("announcements", [{ id: 1, contact_email: "a@b.co" }]), "sensitive");
  assert.equal(rowColumns(ANNOUNCEMENTS), "id, title, body, created_at");
});

// ── the credential-chain probe ──────────────────────────────────────────────

test("clean twin: a readable public-by-design table is not a finding", async () => {
  await withServer((req, res) => {
    if (req.url === "/rest/v1/") return json(res, { paths: { "/announcements": {} } });
    if (req.url?.startsWith("/rest/v1/announcements")) return json(res, ANNOUNCEMENTS);
    json(res, []);
  }, async (port) => {
    const finding = await probeCredentialUrlPairs([{ prefix: "SUPABASE", url: `http://127.0.0.1:${port}`, key: KEY }]);
    assert.equal(finding, null);
  });
});

test("clean twin: a readable table nothing marks as sensitive is information, worded as a question", async () => {
  await withServer((req, res) => {
    if (req.url === "/rest/v1/") return json(res, { paths: { "/bulletin": {} } });
    if (req.url?.startsWith("/rest/v1/bulletin")) return json(res, [{ id: 1, title: "Roof repairs", body: "Scaffolding goes up Monday." }]);
    json(res, []);
  }, async (port) => {
    const finding = await probeCredentialUrlPairs([{ prefix: "SUPABASE", url: `http://127.0.0.1:${port}`, key: KEY }]);
    assert.ok(finding);
    assert.equal(finding.severity, "info");
    assert.match(finding.testName, /Not Classified/);
    assert.match(finding.description, /id, title, body/);
    assert.match(finding.fix, /Confirm/);
  });
});

test("a table of per-user rows is still critical, even with an unfamiliar name", async () => {
  await withServer((req, res) => {
    if (req.url === "/rest/v1/") return json(res, { paths: { "/notes": {}, "/announcements": {} } });
    if (req.url?.startsWith("/rest/v1/announcements")) return json(res, ANNOUNCEMENTS);
    if (req.url?.startsWith("/rest/v1/notes")) return json(res, [{ id: 1, body: "my diary", user_id: "u-1" }]);
    json(res, []);
  }, async (port) => {
    const finding = await probeCredentialUrlPairs([{ prefix: "SUPABASE", url: `http://127.0.0.1:${port}`, key: KEY }]);
    assert.equal(finding?.severity, "critical");
    assert.match(finding?.payload, /notes/);
  });
});

test("a sensitive table is critical and wins over an unclassified one found first", async () => {
  await withServer((req, res) => {
    if (req.url === "/rest/v1/") return json(res, { paths: { "/bulletin": {}, "/profiles": {} } });
    if (req.url?.startsWith("/rest/v1/bulletin")) return json(res, [{ id: 1, title: "x" }]);
    if (req.url?.startsWith("/rest/v1/profiles")) return json(res, [{ id: "u1", display_name: "Sam" }]);
    json(res, []);
  }, async (port) => {
    const finding = await probeCredentialUrlPairs([{ prefix: "SUPABASE", url: `http://127.0.0.1:${port}`, key: KEY }]);
    assert.equal(finding?.severity, "critical");
    assert.match(finding?.payload, /profiles/);
  });
});

test("the tables the app's own code reads are tried before the guess list", async () => {
  await withServer((req, res) => {
    if (req.url === "/rest/v1/") { res.writeHead(401); return res.end("locked"); } // schema listing is service_role only
    if (req.url?.startsWith("/rest/v1/orders")) return json(res, [{ id: 1, total: 12 }]);
    json(res, []);
  }, async (port) => {
    const pair = { prefix: "SUPABASE", url: `http://127.0.0.1:${port}`, key: KEY };
    assert.equal(await probeCredentialUrlPairs([pair]), null, "not in the guess list, so not found without the app's names");
    const finding = await probeCredentialUrlPairs([pair], ["orders"]);
    assert.equal(finding?.severity, "critical");
    assert.match(finding?.payload, /orders/);
  });
});

// ── Supabase Storage ────────────────────────────────────────────────────────

const storagePair = (port: number) => ({ prefix: "SUPABASE", url: `http://127.0.0.1:${port}`, key: KEY });

test("a bucket the code names is flagged when its files can be listed, although the bucket list is empty", async () => {
  await withServer((req, res) => {
    if (req.url === "/storage/v1/bucket") return json(res, []);
    if (req.method === "POST" && req.url === "/storage/v1/object/list/avatars") return json(res, [{ name: "passport-scan.png" }]);
    json(res, { message: "not found" }, 404);
  }, async (port) => {
    const finding = await probeSupabaseStorage([storagePair(port)], ["avatars"]);
    assert.ok(finding);
    assert.equal(finding.severity, "medium");
    assert.match(finding.testName, /avatars/);
    assert.match(finding.description, /passport-scan\.png/);
    assert.ok(finding.evidence.attack.request.includes("POST /storage/v1/object/list/avatars"));
    assert.ok(!finding.evidence.attack.request.includes(KEY), "the key is not written out whole");
  });
});

test("a bucket found in the bucket list is probed too", async () => {
  await withServer((req, res) => {
    if (req.url === "/storage/v1/bucket") return json(res, [{ name: "docs" }]);
    if (req.method === "POST" && req.url === "/storage/v1/object/list/docs") return json(res, [{ name: "invoice-1.pdf" }]);
    json(res, [], 200);
  }, async (port) => {
    const finding = await probeSupabaseStorage([storagePair(port)]);
    assert.match(finding?.testName, /docs/);
  });
});

test("clean twin: buckets that list nothing, or refuse, are not findings", async () => {
  await withServer((req, res) => {
    if (req.url === "/storage/v1/bucket") return json(res, [{ name: "docs" }, { name: "avatars" }]);
    if (req.url === "/storage/v1/object/list/docs") return json(res, { message: "new row violates row-level security policy" }, 400);
    if (req.url === "/storage/v1/object/list/avatars") return json(res, []);
    json(res, { message: "Bucket not found" }, 404);
  }, async (port) => {
    assert.equal(await probeSupabaseStorage([storagePair(port)], ["avatars", "ghost"]), null);
  });
});

test("only Supabase pairs are probed, and no more than five buckets", async () => {
  const asked: string[] = [];
  await withServer((req, res) => {
    asked.push(`${req.method} ${req.url}`);
    json(res, []);
  }, async (port) => {
    assert.equal(await probeSupabaseStorage([{ prefix: "BAAS", url: `http://127.0.0.1:${port}`, key: KEY }], ["a"]), null);
    assert.equal(asked.length, 0);
    await probeSupabaseStorage([storagePair(port)], ["a", "a", "b", "c", "d", "e", "f", "g"]);
    assert.equal(asked.filter((a) => a.startsWith("POST ")).length, 5);
  });
});

// ── keys in client code ─────────────────────────────────────────────────────

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (claims: Record<string, unknown>) => {
  const head = `${b64({ alg: "HS256", typ: "JWT" })}.${b64(claims)}`;
  return `${head}.${createHash("sha256").update(head).digest("base64url")}`;
};
const ANON = jwt({ iss: "supabase", ref: "abcdefghijklmnopqrst", role: "anon", iat: 1700000000, exp: 2000000000 });
const SERVICE = jwt({ iss: "supabase", ref: "abcdefghijklmnopqrst", role: "service_role", iat: 1700000000, exp: 2000000000 });
const OPENAI = "sk-proj-" + createHash("sha256").update("lab-openai-1").digest("base64url") + createHash("sha256").update("lab-openai-2").digest("base64url");

test("an OpenAI key in the bundle is reported as a critical exposed credential, masked", () => {
  const found = analyzeSecrets(`${"function Ee(e){return e}".repeat(500)}const hI="${OPENAI}";`, "/assets/index.js");
  const f = found!.find((x) => /OpenAI/.test(x.issue));
  assert.equal(f?.severity, "critical");
  assert.ok(!JSON.stringify(f).includes(OPENAI), "never written out whole");
  assert.match(f!.masked!, /^sk-p\*+/);
});

test("the legacy OpenAI key format is recognised", () => {
  const legacy = "sk-" + createHash("sha256").update("a").digest("hex").slice(0, 20) + "T3BlbkFJ" + createHash("sha256").update("b").digest("hex").slice(0, 24);
  assert.ok(analyzeSecrets(`const k="${legacy}"`)!.some((x) => /OpenAI/.test(x.issue)));
});

test("a documented placeholder OpenAI key is not a finding", () => {
  assert.ok(!analyzeSecrets(`const k="sk-proj-YOUR_OPENAI_API_KEY_HERE_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"`)!.some((x) => /OpenAI/.test(x.issue)));
});

test("a service_role key is reported by its role claim, whatever the variable is called", () => {
  const found = analyzeSecrets(`const sM="https://abcdefghijklmnopqrst.supabase.co",aM="${ANON}",fI=cO(sM,"${SERVICE}");`, "/assets/index.js");
  const f = found!.find((x) => /service_role/.test(x.issue));
  assert.equal(f?.severity, "critical");
  assert.ok(!JSON.stringify(f).includes(SERVICE), "never written out whole");
});

test("clean twin: the public anon key alone is not a finding", () => {
  assert.deepEqual(analyzeSecrets(`const sM="https://abcdefghijklmnopqrst.supabase.co",aM="${ANON}",Tn=cO(sM,aM);`), []);
});
