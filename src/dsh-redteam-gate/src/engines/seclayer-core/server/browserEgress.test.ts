import test from "node:test";
import assert from "node:assert/strict";
import { fetchForBrowser } from "./browserEgress.js";

const req = (over: Partial<Parameters<typeof fetchForBrowser>[0]> = {}) => ({
  url: "https://example.com/",
  method: "GET",
  headers: {},
  body: null,
  ...over,
});

test("fetchForBrowser aborts non-http schemes without fetching", async () => {
  let called = false;
  const fake = (async () => { called = true; return new Response(""); }) as any;
  for (const url of ["file:///etc/passwd", "ftp://example.com/", "gopher://x/", "not a url"]) {
    assert.equal(await fetchForBrowser(req({ url }), fake), null);
  }
  assert.equal(called, false);
});

test("fetchForBrowser aborts when the SSRF-safe fetch refuses the address", async () => {
  const refusing = (async () => {
    throw Object.assign(new Error("Refusing to connect"), { code: "ESSRFBLOCKED" });
  }) as any;
  assert.equal(await fetchForBrowser(req({ url: "http://169.254.169.254.nip.io/latest/meta-data/" }), refusing), null);
});

// Chromium follows a fulfilled 3xx itself WITHOUT routing the next hop back
// through the guard, so redirects must be followed and checked here.
test("fetchForBrowser follows redirects itself and refuses a hop to a literal internal IP", async () => {
  const urls: string[] = [];
  const fake = (async (u: string) => {
    urls.push(u);
    return new Response(null, { status: 302, headers: { location: "http://169.254.169.254/latest/meta-data/" } });
  }) as any;
  assert.equal(await fetchForBrowser(req(), fake), null);
  assert.deepEqual(urls, ["https://example.com/"], "the internal hop is never fetched");
});

test("fetchForBrowser returns the final response after safe redirects, as GET after a 303", async () => {
  const calls: Array<{ u: string; method: string }> = [];
  const fake = (async (u: string, opts: any) => {
    calls.push({ u, method: opts.method });
    if (calls.length === 1) return new Response(null, { status: 303, headers: { location: "/next" } });
    return new Response("final", { status: 200 });
  }) as any;
  const res = await fetchForBrowser(req({ method: "POST", body: Buffer.from("x") }), fake);
  assert.equal(res?.status, 200);
  assert.equal(res?.body.toString(), "final");
  assert.deepEqual(calls, [{ u: "https://example.com/", method: "POST" }, { u: "https://example.com/next", method: "GET" }]);
});

test("fetchForBrowser refuses literal internal IPs and endless redirect chains", async () => {
  const never = (async () => { throw new Error("must not fetch"); }) as any;
  for (const url of ["http://127.0.0.1/", "http://10.0.0.5:8080/", "http://[::1]/", "http://169.254.169.254/"]) {
    assert.equal(await fetchForBrowser(req({ url }), never), null, url);
  }
  const loop = (async () => new Response(null, { status: 302, headers: { location: "/again" } })) as any;
  assert.equal(await fetchForBrowser(req(), loop), null);
});

test("fetchForBrowser strips hop-by-hop request headers and stale response encodings", async () => {
  let sent: Record<string, string> = {};
  const fake = (async (_u: string, opts: any) => {
    sent = opts.headers;
    const h = new Headers({ "content-type": "text/html", "content-encoding": "gzip", "content-length": "5" });
    h.append("set-cookie", "a=1");
    h.append("set-cookie", "b=2");
    return new Response("hello", { status: 200, headers: h });
  }) as any;
  const res = await fetchForBrowser(
    req({ headers: { Host: "evil", Connection: "close", ":authority": "x", "User-Agent": "ua", Cookie: "s=1" } }),
    fake,
  );
  assert.deepEqual(sent, { "user-agent": "ua", cookie: "s=1" });
  assert.equal(res?.body.toString(), "hello");
  assert.equal(res?.headers["content-encoding"], undefined);
  assert.equal(res?.headers["content-length"], undefined);
  assert.equal(res?.headers["set-cookie"], "a=1\nb=2");
});

test("fetchForBrowser refuses oversized bodies", async () => {
  const fake = (async () =>
    new Response("x", { headers: { "content-length": String(50 * 1024 * 1024) } })) as any;
  assert.equal(await fetchForBrowser(req(), fake), null);
});

test("fetchForBrowser drops the body on GET/HEAD and forwards it otherwise", async () => {
  const bodies: any[] = [];
  const fake = (async (_u: string, opts: any) => { bodies.push(opts.body); return new Response(""); }) as any;
  await fetchForBrowser(req({ method: "GET", body: Buffer.from("x") }), fake);
  await fetchForBrowser(req({ method: "POST", body: Buffer.from("y") }), fake);
  assert.equal(bodies[0], undefined);
  assert.equal(String(bodies[1]), "y");
});
