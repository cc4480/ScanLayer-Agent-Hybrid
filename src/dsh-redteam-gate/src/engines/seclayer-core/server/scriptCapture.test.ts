import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { scriptUrls, fetchFirstPartyScripts, lazyChunkUrls, MAX_SCRIPTS, MAX_LAZY_CHUNKS } from "./scriptCapture.js";
import { analyzeSecrets } from "./staticAnalysis.js";

// The crawler follows <a href>, never <script src>, so a single-page app's bundle (where its keys live) was never read.

test("scriptUrls keeps same-origin scripts only, without duplicates, capped", () => {
  const html = `<script src="/a.js"></script><script type="module" crossorigin src="/assets/b.js?v=1"></script>
    <script src="https://cdn.other.test/x.js"></script><script src="/a.js"></script><script>inline()</script>` +
    Array.from({ length: 12 }, (_, i) => `<script src="/n${i}.js"></script>`).join("");
  const urls = scriptUrls(html, "https://app.example.test/");
  assert.deepEqual(urls.slice(0, 2), ["https://app.example.test/a.js", "https://app.example.test/assets/b.js?v=1"]);
  assert.ok(!urls.some((u) => u.includes("other.test")));
  assert.equal(urls.length, MAX_SCRIPTS);
});

test("fetchFirstPartyScripts downloads the bundle and skips failures", async () => {
  const server = http.createServer((req, res) => {
    if (req.url === "/ok.js") { res.writeHead(200, { "content-type": "application/javascript" }); return res.end("const a=1;".repeat(400_000)); }
    res.writeHead(404); res.end("no");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as AddressInfo).port;
  const prev = [process.env.NODE_ENV, process.env.SCAN_DEV_ALLOW_HOSTS];
  process.env.NODE_ENV = "development"; process.env.SCAN_DEV_ALLOW_HOSTS = `127.0.0.1:${port}`;
  try {
    const base = `http://127.0.0.1:${port}/`;
    const got = await fetchFirstPartyScripts(`<script src="/ok.js"></script><script src="/missing.js"></script>`, base);
    assert.equal(got.length, 1);
    assert.equal(got[0]!.text.length, 4_000_000, "read past the old 300,000-character capture limit");
  } finally {
    if (prev[0] === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = prev[0];
    if (prev[1] === undefined) delete process.env.SCAN_DEV_ALLOW_HOSTS; else process.env.SCAN_DEV_ALLOW_HOSTS = prev[1];
    await new Promise((r) => server.close(r));
  }
});

test("secret signatures read hostile 5 MB scripts in bounded time", () => {
  for (const text of ["eyJ".repeat(1_700_000), "sk-".repeat(1_700_000), "aB3-_".repeat(1_000_000)]) {
    const t0 = performance.now();
    analyzeSecrets(text);
    assert.ok(performance.now() - t0 < 5000, "took too long");
  }
});

test("scriptUrls also takes chunks the page only preloads, in either attribute order, and not stylesheets", () => {
  const html = `<link rel="modulepreload" href="/assets/keys.js"/><link href="/assets/supa.js" rel="modulepreload" crossorigin/><link rel="stylesheet" href="/a.css"/><script type="module" src="/assets/entry.js"></script>`;
  assert.deepEqual(scriptUrls(html, "https://app.example.test/"), [
    "https://app.example.test/assets/entry.js", "https://app.example.test/assets/keys.js", "https://app.example.test/assets/supa.js",
  ]);
});

// A route loaded with import() (React.lazy) is in a chunk the HTML never names; a key in a lazy admin screen was never read.
test("fetchFirstPartyScripts follows import() and Vite's preload list to the chunks, and a chunk nobody loads stays unread", async () => {
  const KEY = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.c2lnbmF0dXJlLWZpbGxlci1ieXRlcw";
  const routes: Record<string, string> = {
    "/assets/index.js": `const Admin=lazy(()=>import("./Admin-3fa9.js"));const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/Settings-77ab.js"])))=>i.map(i=>d[i]);x(()=>__vitePreload(()=>import("./Settings-77ab.js"),__vite__mapDeps([0])));`,
    "/assets/Admin-3fa9.js": `const k="${KEY}";`,
    "/assets/Settings-77ab.js": `export default 1;`,
    "/assets/Orphan-0000.js": `const k="${KEY}";`,
  };
  const server = http.createServer((req, res) => {
    const body = routes[req.url ?? ""];
    if (body === undefined) { res.writeHead(404); return res.end("no"); }
    res.writeHead(200, { "content-type": "application/javascript" }); res.end(body);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as AddressInfo).port;
  const prev = [process.env.NODE_ENV, process.env.SCAN_DEV_ALLOW_HOSTS];
  process.env.NODE_ENV = "development"; process.env.SCAN_DEV_ALLOW_HOSTS = `127.0.0.1:${port}`;
  try {
    const base = `http://127.0.0.1:${port}/`;
    const got = await fetchFirstPartyScripts(`<script type="module" src="/assets/index.js"></script>`, base);
    assert.deepEqual(got.map((g) => new URL(g.url).pathname), ["/assets/index.js", "/assets/Admin-3fa9.js", "/assets/Settings-77ab.js"]);
    assert.ok(got.some((g) => g.text.includes(KEY)), "the key in the lazy chunk was read");
    assert.ok(!got.some((g) => g.url.includes("Orphan")), "a chunk no script loads is not guessed");
  } finally {
    server.close();
    if (prev[0] === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = prev[0];
    if (prev[1] === undefined) delete process.env.SCAN_DEV_ALLOW_HOSTS; else process.env.SCAN_DEV_ALLOW_HOSTS = prev[1];
  }
});

test("lazyChunkUrls: same origin only, .js only, nothing already read, capped", () => {
  const text = `import("./a.js");import("https://cdn.other.test/x.js");import("./data.json");import("./seen.js");` +
    Array.from({ length: 30 }, (_, i) => `import("./c${i}.js");`).join("");
  const urls = lazyChunkUrls([{ url: "https://app.test/assets/index.js", text }, { url: "https://app.test/assets/seen.js", text: "" }], "https://app.test/");
  assert.equal(urls.length, MAX_LAZY_CHUNKS);
  assert.equal(urls[0], "https://app.test/assets/a.js");
  assert.ok(urls.every((u) => u.startsWith("https://app.test/") && u.endsWith(".js")));
  assert.ok(!urls.includes("https://app.test/assets/seen.js"));
});
