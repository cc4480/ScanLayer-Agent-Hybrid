import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import {
  extractBucketUrls,
  classifyBucketListing,
  bucketLooksOwned,
  listedKeys,
  listsOnlyStaticAssets,
  probeOpenBuckets,
} from "./bucketProbe.js";

// --- extractBucketUrls ------------------------------------------------------

test("extractBucketUrls finds S3 virtual-hosted and path-style buckets", () => {
  const html = `
    <img src="https://my-assets.s3.amazonaws.com/logo.png">
    <link href="https://prod-uploads.s3.us-west-2.amazonaws.com/style.css">
    fetch("https://s3.eu-central-1.amazonaws.com/legacy-bucket/data.json")
  `;
  const refs = extractBucketUrls(html);
  const buckets = refs.filter((r) => r.provider === "s3").map((r) => r.bucket).sort();
  assert.deepEqual(buckets, ["legacy-bucket", "my-assets", "prod-uploads"]);
  const one = refs.find((r) => r.bucket === "my-assets")!;
  assert.match(one.listUrl, /list-type=2/);
});

test("extractBucketUrls finds GCS (path and virtual-hosted) and Azure buckets", () => {
  const html = `
    a="https://storage.googleapis.com/app-public-bucket/x.png";
    b="https://user-uploads.storage.googleapis.com/y.png";
    c="https://myacct.blob.core.windows.net/media/z.png";
  `;
  const refs = extractBucketUrls(html);
  assert.ok(refs.some((r) => r.provider === "gcs" && r.bucket === "app-public-bucket"));
  assert.ok(refs.some((r) => r.provider === "gcs" && r.bucket === "user-uploads"));
  const az = refs.find((r) => r.provider === "azure")!;
  assert.equal(az.bucket, "myacct/media");
  assert.match(az.listUrl, /restype=container&comp=list/);
});

test("extractBucketUrls dedupes and caps at four", () => {
  const many = Array.from({ length: 8 }, (_, i) => `https://bucket-num-${i}.s3.amazonaws.com/o`).join(" ");
  const dupes = "https://same-bucket.s3.amazonaws.com/a https://same-bucket.s3.amazonaws.com/b";
  assert.equal(extractBucketUrls(many).length, 4);
  assert.equal(extractBucketUrls(dupes).length, 1);
});

test("extractBucketUrls returns nothing for content with no bucket URLs", () => {
  assert.deepEqual(extractBucketUrls('<a href="https://example.com/about">x</a>'), []);
  assert.deepEqual(extractBucketUrls(""), []);
});

// --- classifyBucketListing: the false-positive-critical oracle --------------

test("classifyBucketListing: S3 200 + ListBucketResult is open, and samples a key", () => {
  const body = `<?xml version="1.0"?><ListBucketResult><Contents><Key>secrets/db.env</Key></Contents></ListBucketResult>`;
  assert.deepEqual(classifyBucketListing("s3", 200, body), { open: true, sample: "secrets/db.env" });
});

test("classifyBucketListing: S3 403 AccessDenied is secured (no finding)", () => {
  const denied = `<?xml version="1.0"?><Error><Code>AccessDenied</Code></Error>`;
  assert.deepEqual(classifyBucketListing("s3", 403, denied), { open: false });
});

test("classifyBucketListing: a 200 that is not a listing document is NOT open", () => {
  // e.g. a bucket that returns its index.html or an SPA shell on the root.
  assert.deepEqual(classifyBucketListing("s3", 200, "<!DOCTYPE html><html>...</html>"), { open: false });
});

test("classifyBucketListing: GCS storage#objects JSON is open, and samples a name", () => {
  const json = `{"kind": "storage#objects","items":[{"name":"uploads/passport.jpg"}]}`;
  assert.deepEqual(classifyBucketListing("gcs", 200, json), { open: true, sample: "uploads/passport.jpg" });
});

test("classifyBucketListing: GCS 403 error JSON is secured", () => {
  assert.deepEqual(classifyBucketListing("gcs", 403, `{"error":{"code":403,"message":"does not have storage.objects.list"}}`), { open: false });
});

test("classifyBucketListing: Azure EnumerationResults is open", () => {
  const xml = `<?xml version="1.0"?><EnumerationResults><Blobs><Blob><Name>private/report.pdf</Name></Blob></Blobs></EnumerationResults>`;
  assert.deepEqual(classifyBucketListing("azure", 200, xml), { open: true, sample: "private/report.pdf" });
});

test("classifyBucketListing: an open bucket with no visible key is still open, without a sample", () => {
  assert.deepEqual(classifyBucketListing("s3", 200, "<ListBucketResult></ListBucketResult>"), { open: true, sample: undefined });
});

test("classifyBucketListing: a non-200 is never open regardless of body", () => {
  assert.deepEqual(classifyBucketListing("s3", 500, "<ListBucketResult>"), { open: false });
});

test("bucketLooksOwned: the site's host or brand in the bucket name, nothing weaker", () => {
  assert.equal(bucketLooksOwned("acme-prod-uploads", "www.acme.com"), true);
  assert.equal(bucketLooksOwned("www.acme.com", "acme.com"), true);
  assert.equal(bucketLooksOwned("acmeassets", "shop.acme.co.uk"), true);
  // A public dataset or a vendor's bucket shares nothing with the site.
  assert.equal(bucketLooksOwned("noaa-ghcn-pds", "acme.com"), false);
  // Brands under four characters are too common to be evidence.
  assert.equal(bucketLooksOwned("app-assets", "app.io"), false);
});

test("listsOnlyStaticAssets ignores folders and needs at least one file", () => {
  assert.equal(listsOnlyStaticAssets(["img/", "img/logo.png", "css/site.css", "js/app.js"]), true);
  assert.equal(listsOnlyStaticAssets(["img/logo.png", "exports/customers.csv"]), false);
  assert.equal(listsOnlyStaticAssets(["img/"]), false);
  assert.deepEqual(listedKeys('<ListBucketResult><Contents><Key>a.png</Key></Contents><Contents><Key>b.sql</Key></Contents></ListBucketResult>'), ["a.png", "b.sql"]);
  assert.deepEqual(listedKeys('{"kind":"storage#objects","items":[{"name":"x.css"}]}'), ["x.css"]);
});

test("probeOpenBuckets hedges a bucket the site does not own and one holding only static assets", async () => {
  // Stand-in for the bucket's list endpoint: answers with whichever listing the
  // request asks for.
  const listing = (keys: string[]) =>
    `<?xml version="1.0"?><ListBucketResult>${keys.map((k) => `<Contents><Key>${k}</Key></Contents>`).join("")}</ListBucketResult>`;
  const server = http.createServer((req, res) => {
    const kind = new URL(req.url || "/", "http://x").searchParams.get("kind");
    res.writeHead(200, { "Content-Type": "application/xml" });
    res.end(kind === "static" ? listing(["img/logo.png", "css/site.css"]) : listing(["exports/customers-2026.csv"]));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as any).port;
  const prevEnv = process.env.NODE_ENV;
  const prevAllow = process.env.SCAN_DEV_ALLOW_HOSTS;
  const ref = (bucket: string, kind: string) =>
    ({ provider: "s3" as const, bucket, listUrl: `http://127.0.0.1:${port}/?kind=${kind}`, display: `${bucket} (S3)` });
  try {
    process.env.NODE_ENV = "development";
    process.env.SCAN_DEV_ALLOW_HOSTS = `127.0.0.1:${port}`;
    const ua = { "User-Agent": "test" };

    // The site's own bucket with a data export in it: the real finding, unchanged.
    const owned = await probeOpenBuckets([ref("acme-prod-exports", "data")], ua, "www.acme.com");
    assert.equal(owned.severity, "high");
    assert.equal(owned.confidence, undefined);

    // Someone else's bucket the page happens to reference: was HIGH, blamed on the site.
    const thirdParty = await probeOpenBuckets([ref("noaa-ghcn-pds", "data")], ua, "www.acme.com");
    assert.equal(thirdParty.severity, "low");
    assert.equal(thirdParty.confidence, "medium");
    assert.match(thirdParty.description, /Nothing ties the bucket to this site/);

    // The site's own asset bucket: public by design.
    const assets = await probeOpenBuckets([ref("acme-static", "static")], ua, "www.acme.com");
    assert.equal(assets.severity, "low");
    assert.match(assets.description, /static asset/);
  } finally {
    if (prevEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = prevEnv;
    if (prevAllow === undefined) delete process.env.SCAN_DEV_ALLOW_HOSTS; else process.env.SCAN_DEV_ALLOW_HOSTS = prevAllow;
    await new Promise<void>((r) => server.close(() => r()));
  }
});
