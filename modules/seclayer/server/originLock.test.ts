import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { AddressInfo } from "node:net";
import { originLock } from "./originLock.js";

async function statusFor(secret: string | undefined, path: string, header?: string): Promise<number> {
  const app = express();
  app.use(originLock(secret));
  app.get("*", (_req, res) => res.send("ok"));
  const server = app.listen(0);
  await new Promise<void>((r) => server.once("listening", () => r()));
  try {
    const { port } = server.address() as AddressInfo;
    const res = await fetch(`http://127.0.0.1:${port}${path}`, header === undefined ? {} : { headers: { "X-Origin-Auth": header } });
    return res.status;
  } finally {
    await new Promise((r) => server.close(r));
  }
}

test("originLock is a no-op until a secret is configured", async () => {
  assert.equal(await statusFor(undefined, "/"), 200);
  assert.equal(await statusFor("", "/"), 200);
});

test("originLock rejects requests that did not come through Cloudflare", async () => {
  assert.equal(await statusFor("s3cret-value", "/"), 403, "no header");
  assert.equal(await statusFor("s3cret-value", "/api/scans", "wrong"), 403, "wrong header");
  assert.equal(await statusFor("s3cret-value", "/", "s3cret-valuE"), 403, "near miss");
  assert.equal(await statusFor("s3cret-value", "/", "s3cret-value"), 200, "correct header");
});

test("originLock lets Railway's direct health check through", async () => {
  assert.equal(await statusFor("s3cret-value", "/api/system/health"), 200);
});
