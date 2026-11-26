import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { AddressInfo } from "node:net";
import { healthHandler, healthDetailAllowed, HEALTH_DETAIL_HEADER } from "./healthCheck.js";

const OPERATOR_FIELDS = ["checks", "uptimeSeconds", "instance", "memory", "timestamp"];

async function probe(opts: { dbOk?: boolean; token?: string; header?: string }) {
  const app = express();
  app.get("/api/system/health", healthHandler({
    healthy: async () => opts.dbOk ?? true,
    appVersion: "public beta",
    detailToken: opts.token,
  }));
  const server = app.listen(0);
  await new Promise<void>((r) => server.once("listening", () => r()));
  try {
    const { port } = server.address() as AddressInfo;
    const headers: Record<string, string> = opts.header === undefined ? {} : { [HEALTH_DETAIL_HEADER]: opts.header };
    const res = await fetch(`http://127.0.0.1:${port}/api/system/health`, { headers });
    return { status: res.status, cache: res.headers.get("cache-control"), body: await res.json() as Record<string, unknown> };
  } finally {
    await new Promise((r) => server.close(r));
  }
}

test("the public answer is only what the navbar renders", async () => {
  const { status, body } = await probe({});
  assert.equal(status, 200);
  assert.deepEqual(body, { status: "Online", version: "public beta" });
});

test("operator fields stay hidden without the right token", async () => {
  for (const [token, header] of [
    [undefined, undefined], [undefined, "anything"], ["", ""], ["s3cret", undefined],
    ["s3cret", "wrong"], ["s3cret", "s3creT"], ["s3cret", "s3cret-longer"],
  ] as const) {
    const { body } = await probe({ token, header });
    for (const f of OPERATOR_FIELDS) assert.ok(!(f in body), `${f} leaked for token=${token} header=${header}`);
  }
});

test("the right token unlocks uptime, instance and memory for operators", async () => {
  const { body } = await probe({ token: "s3cret", header: "s3cret" });
  assert.equal(body.status, "Online");
  assert.deepEqual(body.checks, { database: "ok" });
  assert.equal(typeof body.uptimeSeconds, "number");
  assert.match(String(body.instance), /^[0-9a-f]{8}$/);
  assert.equal(typeof (body.memory as { rssMb: unknown }).rssMb, "number");
});

// Railway's healthcheck and the Docker HEALTHCHECK read only the status code.
test("a lost database still answers 503 Degraded, with or without the token", async () => {
  const pub = await probe({ dbOk: false });
  assert.equal(pub.status, 503);
  assert.deepEqual(pub.body, { status: "Degraded", version: "public beta" });
  const op = await probe({ dbOk: false, token: "s3cret", header: "s3cret" });
  assert.equal(op.status, 503);
  assert.deepEqual(op.body.checks, { database: "error" });
});

// A cached detail answer would be replayed to the public.
test("no answer is cacheable", async () => {
  assert.equal((await probe({})).cache, "no-store");
  assert.equal((await probe({ token: "s3cret", header: "s3cret" })).cache, "no-store");
});

test("a whitespace-only token counts as unset", () => {
  assert.equal(healthDetailAllowed("   ", "   "), false);
  assert.equal(healthDetailAllowed("", ""), false);
});
