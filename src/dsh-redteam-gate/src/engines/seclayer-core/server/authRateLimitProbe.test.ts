import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { probeAuthRateLimit } from "./authRateLimitProbe.js";

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

const H = { "User-Agent": "test" };

test("flags an OTP-verify endpoint that never throttles — LOW confidence, LOW severity, no PROVEN receipt", async () => {
  const noLimit: http.RequestListener = (req, res) => {
    if (req.url !== "/api/auth/verify-sms") { res.writeHead(404); return res.end("{}"); }
    res.writeHead(400, { "Content-Type": "application/json" }); res.end('{"error":"Invalid code"}');
  };
  await withServer(noLimit, async (port) => {
    const finding = await probeAuthRateLimit(`http://127.0.0.1:${port}/`, [], H);
    assert.ok(finding, "expected a missing-rate-limit finding");
    assert.match(finding!.testName, /No Rate Limiting/i);
    assert.equal(finding!.confidence, "low", "absence of a control is an observation, not a confirmation");
    // A per-code attempt cap answers every guess with the same 401, so this probe
    // cannot distinguish "no limit" from "correctly limited per code". Low it is.
    assert.equal(finding!.severity, "low", "must not be high: the check cannot prove its finding");
    assert.equal(finding!.evidence, undefined, "must NOT carry a PROVEN receipt");
  });
});

/** Reads a JSON body so a fixture can behave like an endpoint that requires a field. */
async function readJson(req: http.IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"); } catch { return {}; }
}

// Regression for the seclayer.app false positive (2026-11-26): a verify endpoint
// that requires `email`, returns 401 for a wrong code, and limits after SIX
// attempts. The old probe sent a body with no `email` and a burst of exactly 6,
// so it saw twelve 400s that never reached the limiter and reported "no rate
// limiting" about a site that was, in fact, limiting. Both halves are fixed, and
// this fixture asserts the composite: the probe must send the field AND outlast
// a threshold of 6.
test("does NOT fire on a limiter with a threshold of 6 that requires an email field (seclayer.app regression)", async () => {
  let compared = 0;
  const strict: http.RequestListener = async (req, res) => {
    if (req.url !== "/api/auth/verify-code") { res.writeHead(404); return res.end("{}"); }
    const body = await readJson(req);
    if (!body.email) {
      res.writeHead(400, { "Content-Type": "application/json" });
      return res.end('{"status":"error","message":"Enter the email address and the 6-digit code."}');
    }
    compared++;
    if (compared > 6) {
      res.writeHead(429, { "Content-Type": "application/json", "Retry-After": "863" });
      return res.end('{"status":"error","message":"Too many code attempts. Please wait a few minutes and try again."}');
    }
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end('{"status":"error","message":"That code is not valid. Request a new one and try again."}');
  };
  await withServer(strict, async (port) => {
    assert.equal(await probeAuthRateLimit(`http://127.0.0.1:${port}/`, [], H), null,
      "a limiter at 6 must be found, not reported as absent");
    assert.equal(compared, 7, "the probe must reach the limiter (7 compared attempts), not bounce on validation");
  });
});

test("does NOT fire when attempts are rejected for a missing request field (never compared a code)", async () => {
  const missingField: http.RequestListener = (req, res) => {
    if (req.url !== "/api/auth/verify-code") { res.writeHead(404); return res.end("{}"); }
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end('{"status":"error","message":"Enter the email address and the 6-digit code."}');
  };
  await withServer(missingField, async (port) => {
    assert.equal(await probeAuthRateLimit(`http://127.0.0.1:${port}/`, [], H), null,
      "a validation rejection is not evidence about throttling");
  });
});

// The seclayer.app limiter is express-rate-limit with max=20 per 15 min on the
// verify route (routes/auth.ts). A burst of 12 sat entirely inside the allowance,
// so 12 clean 401s were read as "no limiter" about an endpoint that had one.
test("does NOT fire on a limiter with a threshold of 20 (the seclayer.app production shape)", async () => {
  let hits = 0;
  const limiter20: http.RequestListener = (req, res) => {
    if (req.url !== "/api/auth/verify-code") { res.writeHead(404); return res.end("{}"); }
    hits++;
    if (hits > 20) {
      res.writeHead(429, { "Content-Type": "application/json" });
      return res.end('{"status":"error","message":"Too many code attempts. Please wait a few minutes and try again."}');
    }
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end('{"status":"error","message":"That code is not valid. Request a new one and try again."}');
  };
  await withServer(limiter20, async (port) => {
    assert.equal(await probeAuthRateLimit(`http://127.0.0.1:${port}/`, [], H), null,
      "a limiter at 20 must be found, not reported as absent");
    assert.equal(hits, 21, "the burst must outlast the threshold and stop on the first 429");
  });
});

test("does NOT fire when the endpoint returns 429 within the burst", async () => {
  let hits = 0;
  const limited429: http.RequestListener = (req, res) => {
    if (req.url !== "/api/auth/verify-sms") { res.writeHead(404); return res.end("{}"); }
    hits++;
    if (hits > 3) { res.writeHead(429, { "Content-Type": "application/json" }); return res.end('{"error":"Too many attempts"}'); }
    res.writeHead(400, { "Content-Type": "application/json" }); res.end('{"error":"Invalid code"}');
  };
  await withServer(limited429, async (port) => {
    assert.equal(await probeAuthRateLimit(`http://127.0.0.1:${port}/`, [], H), null);
  });
});

test("does NOT fire when RateLimit-* headers are present (limiter observable from the first response)", async () => {
  const headerLimiter: http.RequestListener = (req, res) => {
    if (req.url !== "/api/auth/verify-sms") { res.writeHead(404); return res.end("{}"); }
    res.writeHead(400, { "Content-Type": "application/json", "RateLimit-Limit": "3", "RateLimit-Remaining": "2" });
    res.end('{"error":"Invalid code"}');
  };
  await withServer(headerLimiter, async (port) => {
    assert.equal(await probeAuthRateLimit(`http://127.0.0.1:${port}/`, [], H), null);
  });
});

test("does NOT fire on a 404 (no such endpoint) or a 200 (accepts anything)", async () => {
  await withServer((_req, res) => { res.writeHead(404); res.end("{}"); }, async (port) => {
    assert.equal(await probeAuthRateLimit(`http://127.0.0.1:${port}/`, [], H), null);
  });
  await withServer((req, res) => {
    if (req.url !== "/api/auth/verify-sms") { res.writeHead(404); return res.end("{}"); }
    res.writeHead(200, { "Content-Type": "application/json" }); res.end('{"ok":true}');
  }, async (port) => {
    assert.equal(await probeAuthRateLimit(`http://127.0.0.1:${port}/`, [], H), null);
  });
});

test("finds a verify endpoint supplied via a discovered POST target matching the hint", async () => {
  const handler: http.RequestListener = (req, res) => {
    if (req.url !== "/custom/2fa/check") { res.writeHead(404); return res.end("{}"); }
    res.writeHead(401, { "Content-Type": "application/json" }); res.end('{"error":"bad code"}');
  };
  await withServer(handler, async (port) => {
    const finding = await probeAuthRateLimit(`http://127.0.0.1:${port}/`, [`http://127.0.0.1:${port}/custom/2fa/check`], H);
    assert.ok(finding, "expected the discovered 2fa endpoint to be tested");
  });
});
