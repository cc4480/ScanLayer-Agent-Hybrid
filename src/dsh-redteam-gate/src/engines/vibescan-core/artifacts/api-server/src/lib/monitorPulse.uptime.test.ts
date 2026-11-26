import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from "vitest";
import { runPulse, summariseUptime, certDaysRemaining } from "./monitorPulse";

describe("summariseUptime", () => {
  it("returns nulls rather than zero when nothing has been checked", () => {
    // Zero percent uptime and "not checked yet" are very different things to
    // put in front of somebody.
    expect(summariseUptime([])).toEqual({ uptimePct: null, medianResponseMs: null, checks: 0 });
  });

  it("reports 100% when every check succeeded", () => {
    const summary = summariseUptime([
      { reachable: true, responseTimeMs: 100 },
      { reachable: true, responseTimeMs: 200 },
    ]);
    expect(summary.uptimePct).toBe(100);
    expect(summary.checks).toBe(2);
  });

  it("reports one failure in twenty-four as 95.8%", () => {
    const pulses = Array.from({ length: 24 }, (_, i) => ({
      reachable: i !== 5,
      responseTimeMs: i !== 5 ? 150 : null,
    }));
    expect(summariseUptime(pulses).uptimePct).toBe(95.8);
  });

  it("uses the median, so one timeout does not distort the figure", () => {
    // The mean of these is 1,290ms; the median is 150. A site that answers in
    // 150ms all day should not be shown as slow because one check timed out.
    const summary = summariseUptime([
      { reachable: true, responseTimeMs: 140 },
      { reachable: true, responseTimeMs: 150 },
      { reachable: true, responseTimeMs: 160 },
      { reachable: true, responseTimeMs: 10_000 },
      { reachable: true, responseTimeMs: 150 },
    ]);
    expect(summary.medianResponseMs).toBe(150);
  });

  it("averages the middle pair for an even count", () => {
    const summary = summariseUptime([
      { reachable: true, responseTimeMs: 100 },
      { reachable: true, responseTimeMs: 200 },
    ]);
    expect(summary.medianResponseMs).toBe(150);
  });

  it("excludes failed checks from the response time", () => {
    // A failed check's elapsed time is the timeout, not the site's speed.
    const summary = summariseUptime([
      { reachable: true, responseTimeMs: 100 },
      { reachable: false, responseTimeMs: 10_000 },
      { reachable: true, responseTimeMs: 120 },
    ]);
    expect(summary.medianResponseMs).toBe(110);
    expect(summary.uptimePct).toBe(66.7);
  });
});

describe("certDaysRemaining", () => {
  const now = new Date("2026-09-21T12:00:00.000Z");

  it("counts whole days to expiry", () => {
    expect(certDaysRemaining(new Date("2026-10-21T12:00:00.000Z"), now)).toBe(30);
  });

  it("returns a negative number for an already-expired certificate", () => {
    // Not clamped to zero: "expired 3 days ago" is the more useful fact, and
    // the alert thresholds treat anything at or below zero as past caring.
    expect(certDaysRemaining(new Date("2026-09-18T12:00:00.000Z"), now)).toBe(-3);
  });

  it("returns null for a missing or unparseable date", () => {
    expect(certDaysRemaining(null, now)).toBeNull();
    expect(certDaysRemaining(new Date("not a date"), now)).toBeNull();
  });
});

// ── The redirect path ─────────────────────────────────────────────────────────

/**
 * runPulse follows redirects by hand so every hop can be checked against the
 * SSRF guard first.
 *
 * `redirect: "follow"` would have quietly undone the check the URL passed when
 * the subscription was created: a target validated as public last month can
 * answer today with a 302 to a link-local metadata address, and fetch would
 * follow it before any of our code saw the Location header. Nothing about that
 * failure is visible in the dashboard, which is why it gets a test rather than
 * a comment.
 */
describe("runPulse — redirects (local lab server, opt-in on)", () => {
  // A local HTTP server plays the monitored site. Pulses to loopback need the scanner's private-target allowance, which
  // the scanner's own guard reads; it is set here for these tests only and restored after. The guard still runs on every
  // hop, which is what these tests exercise: a public-looking first hop is not needed, because the guard checks each hop
  // before it is sent.
  let server: import("node:http").Server;
  let base = "";
  const optOut = process.env["ALLOW_PRIVATE_SCAN_TARGETS"];

  beforeAll(async () => {
    const http = await import("node:http");
    server = http.createServer((req, res) => {
      const url = new URL(req.url ?? "/", "http://lab.local");
      const send = (status: number, headers: Record<string, string> = {}, body = "ok") => {
        res.writeHead(status, { "content-type": "text/plain", ...headers });
        res.end(body);
      };
      if (url.pathname.startsWith("/status/")) return send(Number(url.pathname.slice("/status/".length)));
      if (url.pathname === "/to-metadata") return send(302, { location: "http://169.254.169.254/latest/meta-data/" });
      if (url.pathname === "/loop") return send(302, { location: "/loop" });
      if (url.pathname === "/to-final") return send(302, { location: "/final" });
      if (url.pathname === "/final") return send(200, { "x-frame-options": "DENY" });
      send(404);
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    base = `http://127.0.0.1:${(server.address() as import("node:net").AddressInfo).port}`;
  }, 15_000);
  afterAll(() => new Promise<void>((r) => server.close(() => r())));

  beforeEach(() => { process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = "true"; });
  afterEach(() => {
    if (optOut === undefined) delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"];
    else process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = optOut;
  });

  it("gives up rather than following a redirect chain forever", async () => {
    const result = await runPulse(`${base}/loop`);
    expect(result.reachable).toBe(false);
    expect(result.failureReason).toMatch(/redirects/);
  }, 40_000);

  it("records the final URL after a legitimate redirect, not the one asked for", async () => {
    // Monitored URLs redirect to www or to HTTPS constantly, so refusing redirects outright (the webhook module's approach)
    // would break the common case. The final URL is what drift compares against.
    const result = await runPulse(`${base}/to-final`);
    expect(result.reachable).toBe(true);
    expect(result.httpStatus).toBe(200);
    expect(result.finalUrl).toBe(`${base}/final`);
    expect(result.snapshot?.present).toContain("x-frame-options");
  }, 20_000);

  it("treats a 5xx as unreachable and a 404 as reachable", async () => {
    // Availability is "is the site serving", not "does this path exist".
    for (const [status, reachable] of [[503, false], [404, true], [200, true]] as const) {
      const result = await runPulse(`${base}/status/${status}`);
      expect(result.reachable, "HTTP " + status).toBe(reachable);
    }
  }, 30_000);

  it("reports a name that does not exist as a result, never a throw", async () => {
    const result = await runPulse("http://no-such-host-" + Date.now() + ".invalid/");
    expect(result.reachable).toBe(false);
    expect(result.failureReason).toBeTruthy();
    expect(result.snapshot).toBeNull();
  });
});

describe("runPulse — redirect to the metadata address, default guard", () => {
  // Default configuration: ALLOW_PRIVATE_SCAN_TARGETS unset. The guard must refuse the cloud metadata address when a public
  // host redirects to it. The first hop must be public to get past the first check, and it cannot be a local server, so the
  // transport is stubbed for example.com only; the guard itself is the real one and runs on every hop.
  const realFetch = globalThis.fetch;
  const sent: string[] = [];
  const optOut = process.env["ALLOW_PRIVATE_SCAN_TARGETS"];
  beforeAll(() => {
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (!url.startsWith("https://example.com/")) return realFetch(input, init);
      sent.push(url);
      return new Response(null, { status: 302, headers: { location: "http://169.254.169.254/latest/meta-data/" } });
    }) as typeof fetch;
  });
  afterAll(() => { globalThis.fetch = realFetch; });
  beforeEach(() => { delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"]; sent.length = 0; });
  afterEach(() => {
    if (optOut === undefined) delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"];
    else process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = optOut;
  });

  it("refuses to follow a public redirect to the metadata address, and never sends to it", async () => {
    const result = await runPulse("https://example.com/to-metadata");
    expect(result.reachable).toBe(false);
    expect(result.failureReason).toMatch(/^Blocked:/);
    expect(result.finalUrl).toContain("169.254.169.254");
    expect(sent).toEqual(["https://example.com/to-metadata"]);
  }, 20_000);
});
