// Rebinding and pinning tests for the rewritten pinning layer. Lab only: the name "lab.invalid" is answered by a
// stub resolver (ssrfGuard._setResolverForTest), so no DNS query leaves the machine, and every connection goes to
// the 127.0.0.1 lab server. Run through the scratchpad vitest runner (see the report); not part of `npm test`.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { fetch as undiciFetch } from "undici";
import { scanDispatcher, vettedLookup } from "../../src/engines/secscan-network/pinnedDispatcher";
import {
  checkUrlSafe,
  resolvesPublicly,
  DNS_LOOKUP_TIMEOUT_MS,
  _clearResolveCache,
  _setResolverForTest,
} from "../../src/engines/secscan-network/ssrfGuard";

const LAB_NAME = "lab.invalid";
const PUBLIC = { address: "93.184.216.34", family: 4 }; // a public answer, never connected to in these tests
const LOOPBACK = { address: "127.0.0.1", family: 4 };
const OTHER = { address: "10.255.255.1", family: 4 }; // the answer a rebinding name gives on a later lookup

const savedOptOut = process.env["ALLOW_PRIVATE_SCAN_TARGETS"];

/** Returns answers in order; the last answer repeats. Counts how often DNS was asked. */
function scriptedResolver(answers: Array<Array<{ address: string; family: number }>>) {
  const state = { calls: 0 };
  const fn = async () => {
    const answer = answers[Math.min(state.calls, answers.length - 1)]!;
    state.calls++;
    return answer;
  };
  return { fn, state };
}

function lookupOf(name: string, options: { all?: boolean } = { all: true }) {
  return new Promise<{ err: NodeJS.ErrnoException | null; addrs?: unknown }>((resolve) =>
    vettedLookup(name, options, (err, addrs) => resolve({ err, addrs })),
  );
}

async function withLabServer(run: (port: number, hits: () => number) => Promise<void>) {
  let hits = 0;
  const server = http.createServer((_q, res) => {
    hits++;
    res.end("internal");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  try {
    await run((server.address() as AddressInfo).port, () => hits);
  } finally {
    server.close();
  }
}

beforeEach(() => {
  _clearResolveCache();
  delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"];
});

afterEach(() => {
  _setResolverForTest(null);
  _clearResolveCache();
  if (savedOptOut === undefined) delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"];
  else process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = savedOptOut;
});

describe("rebinding: a name whose answer changes between lookups", () => {
  it("connects to the first pinned IP, not the later answer (lab opt-in on)", async () => {
    process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = "true";
    const dns = scriptedResolver([[LOOPBACK], [OTHER]]);
    _setResolverForTest(dns.fn);
    await withLabServer(async (port, hits) => {
      const url = `http://${LAB_NAME}:${port}/`;
      expect(await (await undiciFetch(url, { dispatcher: scanDispatcher })).text()).toBe("internal");
      expect(await (await undiciFetch(url, { dispatcher: scanDispatcher })).text()).toBe("internal");
      expect(hits()).toBe(2);
    });
    // The later answer (OTHER) was never asked for: the name was resolved once for the window.
    expect(dns.state.calls).toBe(1);
  });

  it("refuses a name that first answers loopback when the lab opt-in is off, and keeps refusing after it changes", async () => {
    const dns = scriptedResolver([[LOOPBACK], [PUBLIC]]);
    _setResolverForTest(dns.fn);
    await withLabServer(async (port, hits) => {
      const url = `http://${LAB_NAME}:${port}/`;
      await expect(undiciFetch(url, { dispatcher: scanDispatcher })).rejects.toThrow();
      await expect(undiciFetch(url, { dispatcher: scanDispatcher })).rejects.toThrow();
      expect(hits()).toBe(0);
    });
    expect(dns.state.calls).toBe(1);
  });

  it("the connect-time lookup hands back the address the check judged, even after DNS changes", async () => {
    const dns = scriptedResolver([[PUBLIC], [LOOPBACK]]);
    _setResolverForTest(dns.fn);

    // The check (checkUrlSafe) judges the first answer: public, so it passes.
    expect((await checkUrlSafe(`http://${LAB_NAME}/`)).ok).toBe(true);

    // The socket lookup that follows reads the same answer; DNS now says loopback, but the pinned answer is used.
    const pinned = await lookupOf(LAB_NAME, { all: true });
    expect(pinned.err).toBeNull();
    expect(pinned.addrs).toEqual([PUBLIC]);

    // A later check also sees the pinned (public) answer, not the changed one.
    expect(await resolvesPublicly(LAB_NAME)).toBe(true);
    expect(dns.state.calls).toBe(1);
  });

  it("a single-address lookup (no all:true) returns the pinned first address as a string", async () => {
    const dns = scriptedResolver([[PUBLIC], [LOOPBACK]]);
    _setResolverForTest(dns.fn);
    const first = await lookupOf(LAB_NAME, {});
    expect(first.err).toBeNull();
    expect(first.addrs).toBe(PUBLIC.address);
    const second = await lookupOf(LAB_NAME, {});
    expect(second.addrs).toBe(PUBLIC.address);
    expect(dns.state.calls).toBe(1);
  });
});

describe("single resolution per name", () => {
  it("concurrent checks for one name share one DNS lookup", async () => {
    const dns = scriptedResolver([[PUBLIC]]);
    _setResolverForTest(dns.fn);
    const results = await Promise.all(Array.from({ length: 20 }, () => resolvesPublicly(LAB_NAME)));
    expect(results.every((r) => r === true)).toBe(true);
    expect(dns.state.calls).toBe(1);
  });

  it("bounds the cache at 512 names; an evicted name is resolved again", async () => {
    const dns = scriptedResolver([[PUBLIC]]);
    _setResolverForTest(dns.fn);
    for (let i = 0; i < 513; i++) await resolvesPublicly(`n${i}.lab.invalid`);
    expect(dns.state.calls).toBe(513);
    await resolvesPublicly("n512.lab.invalid"); // newest: still cached
    expect(dns.state.calls).toBe(513);
    await resolvesPublicly("n0.lab.invalid"); // oldest: evicted when n512 was inserted
    expect(dns.state.calls).toBe(514);
  });
});

describe("fail closed", () => {
  it("refuses a name whose lookup never answers, once the DNS deadline passes", async () => {
    _setResolverForTest(() => new Promise<never>(() => {}));
    const started = Date.now();
    expect((await checkUrlSafe("http://slow.lab.invalid/")).ok).toBe(false);
    expect(Date.now() - started).toBeGreaterThanOrEqual(DNS_LOOKUP_TIMEOUT_MS - 50);
    const connect = await lookupOf("slow.lab.invalid", { all: true });
    expect((connect.err as NodeJS.ErrnoException | null)?.code).toBe("ETIMEDOUT");
  }, 20_000);

  it("refuses an answer that is empty", async () => {
    _setResolverForTest(async () => []);
    expect(await resolvesPublicly(LAB_NAME)).toBe(false);
  });
});
