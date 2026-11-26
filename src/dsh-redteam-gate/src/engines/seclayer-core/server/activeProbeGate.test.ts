import { test } from "node:test";
import assert from "node:assert/strict";

process.env.DB_PATH = ":memory:";
// Ensure a clean baseline: neither bypass flag set for the first assertions.
delete process.env.DEV_SKIP_DOMAIN_VERIFICATION;
delete process.env.ALLOW_UNVERIFIED_ACTIVE_PROBES;

const { db } = await import("./db.js");
const { activeProbesUnlocked } = await import("./activeProbeGate.js");
const { config } = await import("./config.js");

test("blocked by default: an unverified domain does not unlock active probes", async () => {
  const u = (await db.getOrCreateUser(`gate-${Date.now()}@test.io`));
  assert.equal(await activeProbesUnlocked(u.id, "https://example.com/app"), false);
});

test("verified ownership unlocks active probes for that domain", async () => {
  const u = (await db.getOrCreateUser(`gate-verified-${Date.now()}@test.io`));
  // Start + mark a domain verified through the DB, the same path the DNS/file
  // verification flow uses.
  (await db.startDomainVerification(u.id, "myapp.example.com", "tok-abc123"));
  (await db.markDomainVerified(u.id, "myapp.example.com"));
  assert.equal(await activeProbesUnlocked(u.id, "https://myapp.example.com/login"), true);
  // A different, unverified domain for the same user is still blocked.
  assert.equal(await activeProbesUnlocked(u.id, "https://other.example.com/"), false);
});

test("the operator flag unlocks active probes for ANY target, regardless of verification", async () => {
  const u = (await db.getOrCreateUser(`gate-operator-${Date.now()}@test.io`));
  assert.equal(await activeProbesUnlocked(u.id, "https://anything.example.com/"), false, "blocked before the flag");

  const prev = config.allowUnverifiedActiveProbes;
  (config as any).allowUnverifiedActiveProbes = true;
  try {
    assert.equal(await activeProbesUnlocked(u.id, "https://anything.example.com/"), true, "operator flag unlocks everything");
  } finally {
    (config as any).allowUnverifiedActiveProbes = prev;
  }
});

const { nmapUnlocked, PROOF_RECHECK_MS } = await import("./activeProbeGate.js");

const proofs = (over: Partial<{ txt: boolean; file: boolean; now: number }> = {}) => {
  const calls = { txt: 0, file: 0 };
  return {
    calls,
    checks: {
      txt: async () => { calls.txt += 1; return over.txt ?? false; },
      file: async () => { calls.file += 1; return over.file ?? false; },
      now: () => over.now ?? Date.now(),
    },
  };
};
const verifiedUser = async (domain: string, method: "dns" | "file" = "dns") => {
  const u = (await db.getOrCreateUser(`gate-recheck-${domain}-${Date.now()}@test.io`));
  (await db.startDomainVerification(u.id, domain, "tok-recheck"));
  (await db.markDomainVerified(u.id, domain, method));
  return u;
};

test("a fresh proof is trusted without another lookup", async () => {
  const u = await verifiedUser("fresh.example.com");
  const p = proofs();
  assert.equal(await activeProbesUnlocked(u.id, "https://fresh.example.com/", p.checks), true);
  assert.deepEqual(p.calls, { txt: 0, file: 0 });
});

test("a stale proof is re-checked, and probes stay locked if it no longer holds (a lapsed or sold domain)", async () => {
  const u = await verifiedUser("lapsed.example.com");
  const later = Date.now() + PROOF_RECHECK_MS + 60_000;
  const p = proofs({ now: later, txt: false, file: false });
  assert.equal(await activeProbesUnlocked(u.id, "https://lapsed.example.com/", p.checks), false);
  assert.ok(p.calls.txt >= 1 && p.calls.file >= 1, "both proofs were looked for");
  // The record is not destroyed by a failed lookup: once the proof is back, it unlocks again.
  assert.equal(await activeProbesUnlocked(u.id, "https://lapsed.example.com/", proofs({ now: later, txt: true }).checks), true);
});

test("a stale proof that still holds is renewed for another window", async () => {
  const u = await verifiedUser("renew.example.com");
  const later = Date.now() + PROOF_RECHECK_MS + 60_000;
  assert.equal(await activeProbesUnlocked(u.id, "https://renew.example.com/", proofs({ now: later, file: true }).checks), true);
  // The renewal is stamped with the real clock, so the follow-up check uses it too.
  const again = proofs();
  assert.equal(await activeProbesUnlocked(u.id, "https://renew.example.com/", again.checks), true);
  assert.deepEqual(again.calls, { txt: 0, file: 0 }, "renewed, so no second lookup");
});

test("nmap unlocks for a DNS-only verification", async () => {
  const u = await verifiedUser("netscan.example.com", "dns");
  assert.deepEqual(await nmapUnlocked(u.id, "https://netscan.example.com/", proofs({ txt: true, file: false }).checks), { ok: true });
  assert.deepEqual(await nmapUnlocked(u.id, "https://netscan.example.com/", proofs({ file: true }).checks), { ok: true });
  const stranger = (await db.getOrCreateUser(`gate-nmap-stranger-${Date.now()}@test.io`));
  assert.deepEqual(await nmapUnlocked(stranger.id, "https://netscan.example.com/", proofs({ file: true }).checks), { ok: false, reason: "not_verified" });
});
