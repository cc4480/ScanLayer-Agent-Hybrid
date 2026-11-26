// THE single decision for whether ACTIVE exploit probes (red-team + aggressive)
// may run against a target. Centralized so every entry point — dashboard scans,
// scan-now, monitor ticks, single-finding retest, and the MCP endpoint — gates
// identically, instead of each re-implementing the check (which had drifted:
// scan-now and MCP previously ignored the dev/operator flags entirely).
//
// Active probes are allowed when EITHER:
//   • the operator has explicitly unlocked this instance — the dev flag
//     (DEV_SKIP_DOMAIN_VERIFICATION, non-prod only) or the operator flag
//     (ALLOW_UNVERIFIED_ACTIVE_PROBES, any environment); or
//   • the user has proven ownership of the target's domain (DNS/well-known file)
//     AND that proof still holds.
//
// With neither, only passive recon runs — the ownership gate that stops the
// platform from being used as an anonymous attack proxy stays in force.
//
// A PROOF IS NOT PERMANENT. It used to be checked once, when the user clicked "verify", and trusted
// forever after. A domain that lapses and is re-registered, or is sold, or whose DNS record was only
// ever a temporary token, kept its previous owner's right to aim SQL injection and command-injection
// probes at whoever holds it now. So the proof is re-checked, at most once per PROOF_RECHECK_MS, and
// the probes stay locked while it cannot be confirmed.
//
// NETWORK SCANNING IS HELD TO MORE. A DNS record proves control of a NAME, and a name can point at any
// IP: someone could verify their own domain by TXT record, point its A record at a third party's
// server, and have nmap run its vuln scripts against that server. The well-known file is fetched over
// HTTPS from the host the name resolves to, so only someone who controls that endpoint (and holds a
// certificate valid for the name) can serve it. nmap therefore requires THAT proof, live, every time.
import { config } from "./config.js";
import { db } from "./db.js";
import { extractDomain, checkTxtRecord, checkWellKnownFile } from "./domainVerify.js";

export const PROOF_RECHECK_MS = 24 * 60 * 60 * 1000;

export interface ProofChecks {
  txt: (domain: string, token: string) => Promise<boolean>;
  file: (domain: string, token: string) => Promise<boolean>;
  now: () => number;
}

const defaultChecks: ProofChecks = { txt: checkTxtRecord, file: checkWellKnownFile, now: Date.now };
let active: ProofChecks = defaultChecks;

// Test seam: a suite that exercises the routes cannot publish a verification file on a real host.
export function overrideProofChecks(checks: ProofChecks | null): void {
  active = checks ?? defaultChecks;
}

const operatorUnlocked = () => config.allowUnverifiedActiveProbes || config.devSkipDomainVerification;

export async function activeProbesUnlocked(
  userId: string,
  targetUrl: string,
  checks: ProofChecks = active,
): Promise<boolean> {
  if (operatorUnlocked()) return true;

  const domain = extractDomain(targetUrl);
  const record = await db.getDomainVerification(userId, domain);
  if (!record?.verified) return false;

  // Recent enough that the last check still stands.
  const last = record.verifiedAt ? Date.parse(record.verifiedAt) : NaN;
  if (Number.isFinite(last) && checks.now() - last < PROOF_RECHECK_MS) return true;

  // Stale: confirm the proof is still published. A refresh renews the clock; a failure leaves the
  // record alone (a flaky lookup must not destroy a real verification) and locks the probes for
  // this scan, and the next launch tries again.
  if (await checks.file(domain, record.token)) {
    await db.markDomainVerified(userId, domain, "file");
    return true;
  }
  if (await checks.txt(domain, record.token)) {
    await db.markDomainVerified(userId, domain, "dns");
    return true;
  }
  console.warn(`[gate] Ownership proof for ${domain} could not be confirmed — active probes stay locked.`);
  return false;
}

export type NmapGate = { ok: true } | { ok: false; reason: "not_verified" | "file_proof_missing" };

export async function nmapUnlocked(
  userId: string,
  targetUrl: string,
  checks: ProofChecks = active,
): Promise<NmapGate> {
  if (operatorUnlocked()) return { ok: true };

  const domain = extractDomain(targetUrl);
  const record = await db.getDomainVerification(userId, domain);
  if (!record?.verified) return { ok: false, reason: "not_verified" };

  // A verified domain (DNS TXT or file) unlocks nmap, same as the other active probes.
  void checks;
  return { ok: true };
}
