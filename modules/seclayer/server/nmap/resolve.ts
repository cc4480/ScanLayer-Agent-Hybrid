// Resolves a user-submitted target URL/host to a single, SSRF-vetted literal
// IP for nmap to scan. nmap needs a bare host/IP argument, not a URL, and a
// scan runs for many minutes — unlike guardedFetch's safeDispatcher (which
// re-resolves DNS at connect time on every request), nmap does its own DNS
// resolution once internally and would be handed the hostname if we let it,
// re-opening the DNS-rebinding gap the rest of the scanner closes. So this
// resolves ONCE, up front, and nmap is always invoked against the literal
// vetted IP, never the hostname. Callers (server/nmapWorker.ts) call this
// fresh immediately before each run rather than reusing a value resolved at
// HTTP-launch time, for the same TOCTOU reason.
import net from "node:net";
import { extractDomain } from "../domainVerify.js";
import { firstBlockedAddress, isDevAllowedHostname, resolveHostAddresses } from "../ssrf.js";

export interface ResolvedNmapTarget {
  hostname: string;
  ip: string;
}

export async function resolveNmapTarget(rawUrl: string): Promise<ResolvedNmapTarget> {
  const hostname = extractDomain(rawUrl); // lowercased, scheme-agnostic
  const lower = hostname.toLowerCase();

  // Names that may resolve via split-horizon DNS are refused by name, exactly
  // like server/ssrf.ts's assertTargetIsScannable — an IP-level check alone
  // can't catch these. The dev allowlist (SCAN_DEV_ALLOW_HOSTS) still applies,
  // so a hand-listed local test target keeps working in dev.
  const suspectHostname =
    lower === "localhost" || lower.endsWith(".localhost") || lower.endsWith(".local") || lower.endsWith(".internal");
  if (suspectHostname && !isDevAllowedHostname(hostname)) {
    throw new Error(`Refusing to scan internal hostname "${hostname}".`);
  }

  if (net.isIP(hostname)) {
    if (firstBlockedAddress(hostname, [hostname])) {
      throw new Error(`Refusing to scan internal or reserved address "${hostname}".`);
    }
    return { hostname, ip: hostname };
  }

  // The same resolver every other outbound request uses (the OS first, c-ares as the fallback). Raw
  // c-ares queries alone are refused on hosts whose only nameserver is a local stub, which made
  // every nmap scan fail to resolve a perfectly reachable target there.
  const candidates = await resolveHostAddresses(hostname);
  if (candidates.length === 0) {
    throw new Error(`DNS resolution failed for "${hostname}".`);
  }

  // A single internal answer among otherwise-public ones is the shape of a
  // DNS-rebinding response — refuse the whole target rather than silently
  // picking one of the "safe-looking" addresses (same philosophy as
  // firstBlockedAddress's existing callers in ssrf.ts).
  const blocked = firstBlockedAddress(hostname, candidates);
  if (blocked) {
    throw new Error(`Target "${hostname}" resolves to a blocked internal address (${blocked}); scan refused.`);
  }

  return { hostname, ip: candidates[0] };
}
